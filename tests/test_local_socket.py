"""Tests for the local Unix-socket transport."""

import asyncio
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

from praxis.approval import ApprovalCoordinator, AutoApproveNotifier, NullAuthenticator
from praxis.filesystem import (
    FSExecutor,
    FSPolicyEngine,
    StagedTrash,
    WalkerBackend,
)
from praxis.kill_switch import KillSwitch, reset_kill_switch_for_tests
from praxis.principal import PrincipalResolver, compute_local_response, ensure_local_key
from praxis.transports.local_socket import (
    LocalSocketClient,
    LocalSocketClientError,
    LocalSocketServer,
)


@pytest.fixture(autouse=True)
def _fresh_kill():
    reset_kill_switch_for_tests()
    yield
    reset_kill_switch_for_tests()


@pytest.fixture
def sandbox(tmp_path):
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "passport_2024.pdf").write_bytes(b"pdf-bytes")
    (tmp_path / "Documents" / "resume.pdf").write_bytes(b"cv-bytes")
    (tmp_path / "Downloads").mkdir()
    (tmp_path / "Downloads" / "junk.tmp").write_bytes(b"j")
    return tmp_path


@pytest.fixture
def local_key(tmp_path):
    return ensure_local_key(tmp_path / ".praxis" / "local_key")


@pytest.fixture
def resolver(local_key, tmp_path):
    return PrincipalResolver(
        local_key=local_key,
        local_key_path=tmp_path / ".praxis" / "local_key",
    )


@pytest.fixture
def executor(tmp_path):
    return FSExecutor(
        policy=FSPolicyEngine(),
        approvals=ApprovalCoordinator(
            notifier=AutoApproveNotifier(),
            authenticator=NullAuthenticator(),
        ),
        trash=StagedTrash(trash_dir=tmp_path / "trash", ttl_seconds=60.0),
        kill_switch=KillSwitch(),
        search_backend=WalkerBackend(),
    )


@pytest.fixture
async def running_server(tmp_path, executor, resolver):
    # Unix socket paths on macOS/Linux are capped at ~104-108 bytes.
    # pytest's tmp_path can be long, so create the socket under /tmp.
    with tempfile.TemporaryDirectory(prefix="praxis_") as short_root:
        sock_path = Path(short_root) / "sock"
        server = LocalSocketServer(
            executor=executor,
            resolver=resolver,
            socket_path=sock_path,
        )
        await server.start()
        try:
            yield server
        finally:
            await server.stop()


# ---------------------------------------------------------------------------
# Server lifecycle + permissions
# ---------------------------------------------------------------------------


class TestServerLifecycle:
    async def test_start_creates_socket_file(self, running_server):
        assert running_server.is_running
        assert running_server.socket_path.exists()
        assert running_server.transport_kind == "unix"

    @pytest.mark.skipif(sys.platform == "win32", reason="posix-only")
    async def test_socket_file_is_0600(self, running_server):
        mode = stat.S_IMODE(running_server.socket_path.stat().st_mode)
        assert mode == 0o600, f"expected 0600 got {oct(mode)}"

    async def test_stop_removes_socket_file(self, tmp_path, executor, resolver):
        with tempfile.TemporaryDirectory(prefix="praxis_") as short_root:
            sock = Path(short_root) / "sock"
            s = LocalSocketServer(
                executor=executor, resolver=resolver, socket_path=sock
            )
            await s.start()
            await s.stop()
            assert not sock.exists()
            assert not s.is_running


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


class TestHandshake:
    async def test_correct_hmac_succeeds(self, running_server, local_key):
        client = LocalSocketClient(
            local_key=local_key,
            socket_path=running_server.socket_path,
        )
        await client.connect()
        try:
            r = await client.call("ping")
            assert r["status"] == "success"
            assert r["result"]["pong"] is True
        finally:
            await client.close()

    async def test_wrong_hmac_rejected(self, running_server):
        wrong_key = b"\x00" * 32
        client = LocalSocketClient(
            local_key=wrong_key,
            socket_path=running_server.socket_path,
        )
        with pytest.raises(LocalSocketClientError, match="handshake failed"):
            await client.connect()


# ---------------------------------------------------------------------------
# FS ops end-to-end through the socket
# ---------------------------------------------------------------------------


class TestFSOverSocket:
    async def test_search_for_passport(self, running_server, local_key, sandbox):
        async with LocalSocketClient(
            local_key=local_key,
            socket_path=running_server.socket_path,
        ) as client:
            r = await client.call(
                "fs.search",
                {"query": "passport", "paths": [str(sandbox)], "limit": 5},
            )
        assert r["ok"], r
        assert any("passport" in h["path"] for h in r["result"]["hits"])

    async def test_delete_from_local_stages_to_trash(
        self, running_server, local_key, sandbox
    ):
        target = sandbox / "Downloads" / "junk.tmp"
        async with LocalSocketClient(
            local_key=local_key,
            socket_path=running_server.socket_path,
        ) as client:
            r = await client.call("fs.delete", {"paths": [str(target)]})
        assert r["ok"], r
        assert not target.exists()
        assert r["trashed_paths"]

    async def test_read_credential_store_is_blocked(
        self, running_server, local_key
    ):
        async with LocalSocketClient(
            local_key=local_key,
            socket_path=running_server.socket_path,
        ) as client:
            r = await client.call("fs.read", {"paths": ["~/.ssh/id_rsa"]})
        assert r["status"] == "blocked"
        assert "fs_path" in r["decision_matched_rule"]

    async def test_multiple_ops_per_connection(
        self, running_server, local_key, sandbox
    ):
        async with LocalSocketClient(
            local_key=local_key,
            socket_path=running_server.socket_path,
        ) as client:
            r1 = await client.call(
                "fs.stat",
                {"paths": [str(sandbox / "Documents" / "resume.pdf")]},
            )
            r2 = await client.call(
                "fs.list_dir", {"paths": [str(sandbox / "Documents")]}
            )
            r3 = await client.call("ping")
        assert r1["ok"]
        assert r2["ok"]
        assert r3["status"] == "success"  # ping is a control op, not FSResult

    async def test_unknown_op_returns_error(self, running_server, local_key):
        async with LocalSocketClient(
            local_key=local_key,
            socket_path=running_server.socket_path,
        ) as client:
            r = await client.call("fs.warp_drive", {})
        assert r["status"] == "error"
        assert "unknown" in r["reason"].lower()

    async def test_kill_op_fires_switch(self, running_server, local_key, executor):
        async with LocalSocketClient(
            local_key=local_key,
            socket_path=running_server.socket_path,
        ) as client:
            r = await client.call("kill", {"reason": "test-panic"})
        assert r["status"] == "success"
        # Kill switch is now fired.
        assert executor._kill.is_fired
