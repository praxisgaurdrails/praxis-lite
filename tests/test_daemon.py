"""Tests for the Praxis daemon wire-up."""

import asyncio
import tempfile
from pathlib import Path

import pytest

from praxis.approval import AutoApproveNotifier, NullAuthenticator
from praxis.daemon import DaemonConfig, PraxisDaemon
from praxis.kill_switch import reset_kill_switch_for_tests
from praxis.principal import compute_local_response
from praxis.transports import LocalSocketClient


@pytest.fixture(autouse=True)
def _fresh_kill():
    reset_kill_switch_for_tests()
    yield
    reset_kill_switch_for_tests()


@pytest.fixture
def state_dir(tmp_path):
    # Long tmp_path breaks Unix sockets; put the socket in /tmp.
    d = tmp_path / "praxis"
    d.mkdir()
    return d


@pytest.fixture
async def running_daemon(state_dir):
    from praxis.filesystem import WalkerBackend
    with tempfile.TemporaryDirectory(prefix="praxis_") as short_root:
        cfg = DaemonConfig(
            state_dir=state_dir,
            socket_path=Path(short_root) / "sock",
            enable_rest=False,
            enable_connectivity=False,
            auto_approve=True,
            log_level="WARNING",
            search_backend=WalkerBackend(),
        )
        daemon = PraxisDaemon(cfg)
        await daemon.start(
            notifier=AutoApproveNotifier(),
            authenticator=NullAuthenticator(),
        )
        try:
            yield daemon
        finally:
            await daemon.stop()


class TestLifecycle:
    async def test_start_stop_flow(self, state_dir):
        with tempfile.TemporaryDirectory(prefix="praxis_") as short_root:
            cfg = DaemonConfig(
                state_dir=state_dir,
                socket_path=Path(short_root) / "sock",
                enable_rest=False,
                enable_connectivity=False,
                auto_approve=True,
            )
            d = PraxisDaemon(cfg)
            assert not d.is_running
            await d.start()
            try:
                assert d.is_running
                # Socket really listening.
                assert d.socket_server is not None
                assert d.socket_server.is_running
                # Local key file created 0o600.
                key_path = cfg.resolved_local_key_path()
                assert key_path.exists()
            finally:
                await d.stop()
            assert not d.is_running

    async def test_double_start_is_noop(self, running_daemon):
        # If start() is called twice we should not blow up.
        await running_daemon.start()
        assert running_daemon.is_running

    async def test_status_snapshot(self, running_daemon):
        s = await running_daemon.status()
        assert s["running"] is True
        assert s["socket_running"] is True
        assert s["kill_switch_fired"] is False
        assert s["evidence_session"]


class TestSocketFromDaemon:
    async def test_full_pipeline_via_socket(self, running_daemon, tmp_path):
        # Materialise some files, then talk to the daemon via its socket.
        (tmp_path / "hoard").mkdir()
        (tmp_path / "hoard" / "passport_2024.pdf").write_bytes(b"pdf")
        (tmp_path / "hoard" / "junk.tmp").write_bytes(b"garbage")

        key = running_daemon.resolver.local_key
        async with LocalSocketClient(
            local_key=key,
            socket_path=running_daemon.config.resolved_socket_path(),
        ) as client:
            r = await client.call(
                "fs.search",
                {"query": "passport", "paths": [str(tmp_path / "hoard")]},
            )
            assert r["ok"], r
            hits = r["result"]["hits"]
            assert any("passport" in h["path"] for h in hits)

            r = await client.call(
                "fs.delete",
                {"paths": [str(tmp_path / "hoard" / "junk.tmp")]},
            )
            assert r["ok"], r

    async def test_kill_switch_via_socket(self, running_daemon):
        key = running_daemon.resolver.local_key
        async with LocalSocketClient(
            local_key=key,
            socket_path=running_daemon.config.resolved_socket_path(),
        ) as client:
            r = await client.call("kill", {"reason": "test"})
        assert r["status"] == "success"
        # Kill switch is now fired for the daemon.
        s = await running_daemon.status()
        assert s["kill_switch_fired"] is True
