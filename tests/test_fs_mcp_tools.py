"""Tests for the FS MCP tools."""

import pytest

from praxis.approval import ApprovalCoordinator, AutoApproveNotifier, NullAuthenticator
from praxis.filesystem import (
    FSExecutor,
    FSPolicyEngine,
    StagedTrash,
    WalkerBackend,
)
from praxis.kill_switch import KillSwitch, reset_kill_switch_for_tests
from praxis.mcp.fs_tools import register_fs_tools
from praxis.principal import Principal


mcp_pkg = pytest.importorskip("mcp.server.fastmcp")
FastMCP = mcp_pkg.FastMCP


@pytest.fixture(autouse=True)
def _fresh_kill():
    reset_kill_switch_for_tests()
    yield
    reset_kill_switch_for_tests()


@pytest.fixture
def sandbox(tmp_path):
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "passport_2024.pdf").write_bytes(b"pdf")
    (tmp_path / "Documents" / "resume.pdf").write_bytes(b"cv")
    (tmp_path / "Downloads").mkdir()
    (tmp_path / "Downloads" / "junk.tmp").write_bytes(b"j")
    return tmp_path


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


def _server_with_principal(executor, principal: Principal) -> FastMCP:
    mcp = FastMCP("praxis-test")
    register_fs_tools(
        mcp=mcp,
        executor=executor,
        principal_getter=lambda: principal,
    )
    return mcp


async def _call_tool(mcp: FastMCP, name: str, **kwargs):
    """Invoke a registered FastMCP tool by name.

    FastMCP registers async tool functions; we drive them via the
    internal ``_tool_manager`` so we don't need to spin up a full
    JSON-RPC transport in the test.
    """
    tools = mcp._tool_manager._tools  # noqa: SLF001
    assert name in tools, f"tool {name!r} not registered; have {list(tools)}"
    tool = tools[name]
    return await tool.run(kwargs)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_all_eleven_tools_registered(self, executor):
        mcp = _server_with_principal(executor, Principal.local())
        expected = {
            "fs_search",
            "fs_read",
            "fs_stat",
            "fs_list_dir",
            "fs_create_dir",
            "fs_create_file",
            "fs_write",
            "fs_delete",
            "fs_move",
            "fs_rename",
            "fs_overwrite",
        }
        registered = set(mcp._tool_manager._tools.keys())  # noqa: SLF001
        assert expected <= registered

    def test_docstrings_are_present(self, executor):
        mcp = _server_with_principal(executor, Principal.local())
        for name, tool in mcp._tool_manager._tools.items():  # noqa: SLF001
            assert tool.description, f"{name} is missing help text"


# ---------------------------------------------------------------------------
# Local principal — behaves like the user
# ---------------------------------------------------------------------------


class TestLocalPrincipalOverMCP:
    async def test_search_finds_passport(self, executor, sandbox):
        mcp = _server_with_principal(executor, Principal.local())
        raw = await _call_tool(
            mcp,
            "fs_search",
            query="passport",
            paths=[str(sandbox)],
            limit=3,
        )
        payload = _decode(raw)
        assert payload["ok"], payload
        assert any("passport" in h["path"] for h in payload["result"]["hits"])

    async def test_delete_stages_to_trash(self, executor, sandbox):
        mcp = _server_with_principal(executor, Principal.local())
        raw = await _call_tool(
            mcp,
            "fs_delete",
            paths=[str(sandbox / "Downloads" / "junk.tmp")],
        )
        payload = _decode(raw)
        assert payload["ok"], payload
        assert payload["trashed_paths"]

    async def test_read_secrets_blocked(self, executor):
        mcp = _server_with_principal(executor, Principal.local())
        raw = await _call_tool(mcp, "fs_read", path="~/.ssh/id_rsa")
        payload = _decode(raw)
        assert payload["status"] == "blocked"
        assert "fs_path" in payload["decision_matched_rule"]


# ---------------------------------------------------------------------------
# Agent principal — the wedge behaviour
# ---------------------------------------------------------------------------


class TestAgentPrincipalOverMCP:
    async def test_agent_can_read(self, executor, sandbox):
        mcp = _server_with_principal(
            executor, Principal.agent("claude-desktop")
        )
        raw = await _call_tool(
            mcp,
            "fs_read",
            path=str(sandbox / "Documents" / "resume.pdf"),
        )
        payload = _decode(raw)
        assert payload["ok"], payload

    async def test_agent_delete_blocked(self, executor, sandbox):
        mcp = _server_with_principal(
            executor, Principal.agent("claude-desktop")
        )
        raw = await _call_tool(
            mcp,
            "fs_delete",
            paths=[str(sandbox / "Downloads" / "junk.tmp")],
        )
        payload = _decode(raw)
        assert payload["status"] == "blocked"
        assert (sandbox / "Downloads" / "junk.tmp").exists()

    async def test_agent_create_dir_needs_approval(self, executor, sandbox):
        # Auto-approve notifier is wired → approval succeeds.
        mcp = _server_with_principal(
            executor, Principal.agent("claude-desktop")
        )
        new_dir = sandbox / "agent_dir"
        raw = await _call_tool(mcp, "fs_create_dir", path=str(new_dir))
        payload = _decode(raw)
        assert payload["ok"], payload
        assert new_dir.exists()


# ---------------------------------------------------------------------------
# Helper: unwrap the MCP tool response wire format
# ---------------------------------------------------------------------------


def _decode(raw):
    """Extract our JSON payload from whatever wrapper FastMCP produced.

    ``FastMCPTool.run`` may return the plain dict (when the tool is
    an async fn returning a dict) or a ``(content, structured)`` tuple
    depending on version.
    """
    import json

    if isinstance(raw, dict):
        return raw
    if isinstance(raw, tuple):
        # (content_list, structured_output) shape.
        content, structured = raw
        if isinstance(structured, dict):
            return structured
        # Fall back to first text content block.
        for c in content:
            text = getattr(c, "text", None)
            if text:
                try:
                    return json.loads(text)
                except Exception:
                    continue
    # Last resort: assume it's a Content-alike with .text
    text = getattr(raw, "text", None)
    if text:
        return json.loads(text)
    raise AssertionError(f"unrecognised MCP tool return shape: {raw!r}")
