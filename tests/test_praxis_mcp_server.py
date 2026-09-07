"""Tests for the standalone Praxis MCP server (the Codex/Claude entry point)."""

import subprocess
import sys
from pathlib import Path

import pytest

from praxis.mcp import praxis_server


class TestArgParsing:
    def test_defaults(self):
        args = praxis_server._parse_args([])
        assert args.as_principal == "agent:mcp-caller"
        assert args.transport == "stdio"
        assert args.auto_approve is False
        assert args.no_evidence is False
        # search-roots is now comma-separated (empty default → $HOME in main)
        assert args.search_roots == ""
        assert args.search_root_list == []

    def test_search_roots_comma_separated(self):
        args = praxis_server._parse_args(
            ["--search-roots", "/a,/b,/c"]
        )
        roots = [r.strip() for r in args.search_roots.split(",") if r.strip()]
        assert roots == ["/a", "/b", "/c"]

    def test_search_root_repeatable(self):
        args = praxis_server._parse_args(
            ["--search-root", "/a", "--search-root", "/b"]
        )
        assert args.search_root_list == ["/a", "/b"]

    def test_agent_principal(self):
        args = praxis_server._parse_args(["--as-principal", "agent:codex"])
        p = praxis_server._parse_principal(args.as_principal)
        assert p.is_agent
        assert p.name == "codex"

    def test_praxis_local_parses_but_main_refuses(self):
        # _parse_principal returns LOCAL for "praxis:local" — the
        # refusal happens inside main().  See the subprocess test below.
        p = praxis_server._parse_principal("praxis:local")
        assert p.is_local

    def test_bad_principal(self):
        with pytest.raises(SystemExit):
            praxis_server._parse_principal("bogus")
        with pytest.raises(SystemExit):
            praxis_server._parse_principal("agent:")


class TestBuildServer:
    def test_agent_principal_builds(self, tmp_path):
        from praxis.principal import Principal

        mcp, state = praxis_server.build_server(
            principal=Principal.agent("codex"),
            search_roots=[str(tmp_path)],
            state_dir=tmp_path / ".praxis",
            auto_approve=True,
            no_evidence=True,
        )
        # All the FS tools + praxis_status should be present.
        tools = set(mcp._tool_manager._tools.keys())  # noqa: SLF001
        assert "fs_search" in tools
        assert "fs_delete" in tools
        assert "praxis_status" in tools
        assert state.principal.is_agent


class TestSubprocessStartup:
    """Spawn the real Python entrypoint and assert it prints the banner
    to stderr before we terminate it.  Uses --transport streamable-http
    plus an immediate kill so we don't hang waiting for stdio IO."""

    def test_help_exits_zero(self):
        r = subprocess.run(
            [sys.executable, "-m", "praxis.mcp.praxis_server", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert r.returncode == 0
        assert "praxis-mcp" in r.stdout
        assert "--as-principal" in r.stdout

    def test_refuses_praxis_local_over_mcp(self):
        r = subprocess.run(
            [
                sys.executable,
                "-m",
                "praxis.mcp.praxis_server",
                "--as-principal",
                "praxis:local",
                "--no-evidence",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert r.returncode != 0
        assert "not permitted" in r.stderr.lower()
