"""Tests for enabling/disabling Praxis in on-device AI tools."""

import json

import pytest

from praxis.integrations.clients import (
    ConfigFormat,
    MCPClient,
    build_server_spec,
    detect_clients,
    get_client,
)


# ---------------------------------------------------------------------------
# Server spec
# ---------------------------------------------------------------------------


class TestServerSpec:
    def test_default_spec_is_read_only(self):
        spec = build_server_spec("codex")
        assert spec["command"]  # sys.executable
        assert "-m" in spec["args"]
        assert "praxis.mcp.praxis_server" in spec["args"]
        assert "--as-principal" in spec["args"]
        assert "agent:codex" in spec["args"]
        # read-only default → no --auto-approve
        assert "--auto-approve" not in spec["args"]

    def test_allow_writes_adds_auto_approve(self):
        spec = build_server_spec("codex", allow_writes=True)
        assert "--auto-approve" in spec["args"]

    def test_search_roots_comma_joined(self):
        spec = build_server_spec("codex", search_roots=["/a", "/b"])
        i = spec["args"].index("--search-roots")
        assert spec["args"][i + 1] == "/a,/b"


# ---------------------------------------------------------------------------
# JSON client (Claude Desktop / Cursor shape)
# ---------------------------------------------------------------------------


@pytest.fixture
def json_client(tmp_path):
    return MCPClient(
        key="test-json",
        display_name="Test JSON Client",
        config_path=tmp_path / "cfg" / "mcp.json",
        fmt=ConfigFormat.JSON,
        servers_key="mcpServers",
        parent_dir_hint=tmp_path / "cfg",
    )


class TestJSONClient:
    def test_enable_creates_config(self, json_client):
        assert not json_client.is_praxis_enabled()
        json_client.enable(build_server_spec("test-json"))
        assert json_client.config_path.exists()
        assert json_client.is_praxis_enabled()
        data = json.loads(json_client.config_path.read_text())
        assert "praxis" in data["mcpServers"]

    def test_enable_preserves_existing_servers(self, json_client):
        json_client.config_path.parent.mkdir(parents=True)
        json_client.config_path.write_text(json.dumps({
            "mcpServers": {"other": {"command": "foo", "args": []}},
            "someOtherSetting": 42,
        }))
        json_client.enable(build_server_spec("test-json"))
        data = json.loads(json_client.config_path.read_text())
        assert "other" in data["mcpServers"]
        assert "praxis" in data["mcpServers"]
        assert data["someOtherSetting"] == 42

    def test_disable_removes_only_praxis(self, json_client):
        json_client.config_path.parent.mkdir(parents=True)
        json_client.config_path.write_text(json.dumps({
            "mcpServers": {"other": {"command": "foo", "args": []}},
        }))
        json_client.enable(build_server_spec("test-json"))
        assert json_client.disable()
        data = json.loads(json_client.config_path.read_text())
        assert "other" in data["mcpServers"]
        assert "praxis" not in data["mcpServers"]

    def test_disable_when_absent_returns_false(self, json_client):
        json_client.config_path.parent.mkdir(parents=True)
        json_client.config_path.write_text(json.dumps({"mcpServers": {}}))
        assert json_client.disable() is False

    def test_roundtrip_idempotent(self, json_client):
        spec = build_server_spec("test-json")
        json_client.enable(spec)
        json_client.enable(spec)  # enabling twice shouldn't duplicate
        data = json.loads(json_client.config_path.read_text())
        # Only one praxis entry (dict key, so inherently unique).
        assert list(data["mcpServers"].keys()).count("praxis") == 1


# ---------------------------------------------------------------------------
# TOML client (Codex shape)
# ---------------------------------------------------------------------------


@pytest.fixture
def toml_client(tmp_path):
    return MCPClient(
        key="test-toml",
        display_name="Test TOML Client",
        config_path=tmp_path / "config.toml",
        fmt=ConfigFormat.TOML,
        servers_key="mcp_servers",
        parent_dir_hint=tmp_path,
    )


class TestTOMLClient:
    def test_enable_creates_valid_toml(self, toml_client):
        import tomllib

        toml_client.enable(build_server_spec("test-toml"))
        data = tomllib.loads(toml_client.config_path.read_text())
        assert "praxis" in data["mcp_servers"]
        assert data["mcp_servers"]["praxis"]["command"]

    def test_enable_preserves_other_stanzas(self, toml_client):
        import tomllib

        toml_client.config_path.write_text(
            'model = "gpt-6"\n\n'
            '[mcp_servers.node_repl]\n'
            'command = "node"\n'
            'args = []\n\n'
            '[some_other_table]\n'
            'x = 1\n'
        )
        toml_client.enable(build_server_spec("test-toml"))
        data = tomllib.loads(toml_client.config_path.read_text())
        assert data["model"] == "gpt-6"
        assert "node_repl" in data["mcp_servers"]
        assert "praxis" in data["mcp_servers"]
        assert data["some_other_table"]["x"] == 1

    def test_disable_removes_only_praxis(self, toml_client):
        import tomllib

        toml_client.config_path.write_text(
            '[mcp_servers.node_repl]\n'
            'command = "node"\n'
            'args = []\n'
        )
        toml_client.enable(build_server_spec("test-toml"))
        assert toml_client.disable()
        data = tomllib.loads(toml_client.config_path.read_text())
        assert "node_repl" in data["mcp_servers"]
        assert "praxis" not in data.get("mcp_servers", {})

    def test_disable_removes_praxis_subtables(self, toml_client):
        """Regression: disable must remove nested [mcp_servers.praxis.*]
        sub-tables (e.g. per-tool settings a client adds), even when they
        appear *before* the main [mcp_servers.praxis] stanza."""
        import tomllib

        toml_client.config_path.write_text(
            '[mcp_servers.node_repl]\n'
            'command = "node"\n'
            'args = []\n\n'
            '[mcp_servers.praxis.tools.fs_read]\n'
            'auto_approve = true\n\n'
            '[mcp_servers.praxis.tools.fs_search]\n'
            'auto_approve = true\n\n'
            '# Praxis — guardrail for agentic AI (added by `praxis enable`)\n'
            '[mcp_servers.praxis]\n'
            'command = "python"\n'
            'args = ["-m", "praxis.mcp.praxis_server"]\n'
        )
        assert toml_client.disable()
        text = toml_client.config_path.read_text()
        assert "praxis" not in text.lower()
        data = tomllib.loads(text)
        assert "node_repl" in data["mcp_servers"]
        assert "praxis" not in data.get("mcp_servers", {})

    def test_enable_twice_no_duplicate(self, toml_client):
        toml_client.enable(build_server_spec("test-toml"))
        toml_client.enable(build_server_spec("test-toml"))
        text = toml_client.config_path.read_text()
        assert text.count("[mcp_servers.praxis]") == 1

    def test_disable_when_absent_returns_false(self, toml_client):
        toml_client.config_path.write_text('model = "x"\n')
        assert toml_client.disable() is False

    def test_backup_created_on_enable(self, toml_client):
        toml_client.config_path.write_text('model = "x"\n')
        toml_client.enable(build_server_spec("test-toml"))
        backups = list(toml_client.config_path.parent.glob("*.praxis-bak-*"))
        assert backups


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestDetection:
    def test_get_client_known(self):
        assert get_client("codex") is not None
        assert get_client("claude-desktop") is not None
        assert get_client("nonexistent") is None

    def test_detect_returns_all_known(self):
        statuses = detect_clients()
        keys = {s.client.key for s in statuses}
        assert "codex" in keys
        assert "claude-desktop" in keys
        assert "cursor" in keys

    def test_is_installed_via_parent_dir(self, tmp_path):
        c = MCPClient(
            key="x", display_name="X",
            config_path=tmp_path / "sub" / "cfg.json",
            fmt=ConfigFormat.JSON, servers_key="mcpServers",
            parent_dir_hint=tmp_path / "sub",
        )
        assert not c.is_installed()
        (tmp_path / "sub").mkdir()
        assert c.is_installed()
