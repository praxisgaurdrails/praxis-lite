"""Tests for the menubar controller (headless — no tray/display needed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from praxis.integrations import KNOWN_CLIENTS, get_client
from praxis.menubar import MENU_STRICTNESS, MenubarController, ToolState


@pytest.fixture
def ctrl(tmp_path, monkeypatch):
    # Point config at an isolated state dir.
    monkeypatch.setenv("PRAXIS_STATE_DIR", str(tmp_path))
    return MenubarController()


def test_strictness_defaults_to_balanced(ctrl):
    assert ctrl.strictness() == "balanced"


def test_set_and_get_strictness_roundtrip(ctrl):
    for name in MENU_STRICTNESS:
        ctrl.set_strictness(name)
        assert ctrl.strictness() == name


def test_set_strictness_preserves_roots(ctrl, tmp_path):
    from praxis.config import PraxisConfig

    cfg = PraxisConfig.from_preset("balanced")
    cfg.search_roots = ["~/Projects", "~/Notes"]
    cfg.save(tmp_path / "config.toml")

    ctrl.set_strictness("paranoid")
    from praxis.config import PraxisConfig as PC

    reloaded = PC.load(tmp_path / "config.toml")
    assert reloaded.strictness == "paranoid"
    assert reloaded.search_roots == ["~/Projects", "~/Notes"]


def test_invalid_strictness_raises(ctrl):
    with pytest.raises(ValueError):
        ctrl.set_strictness("nope")


def test_tools_lists_all_known_clients(ctrl):
    tools = ctrl.tools()
    assert len(tools) == len(KNOWN_CLIENTS)
    assert all(isinstance(t, ToolState) for t in tools)
    keys = {t.key for t in tools}
    assert {"codex", "claude-desktop", "cursor", "windsurf"} <= keys


def test_toggle_tool_enables_then_disables(tmp_path, monkeypatch):
    monkeypatch.setenv("PRAXIS_STATE_DIR", str(tmp_path))
    ctrl = MenubarController()

    # Redirect the codex client at an isolated TOML config.
    cfg = tmp_path / "codex.toml"
    cfg.write_text('model = "x"\n[mcp_servers.node]\ncommand = "node"\nargs = []\n')
    codex = get_client("codex")
    monkeypatch.setattr(codex, "config_path", cfg)

    assert codex.is_praxis_enabled() is False
    assert ctrl.toggle_tool("codex") is True         # enable
    assert codex.is_praxis_enabled() is True
    assert ctrl.toggle_tool("codex") is False        # disable
    assert codex.is_praxis_enabled() is False
    # untouched neighbour survives
    assert "node" in cfg.read_text()


def test_toggle_unknown_tool_raises(ctrl):
    with pytest.raises(ValueError):
        ctrl.toggle_tool("nonexistent")


def test_config_file_path(ctrl, tmp_path):
    assert ctrl.config_file() == tmp_path / "config.toml"


def test_icon_renders():
    from praxis.menubar import _make_icon

    img = _make_icon(active=True)
    assert img.size == (64, 64)
    img2 = _make_icon(active=False)
    assert img2.size == (64, 64)


# --- autostart (logic only; no launchctl/registry side effects) -----------

def test_autostart_menubar_command_is_list():
    from praxis import autostart

    cmd = autostart.menubar_command()
    assert isinstance(cmd, list) and cmd
    assert cmd[-1] == "menubar"


def test_autostart_disabled_by_default(monkeypatch, tmp_path):
    from praxis import autostart

    # Point HOME at an empty dir so no plist/desktop entry exists.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(autostart.Path, "home", classmethod(lambda cls: tmp_path))
    assert autostart.is_enabled() is False
