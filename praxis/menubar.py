"""
Praxis menubar app — the safe, always-on way to manage the guardrail.

Runs in the macOS menubar / Windows-Linux system tray.  From it you can:

* see and change the guardrail **strictness** (paranoid / balanced /
  permissive),
* **enable or disable** Praxis in each AI tool (Codex, Claude, Cursor,
  Windsurf) with one click,
* open the config folder and quit.

Why a menubar app instead of chat slash-commands?  An AI agent must never
be able to switch off its own guardrail — that would defeat the purpose.
The menubar is *your* trusted, local control surface: only the human at
the keyboard can toggle Praxis here.

The controller (:class:`MenubarController`) is pure logic and unit-tested
without a display; :func:`run_tray` draws the actual tray using ``pystray``
(an optional extra: ``pip install 'praxis-guardrail[menubar]'``).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from praxis.config import PraxisConfig, VALID_STRICTNESS, default_config_path
from praxis.integrations import KNOWN_CLIENTS, build_server_spec, get_client

# Presets a user can pick from the menu (custom is edit-the-file only).
MENU_STRICTNESS = ("paranoid", "balanced", "permissive")


@dataclass(frozen=True)
class ToolState:
    key: str
    display_name: str
    installed: bool
    enabled: bool


class MenubarController:
    """All menubar actions, with no UI dependency (testable headless)."""

    # ---- strictness ----------------------------------------------------
    def strictness(self) -> str:
        return PraxisConfig.load().strictness

    def set_strictness(self, name: str) -> None:
        if name not in VALID_STRICTNESS:
            raise ValueError(f"unknown strictness {name!r}")
        cfg = PraxisConfig.load()
        # Preserve roots; swap to the chosen preset.
        new = PraxisConfig.from_preset(name)
        new.search_roots = cfg.search_roots
        new.save()

    # ---- per-tool enable/disable --------------------------------------
    def tools(self) -> list[ToolState]:
        out: list[ToolState] = []
        for c in KNOWN_CLIENTS:
            out.append(
                ToolState(
                    key=c.key,
                    display_name=c.display_name,
                    installed=c.is_installed(),
                    enabled=c.is_praxis_enabled(),
                )
            )
        return out

    def toggle_tool(self, key: str) -> bool:
        """Enable if disabled, disable if enabled.  Returns the new state."""
        client = get_client(key)
        if client is None:
            raise ValueError(f"unknown tool {key!r}")
        if client.is_praxis_enabled():
            client.disable()
            return False
        client.enable(build_server_spec(key))
        return True

    def any_enabled(self) -> bool:
        return any(t.enabled for t in self.tools())

    # ---- misc ----------------------------------------------------------
    def config_file(self) -> Path:
        return default_config_path()


# ---------------------------------------------------------------------------
# Tray UI (needs pystray + Pillow — the [menubar] extra)
# ---------------------------------------------------------------------------
def _make_icon(active: bool):
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    color = (46, 160, 67, 255) if active else (142, 142, 147, 255)
    # Shield.
    d.polygon(
        [(32, 4), (58, 15), (58, 34), (32, 60), (6, 34), (6, 15)],
        fill=color,
    )
    # Checkmark.
    d.line([(21, 33), (29, 43), (45, 21)], fill=(255, 255, 255, 255), width=6)
    return img


def run_tray(controller: MenubarController | None = None) -> int:
    """Launch the tray.  Blocks until the user quits.  Returns an exit code."""
    try:
        import pystray
        from pystray import Menu, MenuItem as Item
    except ImportError:
        print(
            "The menubar app needs the 'menubar' extra:\n"
            "    pip install 'praxis-guardrail[menubar]'",
        )
        return 1

    ctrl = controller or MenubarController()

    def _title(_item) -> str:
        return f"Praxis — {ctrl.strictness()}"

    def _make_strictness_item(name: str):
        return Item(
            name.capitalize(),
            lambda icon, item: (_set_strict(icon, name)),
            checked=lambda item, n=name: ctrl.strictness() == n,
            radio=True,
        )

    def _set_strict(icon, name: str) -> None:
        ctrl.set_strictness(name)
        icon.icon = _make_icon(ctrl.any_enabled())
        icon.notify(f"Strictness set to {name}. Restart your AI tools.", "Praxis")

    def _make_tool_item(key: str, display: str):
        def _toggle(icon, item):
            try:
                now = ctrl.toggle_tool(key)
            except Exception as e:  # pragma: no cover - defensive
                icon.notify(f"Couldn't toggle {display}: {e}", "Praxis")
                return
            icon.icon = _make_icon(ctrl.any_enabled())
            state = "enabled" if now else "disabled"
            icon.notify(f"Praxis {state} in {display}. Restart it to apply.", "Praxis")

        return Item(
            display,
            _toggle,
            checked=lambda item, k=key: get_client(k).is_praxis_enabled(),  # type: ignore[union-attr]
            enabled=lambda item, k=key: get_client(k).is_installed(),  # type: ignore[union-attr]
        )

    def _open_config(icon, item):
        import subprocess
        import sys

        path = ctrl.config_file().parent
        path.mkdir(parents=True, exist_ok=True)
        if sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        elif sys.platform.startswith("win"):
            subprocess.Popen(["explorer", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])

    strictness_menu = Menu(*(_make_strictness_item(n) for n in MENU_STRICTNESS))
    tool_items = [_make_tool_item(c.key, c.display_name) for c in KNOWN_CLIENTS]

    menu = Menu(
        Item(_title, None, enabled=False),
        Menu.SEPARATOR,
        Item("Strictness", strictness_menu),
        Menu.SEPARATOR,
        Item("AI tools", Menu(*tool_items)),
        Menu.SEPARATOR,
        Item("Open config folder…", _open_config),
        Item("Quit Praxis", lambda icon, item: icon.stop()),
    )

    icon = pystray.Icon(
        "praxis",
        icon=_make_icon(ctrl.any_enabled()),
        title="Praxis — guardrail for agentic AI",
        menu=menu,
    )
    icon.run()
    return 0


__all__ = ["MenubarController", "ToolState", "MENU_STRICTNESS", "run_tray"]
