"""
Start the Praxis menubar app automatically at login.

Cross-platform:

* **macOS** — a LaunchAgent at ``~/Library/LaunchAgents/app.praxis.menubar.plist``
* **Linux** — an XDG autostart entry at ``~/.config/autostart/praxis.desktop``
* **Windows** — a ``Praxis`` value under the ``Run`` registry key

``praxis autostart enable`` / ``disable`` drive this from the CLI; the
installers call it so Praxis is running (and stays running) after setup.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

LABEL = "app.praxis.menubar"


def menubar_command() -> list[str]:
    """The command that launches the menubar app for this install."""
    if getattr(sys, "frozen", False):
        # PyInstaller bundle: the executable itself + the subcommand.
        return [sys.executable, "menubar"]
    praxis = shutil.which("praxis")
    if praxis:
        return [praxis, "menubar"]
    return [sys.executable, "-m", "praxis", "menubar"]


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------
def _mac_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def _mac_enable() -> Path:
    cmd = menubar_command()
    args_xml = "\n".join(f"    <string>{a}</string>" for a in cmd)
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array>
{args_xml}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
</dict></plist>
"""
    path = _mac_plist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(plist)
    # (Re)load it so it starts now too.
    subprocess.run(["launchctl", "unload", str(path)], capture_output=True)
    subprocess.run(["launchctl", "load", str(path)], capture_output=True)
    return path


def _mac_disable() -> None:
    path = _mac_plist_path()
    if path.exists():
        subprocess.run(["launchctl", "unload", str(path)], capture_output=True)
        path.unlink()


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------
def _linux_desktop_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "autostart" / "praxis.desktop"


def _linux_enable() -> Path:
    cmd = " ".join(menubar_command())
    entry = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Praxis\n"
        "Comment=Guardrail for agentic AI\n"
        f"Exec={cmd}\n"
        "X-GNOME-Autostart-enabled=true\n"
    )
    path = _linux_desktop_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(entry)
    return path


def _linux_disable() -> None:
    path = _linux_desktop_path()
    if path.exists():
        path.unlink()


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------
def _win_enable() -> str:
    import winreg  # type: ignore[import-not-found]

    cmd = " ".join(f'"{a}"' if " " in a else a for a in menubar_command())
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        0,
        winreg.KEY_SET_VALUE,
    )
    winreg.SetValueEx(key, "Praxis", 0, winreg.REG_SZ, cmd)
    winreg.CloseKey(key)
    return cmd


def _win_disable() -> None:
    import winreg  # type: ignore[import-not-found]

    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE,
        )
        winreg.DeleteValue(key, "Praxis")
        winreg.CloseKey(key)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def enable() -> str:
    """Enable login autostart for this platform.  Returns a description."""
    if sys.platform == "darwin":
        return f"LaunchAgent installed at {_mac_enable()}"
    if sys.platform.startswith("win"):
        return f"Run key set: {_win_enable()}"
    return f"Autostart entry at {_linux_enable()}"


def disable() -> None:
    if sys.platform == "darwin":
        _mac_disable()
    elif sys.platform.startswith("win"):
        _win_disable()
    else:
        _linux_disable()


def is_enabled() -> bool:
    if sys.platform == "darwin":
        return _mac_plist_path().exists()
    if sys.platform.startswith("win"):
        import winreg  # type: ignore[import-not-found]

        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
            )
            winreg.QueryValueEx(key, "Praxis")
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            return False
    return _linux_desktop_path().exists()


__all__ = ["enable", "disable", "is_enabled", "menubar_command", "LABEL"]
