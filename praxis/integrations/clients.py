"""
Praxis client integrations — enable/disable Praxis in on-device AI tools.

Each supported AI client (Codex, Claude Desktop, Cursor, Windsurf, …)
stores its MCP-server list in a config file.  "Enabling" Praxis means
inserting an ``mcpServers.praxis`` (or ``mcp_servers.praxis``) entry
that tells the client how to spawn the Praxis MCP server.  "Disabling"
means removing that entry.

Two config formats are handled:

* **JSON** (Claude Desktop, Cursor, Windsurf) — parse, edit the servers
  dict, write back.  Clean and lossless.
* **TOML** (Codex) — Python has no stdlib TOML writer, so we edit the
  text directly: remove any existing ``[mcp_servers.praxis]`` stanza and
  append a fresh one.  The rest of the file is preserved byte-for-byte.

The server command we generate uses the *current* Python interpreter
(``sys.executable``) running ``-m praxis.mcp.praxis_server``.  Because
Praxis is pip-installed into that interpreter's environment, the command
works from any working directory — which is exactly the bug that used to
break Codex (it spawns from ``/``).
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Server spec — the command an AI client uses to spawn Praxis
# ---------------------------------------------------------------------------


def build_server_spec(
    agent_name: str,
    search_roots: list[str] | None = None,
    state_dir: Path | None = None,
    allow_writes: bool = False,
    python_executable: str | None = None,
) -> dict[str, Any]:
    """Build the ``{command, args}`` spec an MCP client uses to launch Praxis.

    ``agent_name`` becomes the principal (``agent:<name>``) so the
    evidence log shows which client did what.

    ``allow_writes`` adds ``--auto-approve``.  Off by default for the
    beta: agents can read but T1 writes require the (not-yet-shipped)
    approval UI, so they're denied — a safe posture.  Reads work,
    deletes are blocked, secrets refused.  All the guardrail behavior
    is visible without auto-approving writes.

    The generated command adapts to how Praxis is installed:

    * **Frozen bundle** (PyInstaller ``.app`` / ``.exe``): the command is
      the bundled ``praxis`` executable with the ``mcp`` subcommand.  No
      Python interpreter needed on the user's machine.
    * **pip install**: the command is the Python interpreter running
      ``-m praxis.mcp.praxis_server``.
    """
    roots = search_roots or [
        str(Path.home() / "Documents"),
        str(Path.home() / "Downloads"),
        str(Path.home() / "Desktop"),
    ]
    state = state_dir or (Path.home() / ".praxis")

    common_tail = [
        "--as-principal", f"agent:{agent_name}",
        "--search-roots", ",".join(roots),
        "--state-dir", str(state),
    ]
    if allow_writes:
        common_tail.append("--auto-approve")

    if getattr(sys, "frozen", False):
        # Running as a PyInstaller bundle — point at ourselves + `mcp`.
        command = sys.executable
        args = ["mcp"] + common_tail
    else:
        py = python_executable or sys.executable
        command = py
        args = ["-m", "praxis.mcp.praxis_server"] + common_tail

    return {"command": command, "args": args}


# ---------------------------------------------------------------------------
# Client model
# ---------------------------------------------------------------------------


class ConfigFormat(str, Enum):
    JSON = "json"
    TOML = "toml"


@dataclass
class MCPClient:
    """One AI client we can enable/disable Praxis in."""

    key: str                    # short id: "codex", "claude-desktop", "cursor"
    display_name: str
    config_path: Path
    fmt: ConfigFormat
    servers_key: str            # "mcp_servers" (Codex) or "mcpServers" (rest)
    parent_dir_hint: Path | None = None
    """A directory whose presence indicates the app is installed even if
    the config file doesn't exist yet."""

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def is_installed(self) -> bool:
        """True if the client appears to be installed on this machine."""
        if self.config_path.exists():
            return True
        if self.parent_dir_hint and self.parent_dir_hint.exists():
            return True
        return False

    def is_praxis_enabled(self) -> bool:
        """True if a Praxis entry is present in the client's config."""
        if not self.config_path.exists():
            return False
        try:
            if self.fmt == ConfigFormat.JSON:
                data = json.loads(self.config_path.read_text() or "{}")
                servers = data.get(self.servers_key, {}) or {}
                return "praxis" in servers
            else:  # TOML — text scan is enough for detection
                text = self.config_path.read_text()
                return bool(re.search(
                    rf"^\[{re.escape(self.servers_key)}\.praxis\]",
                    text,
                    re.MULTILINE,
                ))
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Enable / disable
    # ------------------------------------------------------------------

    def enable(self, server_spec: dict[str, Any]) -> None:
        """Add / replace the Praxis MCP entry.  Backs up the config first."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._backup()
        if self.fmt == ConfigFormat.JSON:
            self._enable_json(server_spec)
        else:
            self._enable_toml(server_spec)

    def disable(self) -> bool:
        """Remove the Praxis MCP entry.  Returns True if something changed."""
        if not self.config_path.exists():
            return False
        self._backup()
        if self.fmt == ConfigFormat.JSON:
            return self._disable_json()
        return self._disable_toml()

    # ------------------------------------------------------------------
    # JSON impl
    # ------------------------------------------------------------------

    def _enable_json(self, server_spec: dict[str, Any]) -> None:
        data: dict[str, Any] = {}
        if self.config_path.exists() and self.config_path.read_text().strip():
            data = json.loads(self.config_path.read_text())
        servers = data.setdefault(self.servers_key, {})
        servers["praxis"] = server_spec
        self.config_path.write_text(json.dumps(data, indent=2) + "\n")

    def _disable_json(self) -> bool:
        if not self.config_path.read_text().strip():
            return False
        data = json.loads(self.config_path.read_text())
        servers = data.get(self.servers_key, {})
        if "praxis" not in servers:
            return False
        del servers["praxis"]
        self.config_path.write_text(json.dumps(data, indent=2) + "\n")
        return True

    # ------------------------------------------------------------------
    # TOML impl (text-edit to preserve the rest of the file)
    # ------------------------------------------------------------------

    def _enable_toml(self, server_spec: dict[str, Any]) -> None:
        text = ""
        if self.config_path.exists():
            text = self.config_path.read_text()
        text = self._strip_toml_praxis(text)
        stanza = self._render_toml_stanza(server_spec)
        text = text.rstrip() + "\n\n" + stanza + "\n"
        self.config_path.write_text(text)

    def _disable_toml(self) -> bool:
        text = self.config_path.read_text()
        new_text = self._strip_toml_praxis(text)
        if new_text == text:
            return False
        self.config_path.write_text(new_text.rstrip() + "\n")
        return True

    def _strip_toml_praxis(self, text: str) -> str:
        """Remove the *entire* Praxis entry: the ``[mcp_servers.praxis]``
        table **and** every ``[mcp_servers.praxis.*]`` sub-table (e.g. the
        per-tool ``[mcp_servers.praxis.tools.fs_read]`` settings a client
        may add), plus any leading Praxis comment banner.

        Done line-by-line (rather than one regex) so a nested sub-table
        that appears *before* the main stanza is still removed."""
        exact = f"{self.servers_key}.praxis"
        prefix = f"{self.servers_key}.praxis."
        out: list[str] = []
        skipping = False
        removed_any = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                name = stripped.strip("[]").strip()
                if name == exact or name.startswith(prefix):
                    skipping = True
                    removed_any = True
                    # Drop trailing blank lines and a preceding Praxis
                    # comment banner already collected in `out`.
                    while out and out[-1].strip() == "":
                        out.pop()
                    if (
                        out
                        and out[-1].lstrip().startswith("#")
                        and "praxis" in out[-1].lower()
                    ):
                        out.pop()
                    continue
                skipping = False
            if not skipping:
                out.append(line)
        if not removed_any:
            # Nothing matched — return the text byte-for-byte unchanged so
            # callers can reliably detect "no change".
            return text
        return "\n".join(out)

    def _render_toml_stanza(self, server_spec: dict[str, Any]) -> str:
        command = server_spec["command"]
        args = server_spec["args"]
        args_toml = "[" + ", ".join(_toml_str(a) for a in args) + "]"
        return (
            "# Praxis — guardrail for agentic AI (added by `praxis enable`)\n"
            f"[{self.servers_key}.praxis]\n"
            f"command = {_toml_str(command)}\n"
            f"args = {args_toml}\n"
            "startup_timeout_sec = 60\n"
        )

    # ------------------------------------------------------------------
    # Backup
    # ------------------------------------------------------------------

    def _backup(self) -> None:
        if not self.config_path.exists():
            return
        ts = time.strftime("%Y%m%d-%H%M%S")
        backup = self.config_path.with_suffix(
            self.config_path.suffix + f".praxis-bak-{ts}"
        )
        try:
            shutil.copy2(self.config_path, backup)
        except OSError:
            pass


def _toml_str(s: str) -> str:
    """Serialise a string as a TOML basic string."""
    escaped = str(s).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@dataclass
class ClientStatus:
    client: MCPClient
    installed: bool
    enabled: bool


# ---------------------------------------------------------------------------
# Known clients
# ---------------------------------------------------------------------------


def _known_clients() -> list[MCPClient]:
    home = Path.home()
    clients: list[MCPClient] = [
        MCPClient(
            key="codex",
            display_name="ChatGPT / Codex Desktop",
            config_path=home / ".codex" / "config.toml",
            fmt=ConfigFormat.TOML,
            servers_key="mcp_servers",
            parent_dir_hint=home / ".codex",
        ),
        MCPClient(
            key="claude-desktop",
            display_name="Claude Desktop",
            config_path=home / "Library" / "Application Support" / "Claude"
            / "claude_desktop_config.json",
            fmt=ConfigFormat.JSON,
            servers_key="mcpServers",
            parent_dir_hint=home / "Library" / "Application Support" / "Claude",
        ),
        MCPClient(
            key="cursor",
            display_name="Cursor",
            config_path=home / ".cursor" / "mcp.json",
            fmt=ConfigFormat.JSON,
            servers_key="mcpServers",
            parent_dir_hint=home / ".cursor",
        ),
        MCPClient(
            key="windsurf",
            display_name="Windsurf",
            config_path=home / ".codeium" / "windsurf" / "mcp_config.json",
            fmt=ConfigFormat.JSON,
            servers_key="mcpServers",
            parent_dir_hint=home / ".codeium" / "windsurf",
        ),
    ]
    return clients


KNOWN_CLIENTS: list[MCPClient] = _known_clients()


def get_client(key: str) -> MCPClient | None:
    for c in KNOWN_CLIENTS:
        if c.key == key:
            return c
    return None


def detect_clients(installed_only: bool = False) -> list[ClientStatus]:
    """Return status for every known client (optionally only installed)."""
    out: list[ClientStatus] = []
    for c in KNOWN_CLIENTS:
        installed = c.is_installed()
        if installed_only and not installed:
            continue
        out.append(ClientStatus(
            client=c,
            installed=installed,
            enabled=c.is_praxis_enabled(),
        ))
    return out


__all__ = [
    "ClientStatus",
    "ConfigFormat",
    "KNOWN_CLIENTS",
    "MCPClient",
    "build_server_spec",
    "detect_clients",
    "get_client",
]
