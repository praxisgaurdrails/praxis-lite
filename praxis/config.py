"""
Praxis user configuration — how deep the guardrail interrupts tool calls.

Historically the tier x principal decision matrix was hard-coded.  This
module makes it user-configurable so people can choose *how strict* Praxis
is for external agents and for themselves, without editing code.

The config lives at ``$PRAXIS_STATE_DIR/config.toml`` (default
``~/.praxis/config.toml``) and is created by ``praxis init``.

Model
-----
Every action has a *risk tier* (T0 read, T1 write, T2 delete, T3 root) and
a *principal* (``praxis:local`` = you, ``agent:*`` = an external AI).  For
each (principal-class, tier) the outcome is one of:

* ``allow``  — let it run (the per-domain rule layer still applies)
* ``ask``    — require your approval first
* ``block``  — refuse

Two rules are **not** configurable, by design:

* an ``unknown`` (unauthenticated) caller is always blocked
* T3 (root / irreversible) is always blocked at the chat surface

Presets
-------
* ``paranoid``   — agents may only read; you get asked before writes/deletes
* ``balanced``   — the default; agents read freely, writes need approval,
                   deletes are blocked; you write freely, deletes ask
* ``permissive`` — agents may delete with approval; you act freely
* ``custom``     — the matrix is whatever you set
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

Outcome = Literal["allow", "ask", "block"]

# read=T0, write=T1, delete=T2
_ACTIONS = ("read", "write", "delete")

DEFAULT_SEARCH_ROOTS = ["~/Documents", "~/Downloads", "~/Desktop"]

PRESETS: dict[str, dict[str, dict[str, Outcome]]] = {
    "paranoid": {
        "local": {"read": "allow", "write": "ask", "delete": "ask"},
        "agent": {"read": "allow", "write": "block", "delete": "block"},
    },
    # Balanced == the historical hard-coded matrix.  Keep it identical.
    "balanced": {
        "local": {"read": "allow", "write": "allow", "delete": "ask"},
        "agent": {"read": "allow", "write": "ask", "delete": "block"},
    },
    "permissive": {
        "local": {"read": "allow", "write": "allow", "delete": "allow"},
        "agent": {"read": "allow", "write": "ask", "delete": "ask"},
    },
}

VALID_STRICTNESS = ("paranoid", "balanced", "permissive", "custom")


def default_config_path() -> Path:
    """Resolve the config path from ``$PRAXIS_STATE_DIR`` or ``~/.praxis``."""
    state = os.environ.get("PRAXIS_STATE_DIR")
    base = Path(state).expanduser() if state else Path.home() / ".praxis"
    return base / "config.toml"


@dataclass
class PraxisConfig:
    """Resolved Praxis configuration."""

    strictness: str = "balanced"
    search_roots: list[str] = field(
        default_factory=lambda: list(DEFAULT_SEARCH_ROOTS)
    )
    # Per (principal-class, action) outcome.  Populated from the preset
    # unless strictness == "custom".
    decisions: dict[str, dict[str, Outcome]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.decisions:
            preset = self.strictness if self.strictness in PRESETS else "balanced"
            # deep copy so callers can't mutate the shared PRESETS dict
            self.decisions = {
                who: dict(actions) for who, actions in PRESETS[preset].items()
            }

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------
    def outcome(self, principal_class: str, action: str) -> Outcome:
        """Return ``allow`` / ``ask`` / ``block`` for a principal-class
        (``"local"`` or ``"agent"``) and an action (``read`` / ``write`` /
        ``delete``).  Unknown inputs fail safe to ``block``."""
        table = self.decisions.get(principal_class)
        if not table:
            return "block"
        return table.get(action, "block")

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    @classmethod
    def from_preset(cls, strictness: str) -> "PraxisConfig":
        if strictness not in VALID_STRICTNESS:
            raise ValueError(
                f"strictness must be one of {VALID_STRICTNESS}, got {strictness!r}"
            )
        return cls(strictness=strictness)

    @classmethod
    def load(cls, path: Path | None = None) -> "PraxisConfig":
        """Load config from ``path`` (default resolved path).  If the file
        is missing or unreadable, return the Balanced default."""
        path = path or default_config_path()
        if not path.exists() or tomllib is None:
            return cls()  # balanced default
        try:
            data = tomllib.loads(path.read_text())
        except Exception:
            return cls()
        strictness = str(data.get("strictness", "balanced")).lower()
        if strictness not in VALID_STRICTNESS:
            strictness = "balanced"
        roots = data.get("search_roots") or list(DEFAULT_SEARCH_ROOTS)

        decisions: dict[str, dict[str, Outcome]] = {}
        if strictness == "custom":
            raw = data.get("decisions", {})
            for who in ("local", "agent"):
                actions = raw.get(who, {}) if isinstance(raw, dict) else {}
                base = dict(PRESETS["balanced"][who])
                for act in _ACTIONS:
                    val = str(actions.get(act, base[act])).lower()
                    base[act] = val if val in ("allow", "ask", "block") else base[act]  # type: ignore[assignment]
                decisions[who] = base
        return cls(strictness=strictness, search_roots=list(roots), decisions=decisions)

    def to_toml(self) -> str:
        """Serialise to TOML text (hand-rolled — no writer dependency)."""
        def _arr(items: list[str]) -> str:
            return "[" + ", ".join('"' + i.replace('"', '\\"') + '"' for i in items) + "]"

        lines = [
            "# Praxis configuration — how deep the guardrail interrupts tool calls.",
            "# Docs: https://github.com/praxisgaurdrails/praxis-lite",
            "",
            "# paranoid | balanced | permissive | custom",
            f'strictness = "{self.strictness}"',
            "",
            "# Folders agents (and you) may search/read.",
            f"search_roots = {_arr(self.search_roots)}",
        ]
        if self.strictness == "custom":
            lines += [
                "",
                "# Per (principal, action) outcome: allow | ask | block.",
                "# read = T0, write = T1, delete = T2. (T3/root is always blocked.)",
            ]
            for who in ("local", "agent"):
                lines.append("")
                lines.append(f"[decisions.{who}]")
                for act in _ACTIONS:
                    lines.append(f'{act} = "{self.decisions[who][act]}"')
        return "\n".join(lines) + "\n"

    def save(self, path: Path | None = None) -> Path:
        path = path or default_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_toml())
        return path


# ---------------------------------------------------------------------------
# Process-wide cached config (so the tier gate can consult it cheaply)
# ---------------------------------------------------------------------------
_ACTIVE: PraxisConfig | None = None


def get_config() -> PraxisConfig:
    """Return the process-wide config, loading it on first use."""
    global _ACTIVE
    if _ACTIVE is None:
        _ACTIVE = PraxisConfig.load()
    return _ACTIVE


def set_config(config: PraxisConfig) -> None:
    """Install a config as the process-wide active one (used by the daemon
    and the MCP server after they resolve their state dir)."""
    global _ACTIVE
    _ACTIVE = config


def reset_config() -> None:
    """Clear the cache (tests)."""
    global _ACTIVE
    _ACTIVE = None


__all__ = [
    "PraxisConfig",
    "PRESETS",
    "VALID_STRICTNESS",
    "DEFAULT_SEARCH_ROOTS",
    "Outcome",
    "default_config_path",
    "get_config",
    "set_config",
    "reset_config",
]
