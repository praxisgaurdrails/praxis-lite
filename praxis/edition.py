"""
Praxis edition detection.

Praxis ships in two editions:

* **Lite** (free) — the MCP filesystem guardrail.  What most people
  download.  No browser guardrail, no REST sidecar, no dashboard, no
  NLP semantic matching.
* **Full** (paid) — everything, including the Playwright browser
  guardrail, the REST sidecar (OpenClaw / framework integration), the
  web dashboard, and NLP semantic intent matching.

Editions are distinguished by which optional subsystems are importable.
A pip install of ``praxis-agent[all]`` is effectively Full; the lean
bundle is Lite.  This module reports which one is running so the CLI,
the licensing layer, and support tooling can behave honestly.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass


def _has(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


@dataclass(frozen=True)
class Edition:
    """Which premium subsystems are available in this install."""

    browser_guardrail: bool     # Playwright — SecureBrowser
    rest_sidecar: bool          # fastapi + uvicorn
    dashboard: bool             # fastapi + jinja2
    semantic_matching: bool     # fastembed — NLP intent layer

    @property
    def is_full(self) -> bool:
        # Full = the browser guardrail + sidecar are present.  These are
        # the headline paid features; semantic is a bonus.
        return self.browser_guardrail and self.rest_sidecar

    @property
    def name(self) -> str:
        return "Full" if self.is_full else "Lite"

    def missing(self) -> list[str]:
        out = []
        if not self.browser_guardrail:
            out.append("browser guardrail (SecureBrowser)")
        if not self.rest_sidecar:
            out.append("REST sidecar (OpenClaw / framework integration)")
        if not self.dashboard:
            out.append("web dashboard")
        if not self.semantic_matching:
            out.append("NLP semantic matching")
        return out


def detect_edition() -> Edition:
    """Detect the running edition from importable subsystems."""
    return Edition(
        browser_guardrail=_has("playwright"),
        rest_sidecar=_has("fastapi") and _has("uvicorn"),
        dashboard=_has("fastapi") and _has("jinja2"),
        semantic_matching=_has("fastembed"),
    )


__all__ = ["Edition", "detect_edition"]
