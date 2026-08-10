"""
LLM registry — picks the first available backend from an ordered list.

The daemon builds a registry once at startup with the priority the
user configured (usually: cloud first when online, Ollama when
offline).  Every ``chat()`` call from the popover / runbook picks the
first backend whose :meth:`is_available` returns True.

If a backend raises :class:`LLMBackendUnavailable` mid-request we fall
through to the next one and re-try.  Any other exception is surfaced
— those are real bugs, not fallback triggers.
"""

from __future__ import annotations

import logging
from typing import Any

from praxis.llm.base import (
    LLMBackend,
    LLMBackendUnavailable,
    LLMMessage,
    LLMResponse,
    ToolSpec,
)

logger = logging.getLogger("praxis.llm.registry")


class LLMRegistry:
    """Ordered list of backends with automatic fallthrough."""

    def __init__(self, backends: list[LLMBackend] | None = None) -> None:
        self._backends: list[LLMBackend] = list(backends or [])

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, backend: LLMBackend) -> None:
        self._backends.append(backend)

    def clear(self) -> None:
        self._backends.clear()

    def backends(self) -> list[LLMBackend]:
        return list(self._backends)

    @property
    def is_empty(self) -> bool:
        return not self._backends

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    async def available_backends(self) -> list[LLMBackend]:
        """Return backends whose ``is_available`` currently reports True.

        Concurrency: probes happen serially so a hung backend can't slow
        down the healthy ones' availability check.  For a fast probe
        strategy, subclass and override.
        """
        out: list[LLMBackend] = []
        for b in self._backends:
            try:
                if await b.is_available():
                    out.append(b)
            except Exception:
                logger.debug("backend %s is_available raised", b.name, exc_info=True)
        return out

    async def status_snapshot(self) -> dict[str, Any]:
        """Return a JSON-serialisable status blob for the status endpoint."""
        rows = []
        for b in self._backends:
            available = False
            try:
                available = await b.is_available()
            except Exception:
                pass
            rows.append({
                "name": b.name,
                "supports_tools": bool(getattr(b, "supports_tools", False)),
                "available": available,
            })
        return {"backends": rows}

    # ------------------------------------------------------------------
    # Chat with fallthrough
    # ------------------------------------------------------------------

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolSpec] | None = None,
        model: str = "",
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Pick the first available backend and run.

        If it raises :class:`LLMBackendUnavailable` we try the next
        one.  If every backend fails, we re-raise the last error.
        """
        if not self._backends:
            raise LLMBackendUnavailable("no LLM backends registered")

        last_error: Exception | None = None
        for b in self._backends:
            try:
                if not await b.is_available():
                    continue
            except Exception as e:
                last_error = e
                continue
            try:
                return await b.chat(
                    messages=messages,
                    tools=tools,
                    model=model,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except LLMBackendUnavailable as e:
                logger.info("backend %s unavailable mid-request: %s", b.name, e)
                last_error = e
                continue

        if last_error is not None:
            raise LLMBackendUnavailable(
                f"all LLM backends unavailable; last error: {last_error}"
            )
        raise LLMBackendUnavailable("no LLM backend was available")


def default_registry() -> LLMRegistry:
    """Build a sensible default registry.

    For v1 that means: only Ollama.  Cloud backends land alongside the
    online popover in Sprint 2 and get inserted at index 0 by the
    daemon config loader.
    """
    from praxis.llm.ollama import OllamaBackend

    return LLMRegistry(backends=[OllamaBackend()])


__all__ = [
    "LLMRegistry",
    "default_registry",
]
