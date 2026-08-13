"""
Runbook capture — snapshot successful T0-T2 chains into the cache.

The :class:`RunbookCaptureBuffer` observes tool calls from an agent
principal, groups them into a *chain* (consecutive successful ops), and
when the chain closes cleanly (agent moves on, or user hits a manual
"save this workflow" button) hands it to a :class:`RunbookCapture`
which builds a :class:`~praxis.runbook.cache.Runbook` and persists
it.

For v1 the trigger phrase comes from the caller (e.g. the user's
natural-language ask that started the whole thing).  Automatic trigger
extraction from tool arguments alone is v1.1+.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from praxis.filesystem.types import FSAction, FSActionEvent, FSResult, FSResultStatus
from praxis.principal import Principal
from praxis.runbook.cache import Runbook, RunbookCache, RunbookStep

logger = logging.getLogger("praxis.runbook.capture")


# ---------------------------------------------------------------------------
# Buffer — collects steps from a live session
# ---------------------------------------------------------------------------


@dataclass
class _PendingChain:
    """One in-progress chain from a specific principal."""

    principal: str
    steps: list[RunbookStep] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    last_step_at: float = field(default_factory=time.time)
    trigger_phrase: str = ""


class RunbookCaptureBuffer:
    """Groups tool calls per principal into chains.

    Not thread-safe.  Constructed once per daemon; the executor tells
    it about every event + outcome pair via :meth:`observe`.
    """

    def __init__(
        self,
        cache: RunbookCache,
        chain_gap_seconds: float = 60.0,
        min_steps: int = 1,
    ) -> None:
        self._cache = cache
        self._chain_gap = float(chain_gap_seconds)
        self._min_steps = max(1, int(min_steps))
        self._pending: dict[str, _PendingChain] = {}

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def set_trigger(self, principal: Principal, trigger_phrase: str) -> None:
        """Tag the next chain from ``principal`` with a natural-language
        trigger.  Called by the popover / orchestrator when it kicks off
        an agent turn."""
        key = str(principal)
        chain = self._pending.get(key)
        if chain is None:
            chain = _PendingChain(principal=key)
            self._pending[key] = chain
        chain.trigger_phrase = trigger_phrase

    def observe(
        self,
        event: FSActionEvent,
        result: FSResult,
    ) -> None:
        """Fold one (event, result) pair into the pending chain.

        Only successful non-search ops make it in.  Searches are
        typically the natural first step of many workflows but the
        specific search args (query string, path) shouldn't parametrise
        a runbook — the trigger phrase does that already.
        """
        principal_str = str(event.principal)
        chain = self._pending.get(principal_str)

        # Start fresh if the previous chain aged out.
        if chain and (time.time() - chain.last_step_at) > self._chain_gap:
            self._flush(chain)
            chain = None

        if chain is None:
            chain = _PendingChain(principal=principal_str)
            self._pending[principal_str] = chain

        # Only successful ops contribute steps.
        if result.status == FSResultStatus.SUCCESS:
            # Skip pure search — the trigger phrase captures intent.
            if event.action != FSAction.SEARCH:
                chain.steps.append(
                    RunbookStep(
                        tool_name=event.action.value,
                        arguments=_stripped_args(event),
                    )
                )
                chain.last_step_at = time.time()

    def flush_all(self) -> list[Runbook]:
        """Persist every pending chain that meets the min-step threshold.

        Called at daemon shutdown so we don't lose in-flight captures.
        """
        out: list[Runbook] = []
        for chain in list(self._pending.values()):
            rb = self._flush(chain)
            if rb is not None:
                out.append(rb)
        self._pending.clear()
        return out

    def close_chain(self, principal: Principal) -> Runbook | None:
        """Explicitly close and persist ``principal``'s current chain.

        Called by the orchestrator when it decides an agent's turn is
        finished.  Returns the persisted runbook or None if the chain
        was too short.
        """
        key = str(principal)
        chain = self._pending.pop(key, None)
        if chain is None:
            return None
        return self._flush(chain)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _flush(self, chain: _PendingChain) -> Runbook | None:
        if len(chain.steps) < self._min_steps:
            return None
        rb = Runbook(
            runbook_id="",
            trigger_phrase=chain.trigger_phrase or "unlabeled runbook",
            steps=chain.steps,
            principal_at_capture=chain.principal,
            captured_at=chain.started_at,
            last_verified=chain.last_step_at,
            verified_success=True,
        )
        self._cache.add(rb)
        logger.info(
            "captured runbook %s (%d steps, trigger=%r)",
            rb.runbook_id,
            len(rb.steps),
            rb.trigger_phrase,
        )
        return rb


# ---------------------------------------------------------------------------
# Public capture (thin wrapper — used by the daemon)
# ---------------------------------------------------------------------------


class RunbookCapture:
    """Public entry point the daemon calls."""

    def __init__(self, cache: RunbookCache | None = None) -> None:
        self._cache = cache or RunbookCache()
        self._buffer = RunbookCaptureBuffer(self._cache)

    @property
    def cache(self) -> RunbookCache:
        return self._cache

    @property
    def buffer(self) -> RunbookCaptureBuffer:
        return self._buffer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_ARG_FIELDS = (
    "paths",
    "target_dir",
    "new_name",
    "query",
    "ext",
    "glob",
    "if_exists",
    "max_bytes",
    "limit",
)


def _stripped_args(event: FSActionEvent) -> dict[str, Any]:
    """Drop bulky / sensitive fields (content bytes) from an event's args.

    Runbooks are stored in plain SQLite — leaving raw content in them
    would be a data-leak risk if a user shares their DB with support.
    """
    d: dict[str, Any] = {}
    for f in _ARG_FIELDS:
        v = getattr(event, f, None)
        if not v and not isinstance(v, int):
            continue
        d[f] = v
    if event.content is not None:
        d["content_size"] = len(event.content)
    return d


__all__ = [
    "RunbookCapture",
    "RunbookCaptureBuffer",
]
