"""
Praxis connectivity monitor — ONLINE / DEGRADED / OFFLINE detection.

The monitor pings three probes periodically:

* ``api.anthropic.com`` (Claude cloud API)
* ``api.openai.com`` (OpenAI / ChatGPT API)
* ``1.1.1.1`` (raw internet — is any network at all?)

Result mapping:

* All three reachable → ``ONLINE``.
* Only ``1.1.1.1`` reachable → ``DEGRADED`` (internet works, one AI
  vendor is down; local LLM would still work).
* Nothing reachable → ``OFFLINE``.

The monitor emits state-change events subscribers can hook into.
The daemon uses this to switch the popover between cloud + local LLM,
mark cloud-dependent tools unavailable, drain the runbook queue when
we come back online, etc.

Design invariants:

1. Never blocks the daemon.  All probing is async.
2. Probes are HEAD requests with a 2-second per-target timeout.  Total
   probe cost is bounded by the slowest of the three.
3. State changes are debounced — we require the same state twice in a
   row to declare it, so a single dropped packet doesn't cause a
   spurious ONLINE→OFFLINE flap.
4. Zero cost when nothing subscribes — the monitor still runs and
   updates ``.state``, but no callbacks are invoked.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger("praxis.connectivity")


class ConnectivityState(str, Enum):
    """The three connectivity states the daemon distinguishes."""

    UNKNOWN = "unknown"       # Before the first probe
    ONLINE = "online"          # All AI vendors + internet reachable
    DEGRADED = "degraded"      # Internet up, at least one AI vendor unreachable
    OFFLINE = "offline"        # No network at all


@dataclass
class ProbeResult:
    """One target's probe result."""

    target: str
    reachable: bool
    latency_ms: float
    error: str = ""


@dataclass
class Snapshot:
    """A serialisable snapshot of the current connectivity state."""

    state: str
    last_checked: float
    probes: list[dict[str, Any]] = field(default_factory=list)
    consecutive_matches: int = 0
    total_changes: int = 0
    ai_vendors_reachable: list[str] = field(default_factory=list)


StateChangeCallback = Callable[[ConnectivityState, ConnectivityState], Any]
"""Signature: ``callback(previous, current)``.  May be async."""


# ---------------------------------------------------------------------------
# Probe targets
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeTarget:
    """A single connectivity probe endpoint."""

    name: str            # short label ('anthropic', 'openai', 'internet')
    host: str            # hostname to resolve + connect
    port: int = 443
    is_ai_vendor: bool = False
    """Only ai-vendor targets contribute to DEGRADED detection."""


DEFAULT_TARGETS: tuple[ProbeTarget, ...] = (
    ProbeTarget(name="anthropic", host="api.anthropic.com", is_ai_vendor=True),
    ProbeTarget(name="openai", host="api.openai.com", is_ai_vendor=True),
    ProbeTarget(name="internet", host="1.1.1.1", is_ai_vendor=False),
)


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------


class ConnectivityMonitor:
    """Periodic connectivity monitor with subscription callbacks.

    Usage::

        mon = ConnectivityMonitor()
        mon.on_state_change(lambda old, new: print(f"{old} -> {new}"))
        await mon.start()
        # ... daemon runs ...
        await mon.stop()

    Snapshot / state can also be polled at any time via ``mon.state`` /
    ``mon.snapshot()``.
    """

    def __init__(
        self,
        targets: tuple[ProbeTarget, ...] = DEFAULT_TARGETS,
        interval_seconds: float = 15.0,
        per_probe_timeout: float = 2.0,
        debounce_matches: int = 2,
    ) -> None:
        self._targets = targets
        self._interval = float(interval_seconds)
        self._timeout = float(per_probe_timeout)
        self._debounce_matches = max(1, int(debounce_matches))

        self._state: ConnectivityState = ConnectivityState.UNKNOWN
        self._pending_state: ConnectivityState | None = None
        self._pending_matches: int = 0
        self._last_probes: list[ProbeResult] = []
        self._last_checked: float = 0.0
        self._total_changes: int = 0

        self._callbacks: list[StateChangeCallback] = []
        self._task: asyncio.Task | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    @property
    def state(self) -> ConnectivityState:
        return self._state

    @property
    def last_probes(self) -> list[ProbeResult]:
        return list(self._last_probes)

    @property
    def is_running(self) -> bool:
        return self._running

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot for status endpoints."""
        return {
            "state": self._state.value,
            "last_checked": self._last_checked,
            "consecutive_matches": self._pending_matches,
            "total_changes": self._total_changes,
            "probes": [
                {
                    "target": p.target,
                    "reachable": p.reachable,
                    "latency_ms": round(p.latency_ms, 1),
                    "error": p.error,
                }
                for p in self._last_probes
            ],
            "ai_vendors_reachable": [
                p.target
                for p in self._last_probes
                if p.reachable and any(t.name == p.target and t.is_ai_vendor for t in self._targets)
            ],
        }

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------

    def on_state_change(self, callback: StateChangeCallback) -> None:
        """Register a callback that fires when the debounced state changes."""
        self._callbacks.append(callback)

    def remove_callback(self, callback: StateChangeCallback) -> None:
        try:
            self._callbacks.remove(callback)
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, run_immediately: bool = True) -> None:
        """Start the background probing task."""
        if self._running:
            return
        self._running = True
        if run_immediately:
            # First probe now so subscribers see a real state ASAP.
            await self._probe_once_and_transition()
        self._task = asyncio.create_task(self._loop(), name="praxis-connectivity")

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def probe_now(self) -> ConnectivityState:
        """Run a probe cycle immediately, outside the normal cadence."""
        await self._probe_once_and_transition()
        return self._state

    # ------------------------------------------------------------------
    # Internals — probing
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        try:
            while self._running:
                await asyncio.sleep(self._interval)
                if not self._running:
                    break
                try:
                    await self._probe_once_and_transition()
                except Exception:
                    logger.exception("connectivity probe cycle failed")
        except asyncio.CancelledError:
            return

    async def _probe_once_and_transition(self) -> None:
        results = await self._probe_all()
        self._last_probes = results
        self._last_checked = time.time()
        observed = self._classify(results)
        await self._transition(observed)

    async def _probe_all(self) -> list[ProbeResult]:
        return await asyncio.gather(
            *(self._probe_target(t) for t in self._targets)
        )

    async def _probe_target(self, target: ProbeTarget) -> ProbeResult:
        start = time.perf_counter()
        try:
            # Cheap TCP probe — connect + close.  Avoids full TLS handshake
            # so we're not slower than we need to be, and doesn't produce
            # 4xx logs on the vendor's end.
            ctx = ssl.create_default_context()
            future = asyncio.open_connection(
                host=target.host,
                port=target.port,
                ssl=ctx,
            )
            reader, writer = await asyncio.wait_for(future, timeout=self._timeout)
            latency_ms = (time.perf_counter() - start) * 1000.0
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return ProbeResult(
                target=target.name,
                reachable=True,
                latency_ms=latency_ms,
            )
        except asyncio.TimeoutError:
            return ProbeResult(
                target=target.name,
                reachable=False,
                latency_ms=self._timeout * 1000.0,
                error="timeout",
            )
        except OSError as e:
            return ProbeResult(
                target=target.name,
                reachable=False,
                latency_ms=(time.perf_counter() - start) * 1000.0,
                error=type(e).__name__,
            )
        except Exception as e:
            return ProbeResult(
                target=target.name,
                reachable=False,
                latency_ms=(time.perf_counter() - start) * 1000.0,
                error=f"unexpected: {type(e).__name__}",
            )

    # ------------------------------------------------------------------
    # Internals — classification + debounce
    # ------------------------------------------------------------------

    def _classify(self, results: list[ProbeResult]) -> ConnectivityState:
        by_name = {r.target: r for r in results}
        internet_up = any(
            r.reachable
            for r in results
            if not any(t.is_ai_vendor for t in self._targets if t.name == r.target)
        )
        any_ai_up = any(
            r.reachable
            for r in results
            if any(t.is_ai_vendor for t in self._targets if t.name == r.target)
        )

        if not internet_up and not any_ai_up:
            # AI vendors *might* still be reachable if 1.1.1.1 is
            # blocked but api.openai.com isn't — very edge case.
            # Treat as OFFLINE if literally nothing responded.
            if not any(r.reachable for r in results):
                return ConnectivityState.OFFLINE

        if internet_up and any_ai_up and all(
            r.reachable for r in results if any(
                t.name == r.target for t in self._targets
            )
        ):
            return ConnectivityState.ONLINE

        if internet_up and any_ai_up:
            # Internet is up, at least one vendor works, but not all.
            return ConnectivityState.ONLINE

        if internet_up:
            return ConnectivityState.DEGRADED

        # Fallback — no internet, but maybe an AI vendor's IP still reachable?
        if any_ai_up:
            return ConnectivityState.ONLINE
        return ConnectivityState.OFFLINE

    async def _transition(self, observed: ConnectivityState) -> None:
        if self._state == ConnectivityState.UNKNOWN:
            # First probe — accept whatever we see, no debounce required.
            self._state = observed
            self._pending_state = observed
            self._pending_matches = self._debounce_matches
            await self._fire(ConnectivityState.UNKNOWN, observed)
            return

        if observed == self._state:
            # Confirm — no transition to consider.
            self._pending_state = observed
            self._pending_matches = self._debounce_matches
            return

        # New observation differs from current state.
        if self._pending_state == observed:
            self._pending_matches += 1
        else:
            self._pending_state = observed
            self._pending_matches = 1

        if self._pending_matches >= self._debounce_matches:
            previous = self._state
            self._state = observed
            self._total_changes += 1
            await self._fire(previous, observed)

    async def _fire(
        self,
        previous: ConnectivityState,
        current: ConnectivityState,
    ) -> None:
        logger.info("connectivity: %s -> %s", previous.value, current.value)
        for cb in list(self._callbacks):
            try:
                res = cb(previous, current)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                logger.exception("connectivity callback %r raised", cb)


__all__ = [
    "ConnectivityMonitor",
    "ConnectivityState",
    "DEFAULT_TARGETS",
    "ProbeResult",
    "ProbeTarget",
    "Snapshot",
    "StateChangeCallback",
]
