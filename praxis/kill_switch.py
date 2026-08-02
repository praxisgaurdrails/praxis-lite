"""
Praxis kill switch — the panic hotkey.

A single global object the daemon exposes to every subsystem.  When
triggered (programmatically today, hotkey in Phase 6) it:

    1. Revokes every capability token in the token store.
    2. Cancels every pending approval request.
    3. Fires user-registered "on_kill" callbacks so subsystems can
       tear down cleanly (executor aborts in-flight ops, MCP proxy
       drops downstream connections, etc.).
    4. Records an evidence marker so the panic is auditable.

The kill switch is deliberately *idempotent* — arming and firing it
twice does nothing extra.  It stays fired until :meth:`reset` is
called (which itself is audited).

See ``docs/DESIGN.md`` §5.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("praxis.kill_switch")


KillHook = Callable[[], None]
"""Signature for functions registered via :meth:`KillSwitch.register`."""


@dataclass
class KillEvent:
    """A single fire of the kill switch, retained for the audit log."""

    reason: str
    fired_at: float = field(default_factory=time.time)
    fired_by: str = "system"
    tokens_revoked: int = 0
    approvals_cancelled: int = 0
    hooks_run: int = 0
    hooks_failed: int = 0


class KillSwitch:
    """Global panic control.

    Thread-safe.  Meant to be constructed once at daemon startup and
    injected everywhere.  Do not construct a fresh one per request.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fired = False
        self._history: list[KillEvent] = []
        self._hooks: list[KillHook] = []
        # Injected at wire-up so we don't take a hard dep on either.
        self._token_store_revoke: Callable[[], int] | None = None
        self._approval_cancel_all: Callable[[], int] | None = None

    # ------------------------------------------------------------------
    # Wiring — called once by the daemon at startup
    # ------------------------------------------------------------------

    def bind_token_store(self, revoke_all: Callable[[], int]) -> None:
        """Provide a callable that revokes every token and returns count."""
        self._token_store_revoke = revoke_all

    def bind_approval_coordinator(
        self, cancel_all: Callable[[], int]
    ) -> None:
        """Provide a callable that cancels every pending approval."""
        self._approval_cancel_all = cancel_all

    def register(self, hook: KillHook) -> None:
        """Register a callback to run when the switch fires.

        Hooks run in registration order.  Exceptions inside a hook are
        logged and swallowed — one bad subsystem never blocks the kill.
        """
        with self._lock:
            self._hooks.append(hook)

    def unregister(self, hook: KillHook) -> None:
        """Remove a previously-registered hook (best-effort)."""
        with self._lock:
            try:
                self._hooks.remove(hook)
            except ValueError:
                pass

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def is_fired(self) -> bool:
        return self._fired

    @property
    def history(self) -> list[KillEvent]:
        with self._lock:
            return list(self._history)

    @property
    def last_event(self) -> KillEvent | None:
        with self._lock:
            return self._history[-1] if self._history else None

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def fire(self, reason: str = "manual", fired_by: str = "user") -> KillEvent:
        """Trip the switch.  Idempotent: a second fire is a no-op."""
        with self._lock:
            if self._fired:
                logger.info("kill switch already fired; ignoring")
                return self._history[-1]
            self._fired = True

            tokens_revoked = 0
            if self._token_store_revoke is not None:
                try:
                    tokens_revoked = int(self._token_store_revoke() or 0)
                except Exception:
                    logger.exception("token revoke failed during kill")

            approvals_cancelled = 0
            if self._approval_cancel_all is not None:
                try:
                    approvals_cancelled = int(
                        self._approval_cancel_all() or 0
                    )
                except Exception:
                    logger.exception(
                        "approval cancel_all failed during kill"
                    )

            hooks_run = 0
            hooks_failed = 0
            for hook in list(self._hooks):
                try:
                    hook()
                    hooks_run += 1
                except Exception:
                    hooks_failed += 1
                    logger.exception("kill-switch hook raised: %r", hook)

            event = KillEvent(
                reason=reason,
                fired_by=fired_by,
                tokens_revoked=tokens_revoked,
                approvals_cancelled=approvals_cancelled,
                hooks_run=hooks_run,
                hooks_failed=hooks_failed,
            )
            self._history.append(event)
            logger.warning(
                "KILL SWITCH FIRED: reason=%r tokens=%d approvals=%d "
                "hooks_ok=%d hooks_failed=%d",
                reason,
                tokens_revoked,
                approvals_cancelled,
                hooks_run,
                hooks_failed,
            )
            return event

    def reset(self, reason: str = "user_reset") -> None:
        """Re-arm the switch after a fire.

        Recorded in history for the audit log.  Does NOT re-issue
        tokens or resurrect cancelled approvals — those are gone.
        """
        with self._lock:
            if not self._fired:
                return
            self._fired = False
            self._history.append(
                KillEvent(reason=f"reset:{reason}", fired_by="user")
            )
            logger.info("kill switch reset: %s", reason)


# ---------------------------------------------------------------------------
# Module-level singleton for the daemon
# ---------------------------------------------------------------------------

_singleton: KillSwitch | None = None


def get_kill_switch() -> KillSwitch:
    """Return the process-wide kill switch, constructing it lazily."""
    global _singleton
    if _singleton is None:
        _singleton = KillSwitch()
    return _singleton


def reset_kill_switch_for_tests() -> None:
    """Test-only: drop the singleton so each test starts fresh."""
    global _singleton
    _singleton = None


__all__ = [
    "KillEvent",
    "KillHook",
    "KillSwitch",
    "get_kill_switch",
    "reset_kill_switch_for_tests",
]
