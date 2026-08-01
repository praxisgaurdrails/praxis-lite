"""
Praxis approval coordinator — OS-notification-based 2FA for T2 ops.

When the tier gate (or a per-policy rule) returns REQUIRE_APPROVAL, the
executor pauses the action, calls :meth:`ApprovalCoordinator.request`,
and waits for the user's answer.  The coordinator dispatches an OS
notification (native banner on macOS / Windows / Linux), waits for a
click, then triggers OS-native authentication (TouchID / Windows Hello
/ PolKit) and returns an :class:`ApprovalOutcome`.

The coordinator is transport-agnostic — the *how* is factored into two
small interfaces the caller can substitute:

* :class:`Notifier` — puts the ask in front of the user and returns
  their answer.
* :class:`Authenticator` — runs the OS 2FA step.

Defaults live in :mod:`praxis.approval.notifiers` and pick a real
implementation per OS.  Tests inject :class:`AutoApproveNotifier` /
:class:`AutoDenyNotifier` to avoid popping real notifications.

See ``docs/DESIGN.md`` §4.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Protocol

from praxis.principal import Principal
from praxis.tiers import RiskTier


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ApprovalStatus(str, Enum):
    """Terminal states of an approval request."""

    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    AUTH_FAILED = "auth_failed"


class ApprovalTimeout(RuntimeError):
    """Raised when the user did not answer within the timeout."""


@dataclass
class ApprovalRequest:
    """A single pending request for the user."""

    request_id: str
    tool_name: str
    tier: RiskTier
    principal: Principal
    summary: str
    """Human-readable one-liner: 'delete 47 files under ~/Downloads'."""
    details: dict[str, Any] = field(default_factory=dict)
    """Structured payload for the notification body (target paths etc)."""
    blast_radius: str = ""
    """Free-text blast-radius description for the UI ('~200 MB, 47 files')."""
    timeout_seconds: float = 30.0
    """After this many seconds without user input, we default to DENY."""
    cool_off_seconds: float = 10.0
    """After user Approve, we wait this many seconds before executing.
       Any key/cancel during this window aborts."""
    created_at: float = field(default_factory=time.time)


@dataclass
class ApprovalOutcome:
    """The user's decision + how it was reached."""

    status: ApprovalStatus
    reason: str = ""
    authenticator: str = ""
    """String naming the auth backend used (e.g. 'touchid', 'noop')."""
    decided_at: float = field(default_factory=time.time)
    """Wall-clock at the moment the coordinator returned."""


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


class Notifier(Protocol):
    """Puts the approval ask in front of the user.

    An implementation returns :class:`ApprovalStatus.APPROVED` or
    :class:`ApprovalStatus.DENIED`.  Never :class:`APPROVED` unless the
    user actually clicked Approve — timeouts must return
    :class:`ApprovalStatus.TIMED_OUT` (or raise :class:`ApprovalTimeout`).
    """

    async def prompt(self, request: ApprovalRequest) -> ApprovalStatus:  # pragma: no cover
        ...


class Authenticator(Protocol):
    """Runs the OS-native second factor after the user clicked Approve.

    Returns True on successful auth, False otherwise.  Never raises for
    normal auth failures — only for backend malfunctions.
    """

    async def authenticate(self, request: ApprovalRequest) -> bool:  # pragma: no cover
        ...

    @property
    def name(self) -> str:  # pragma: no cover
        ...


# ---------------------------------------------------------------------------
# Test / dev implementations
# ---------------------------------------------------------------------------


class AutoApproveNotifier:
    """Notifier that immediately answers APPROVED.  Test-only."""

    async def prompt(self, request: ApprovalRequest) -> ApprovalStatus:
        return ApprovalStatus.APPROVED


class AutoDenyNotifier:
    """Notifier that immediately answers DENIED.  Test-only."""

    async def prompt(self, request: ApprovalRequest) -> ApprovalStatus:
        return ApprovalStatus.DENIED


class NullAuthenticator:
    """Authenticator that always succeeds.  For headless test runs and
    for environments where no OS 2FA is available (Linux without
    PolKit).  Real deployments should replace with a per-OS backend.
    """

    name = "noop"

    async def authenticate(self, request: ApprovalRequest) -> bool:
        return True


def default_notifier() -> Notifier:
    """Return a real-OS notifier if we can build one, else a null one.

    Phase 1 ships with only the null notifier — the OS-native banners
    come in a follow-up commit alongside the tray icon.  We keep the
    factory here so callers use one entry point.
    """
    return _NullNotifier()


def default_authenticator() -> Authenticator:
    """Return the best available authenticator for this OS.

    Phase 1 ships :class:`NullAuthenticator` on all platforms.  Real
    backends land alongside Phase 6 (tray icon + hotkey).  The
    behaviour is kept explicit so a downstream caller can inject a
    real authenticator when running under a UI process.
    """
    return NullAuthenticator()


class _NullNotifier:
    """Denies by default.  Present so a headless daemon never blocks
    forever waiting for a UI that isn't running."""

    async def prompt(self, request: ApprovalRequest) -> ApprovalStatus:
        return ApprovalStatus.DENIED


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------


CoolOffCallback = Callable[[ApprovalRequest], Awaitable[bool]]
"""Optional callback the coordinator invokes during the cool-off window.

Return True to continue the cool-off (nothing detected), False to
abort — for example when the user presses the kill switch.  If None
is passed we just sleep out the cool-off.
"""


class ApprovalCoordinator:
    """Orchestrates the T2 approval flow.

    Usage::

        coord = ApprovalCoordinator()
        outcome = await coord.request(
            ApprovalRequest(
                request_id="req_1234",
                tool_name="fs.delete",
                tier=RiskTier.T2,
                principal=Principal.local(),
                summary="Delete 47 files under ~/Downloads",
            )
        )
        if outcome.status == ApprovalStatus.APPROVED:
            ...  # proceed with the delete

    The coordinator is intentionally stateless across calls — pending
    requests are tracked only for the lifetime of a single
    :meth:`request`.  A separate registry (Phase 2) will manage
    inspectable / cancellable pending requests for the tray UI.
    """

    def __init__(
        self,
        notifier: Notifier | None = None,
        authenticator: Authenticator | None = None,
        cool_off_cb: CoolOffCallback | None = None,
    ) -> None:
        self._notifier: Notifier = notifier or default_notifier()
        self._authenticator: Authenticator = authenticator or default_authenticator()
        self._cool_off_cb = cool_off_cb
        self._active: dict[str, ApprovalRequest] = {}
        self._cancelled: set[str] = set()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def notifier(self) -> Notifier:
        return self._notifier

    @property
    def authenticator(self) -> Authenticator:
        return self._authenticator

    def pending(self) -> list[ApprovalRequest]:
        """Return currently pending requests (snapshot)."""
        return list(self._active.values())

    # ------------------------------------------------------------------
    # Cancellation (kill-switch integration)
    # ------------------------------------------------------------------

    def cancel_all(self, reason: str = "cancelled") -> int:
        """Mark every pending request as cancelled.

        Called from :class:`~praxis.kill_switch.KillSwitch` when
        the user hits the panic hotkey.  Returns the number of
        requests marked.  Does not itself resolve waiting coroutines
        — those observe the cancellation on their next check.
        """
        count = 0
        for req_id in list(self._active):
            self._cancelled.add(req_id)
            count += 1
        return count

    def cancel(self, request_id: str) -> bool:
        """Cancel a single pending request by id."""
        if request_id in self._active:
            self._cancelled.add(request_id)
            return True
        return False

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def request(self, req: ApprovalRequest) -> ApprovalOutcome:
        """Run the full ask-notify-auth-cool-off pipeline.

        Steps:

        1. Register the request as pending.
        2. Ask the :class:`Notifier` — user clicks Approve/Deny.
        3. If DENIED / TIMED_OUT / CANCELLED, return immediately.
        4. If APPROVED, run the :class:`Authenticator` (OS 2FA).
        5. If auth passes, wait out ``cool_off_seconds`` — cancellable
           via :meth:`cancel` or the kill switch.
        6. Return APPROVED, or DENIED with a clear reason.

        The coordinator never raises for user actions.  It raises only
        for programming errors (missing fields, coordinator torn down
        mid-flight).
        """
        if not req.request_id:
            req.request_id = f"req_{uuid.uuid4().hex[:12]}"

        self._active[req.request_id] = req
        try:
            # --- Step 1: notifier prompt with timeout ---
            try:
                notif_status = await asyncio.wait_for(
                    self._notifier.prompt(req),
                    timeout=req.timeout_seconds,
                )
            except asyncio.TimeoutError:
                return ApprovalOutcome(
                    status=ApprovalStatus.TIMED_OUT,
                    reason=(
                        f"user did not respond within "
                        f"{req.timeout_seconds:.0f}s — defaulting to deny"
                    ),
                )

            if self._is_cancelled(req):
                return ApprovalOutcome(
                    status=ApprovalStatus.CANCELLED,
                    reason="cancelled by kill switch or explicit cancel",
                )

            if notif_status == ApprovalStatus.DENIED:
                return ApprovalOutcome(
                    status=ApprovalStatus.DENIED,
                    reason="user denied at notification",
                )
            if notif_status == ApprovalStatus.TIMED_OUT:
                return ApprovalOutcome(
                    status=ApprovalStatus.TIMED_OUT,
                    reason="notifier reported timeout",
                )
            if notif_status != ApprovalStatus.APPROVED:
                return ApprovalOutcome(
                    status=ApprovalStatus.DENIED,
                    reason=f"unexpected notifier status: {notif_status.value}",
                )

            # --- Step 2: OS-native second factor ---
            try:
                auth_ok = await self._authenticator.authenticate(req)
            except Exception as exc:  # never let the authenticator crash us
                return ApprovalOutcome(
                    status=ApprovalStatus.AUTH_FAILED,
                    reason=f"authenticator crashed: {exc!r}",
                    authenticator=self._authenticator.name,
                )
            if not auth_ok:
                return ApprovalOutcome(
                    status=ApprovalStatus.AUTH_FAILED,
                    reason="OS authentication was declined or failed",
                    authenticator=self._authenticator.name,
                )

            # --- Step 3: cool-off window ---
            aborted_reason = await self._cool_off(req)
            if aborted_reason is not None:
                return ApprovalOutcome(
                    status=ApprovalStatus.CANCELLED,
                    reason=aborted_reason,
                    authenticator=self._authenticator.name,
                )

            return ApprovalOutcome(
                status=ApprovalStatus.APPROVED,
                reason="approved by user + OS auth + cool-off elapsed",
                authenticator=self._authenticator.name,
            )
        finally:
            self._active.pop(req.request_id, None)
            self._cancelled.discard(req.request_id)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _is_cancelled(self, req: ApprovalRequest) -> bool:
        return req.request_id in self._cancelled

    async def _cool_off(self, req: ApprovalRequest) -> str | None:
        """Sleep out the cool-off window, checking for cancellation.

        Returns None on success, or a string reason if the cool-off was
        aborted (kill switch, explicit cancel, callback said stop).
        """
        cool_off = max(0.0, req.cool_off_seconds)
        if cool_off == 0.0:
            return None

        interval = 0.1  # poll cadence
        elapsed = 0.0
        while elapsed < cool_off:
            if self._is_cancelled(req):
                return "cool-off aborted (cancelled)"
            if self._cool_off_cb is not None:
                try:
                    cont = await self._cool_off_cb(req)
                except Exception:
                    cont = True  # never crash on user-supplied cb
                if not cont:
                    return "cool-off aborted (callback)"
            await asyncio.sleep(interval)
            elapsed += interval
        # Final cancellation check after sleeping.
        if self._is_cancelled(req):
            return "cool-off aborted (cancelled at end)"
        return None


__all__ = [
    "ApprovalCoordinator",
    "ApprovalOutcome",
    "ApprovalRequest",
    "ApprovalStatus",
    "ApprovalTimeout",
    "AutoApproveNotifier",
    "AutoDenyNotifier",
    "Authenticator",
    "CoolOffCallback",
    "Notifier",
    "NullAuthenticator",
    "default_authenticator",
    "default_notifier",
]
