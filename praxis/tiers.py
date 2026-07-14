"""
Praxis risk tiers — T0 (read) through T3 (root/irreversible).

Every action Praxis exposes classifies into exactly one tier.  The tier
combined with the caller's principal decides what happens: allow,
require approval, or block outright.  See ``docs/DESIGN.md`` §4.

The tier is *action-intrinsic* — a delete is always T2, regardless of
who is asking.  What changes based on principal is the *decision*, not
the tier.
"""

from __future__ import annotations

from enum import Enum


class RiskTier(str, Enum):
    """Risk tier of an operation.

    ``T0`` — Read: search, read a file, list apps, capture the screen.
             Reversible; leaks nothing high-value on its own.

    ``T1`` — Benign write: create a file, launch an app, set clipboard.
             Reversible.  Doesn't destroy user data.

    ``T2`` — Destructive / privacy-sensitive: delete, move, close app,
             modify system state, send a network request to an
             arbitrary host.  User data or state can be lost or
             exposed.  Requires approval + staged trash for filesystem
             ops.

    ``T3`` — Root / irreversible: sudo, format, delete of home dir,
             disabling security features, keychain reads.  Refused
             at the executor layer.  Never gated by chat approval.
    """

    T0 = "t0"
    T1 = "t1"
    T2 = "t2"
    T3 = "t3"

    @property
    def numeric(self) -> int:
        """Numeric rank 0-3, useful for comparisons."""
        return {"t0": 0, "t1": 1, "t2": 2, "t3": 3}[self.value]

    @property
    def label(self) -> str:
        """Human-readable label."""
        return {
            "t0": "read",
            "t1": "benign-write",
            "t2": "destructive",
            "t3": "root/irreversible",
        }[self.value]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, RiskTier):
            return self.numeric >= other.numeric
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, RiskTier):
            return self.numeric > other.numeric
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, RiskTier):
            return self.numeric <= other.numeric
        return NotImplemented

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, RiskTier):
            return self.numeric < other.numeric
        return NotImplemented


# ---------------------------------------------------------------------------
# Default tier assignment for the browser ActionType surface
# ---------------------------------------------------------------------------
#
# The existing codebase only knows about browser actions (click / type /
# navigate / evaluate_js / etc.).  Filesystem / app / system tools are
# not yet added to ``ActionType`` — those land alongside Phase 2.
# Meanwhile we tier the browser actions so ``ActionEvent`` can carry a
# tier from day one and every downstream check has a well-defined value.

_BROWSER_ACTION_TIER: dict[str, RiskTier] = {
    # Read / observe — reversible, non-destructive.
    "navigate": RiskTier.T0,
    "screenshot": RiskTier.T0,
    "scroll": RiskTier.T0,
    "hover": RiskTier.T0,
    # Benign writes — user-visible but reversible / narrowly-scoped.
    "click": RiskTier.T1,
    "type": RiskTier.T1,
    "select": RiskTier.T1,
    "key_press": RiskTier.T1,
    "drag": RiskTier.T1,
    # Destructive / privacy-sensitive — leaves the browser sandbox.
    "submit": RiskTier.T2,
    "download": RiskTier.T2,
    "upload": RiskTier.T2,
    "copy": RiskTier.T2,
    # Root / arbitrary-code-execution — cannot be safely allowed
    # over a chat surface.
    "evaluate_js": RiskTier.T3,
}


def default_tier_for_browser_action(action_type_value: str) -> RiskTier:
    """Return the default tier for a browser action_type string.

    Falls back to T2 for unknown action types so that an unrecognised
    op is treated as destructive rather than silently permitted.
    """
    return _BROWSER_ACTION_TIER.get(action_type_value, RiskTier.T2)


__all__ = [
    "RiskTier",
    "default_tier_for_browser_action",
]
