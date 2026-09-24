"""
Shared tier x principal decision matrix.

Both :mod:`praxis.policy.engine` (browser side) and
:mod:`praxis.filesystem.policy` (filesystem side) need the same
matrix.  Keeping it in one place avoids drift.

Callers pass in the concrete inputs (``Principal``, ``RiskTier`` and a
few metadata bits) and get back a :class:`PolicyDecision` when the
gate has an opinion, or ``None`` when the per-domain rule layer
should take over.

The matrix itself is documented in ``docs/DESIGN.md`` §4:

+----+-----------------+----------------+---------+
|    | praxis:local    | agent:*        | unknown |
+====+=================+================+=========+
| T0 | ALLOW           | ALLOW          | BLOCK   |
| T1 | ALLOW           | REQUIRE_APPROV | BLOCK   |
| T2 | REQUIRE_APPROV  | BLOCK*         | BLOCK   |
| T3 | BLOCK           | BLOCK          | BLOCK   |
+----+-----------------+----------------+---------+
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from praxis.principal import Principal, PrincipalKind
from praxis.tiers import RiskTier

if TYPE_CHECKING:
    from praxis.config import PraxisConfig
    from praxis.policy.engine import PolicyDecision


# The gate emits three "rule" identifiers so evidence readers can tell
# what happened at a glance.
RULE_UNKNOWN_PRINCIPAL = "tier_gate.unknown_principal"
RULE_T3_BLOCKED = "tier_gate.t3_blocked"
RULE_LOCAL_T2 = "tier_gate.local_t2"
RULE_AGENT_T1 = "tier_gate.agent_t1"
RULE_AGENT_T2 = "tier_gate.agent_t2"

# Tier -> the config "action" name it maps to.
_TIER_ACTION = {
    RiskTier.T0: "read",
    RiskTier.T1: "write",
    RiskTier.T2: "delete",
}


def apply_tier_gate(
    principal: Principal,
    tier: RiskTier,
    fingerprint: str = "",
    config: "PraxisConfig | None" = None,
) -> "PolicyDecision | None":
    """Return the tier gate's decision, or ``None`` if silent.

    ``None`` means the per-domain rule layer runs unimpeded.  A
    non-None decision is folded into ``most-restrictive-wins`` for
    non-BLOCK verdicts, and short-circuits the whole evaluation for
    BLOCK.

    The (principal-class, tier) -> outcome matrix comes from the user's
    :class:`~praxis.config.PraxisConfig` (``praxis init``).  With the
    default *balanced* config this reproduces the historical hard-coded
    matrix exactly.  Two rules are never configurable: an ``unknown``
    caller and T3 are always blocked.
    """
    # Import here to avoid a circular import: engine imports us for the
    # optional principal/tier fields, and we import ``PolicyDecision``
    # from engine.
    from praxis.config import get_config
    from praxis.policy.engine import Decision, PolicyDecision, RiskLevel

    # Unauthenticated caller → always blocked (not configurable).
    if principal.kind == PrincipalKind.UNKNOWN:
        return PolicyDecision(
            decision=Decision.BLOCK,
            risk_level=RiskLevel.HIGH,
            matched_rule=RULE_UNKNOWN_PRINCIPAL,
            reason=(
                "Unauthenticated caller cannot perform any action. "
                f"proven_via={principal.proven_via!r}"
            ),
            policy_name="__tier_gate__",
            action_fingerprint=fingerprint,
            tier=tier,
            principal=str(principal),
        )

    # T3 is refused at the chat surface regardless of principal (not
    # configurable — this is the irreversible/root safety floor).
    if tier == RiskTier.T3:
        return PolicyDecision(
            decision=Decision.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            matched_rule=RULE_T3_BLOCKED,
            reason=(
                "T3 (root/irreversible) operations are refused via "
                "the chat surface."
            ),
            policy_name="__tier_gate__",
            action_fingerprint=fingerprint,
            tier=tier,
            principal=str(principal),
        )

    # Configurable band: (local | agent) x (T0 | T1 | T2).
    if principal.kind == PrincipalKind.LOCAL:
        who = "local"
    elif principal.kind == PrincipalKind.AGENT:
        who = "agent"
    else:  # pragma: no cover — defensive
        return None

    cfg = config if config is not None else get_config()
    action = _TIER_ACTION.get(tier, "delete")
    outcome = cfg.outcome(who, action)

    if outcome == "allow":
        # Gate stays silent; the per-domain rule layer decides.
        return None

    rule = f"tier_gate.{who}_{tier.name.lower()}"
    risk = (
        RiskLevel.HIGH
        if tier == RiskTier.T2
        else RiskLevel.MEDIUM
        if tier == RiskTier.T1
        else RiskLevel.LOW
    )

    if outcome == "block":
        reason = (
            f"{action.capitalize()} from {principal} is blocked by your "
            f"Praxis policy (strictness={cfg.strictness})."
        )
        decision = Decision.BLOCK
    else:  # "ask"
        reason = (
            f"{action.capitalize()} from {principal} requires your approval "
            f"(strictness={cfg.strictness})."
        )
        decision = Decision.REQUIRE_APPROVAL

    return PolicyDecision(
        decision=decision,
        risk_level=risk,
        matched_rule=rule,
        reason=reason,
        policy_name="__tier_gate__",
        action_fingerprint=fingerprint,
        tier=tier,
        principal=str(principal),
    )


__all__ = [
    "RULE_AGENT_T1",
    "RULE_AGENT_T2",
    "RULE_LOCAL_T2",
    "RULE_T3_BLOCKED",
    "RULE_UNKNOWN_PRINCIPAL",
    "apply_tier_gate",
]
