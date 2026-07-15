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
    from praxis.policy.engine import PolicyDecision


# The gate emits three "rule" identifiers so evidence readers can tell
# what happened at a glance.
RULE_UNKNOWN_PRINCIPAL = "tier_gate.unknown_principal"
RULE_T3_BLOCKED = "tier_gate.t3_blocked"
RULE_LOCAL_T2 = "tier_gate.local_t2"
RULE_AGENT_T1 = "tier_gate.agent_t1"
RULE_AGENT_T2 = "tier_gate.agent_t2"


def apply_tier_gate(
    principal: Principal,
    tier: RiskTier,
    fingerprint: str = "",
) -> "PolicyDecision | None":
    """Return the tier gate's decision, or ``None`` if silent.

    ``None`` means the per-domain rule layer runs unimpeded.  A
    non-None decision is folded into ``most-restrictive-wins`` for
    non-BLOCK verdicts, and short-circuits the whole evaluation for
    BLOCK.
    """
    # Import here to avoid a circular import: engine imports us for the
    # optional principal/tier fields, and we import ``PolicyDecision``
    # from engine.
    from praxis.policy.engine import Decision, PolicyDecision, RiskLevel

    # Unauthenticated caller → always blocked.
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

    # T3 is refused at the chat surface regardless of principal.
    if tier == RiskTier.T3:
        return PolicyDecision(
            decision=Decision.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            matched_rule=RULE_T3_BLOCKED,
            reason=(
                "T3 (root/irreversible) operations are refused via "
                "the chat surface.  Enable via ~/.praxis/config.yaml "
                "t3_unlocks: and restart the daemon."
            ),
            policy_name="__tier_gate__",
            action_fingerprint=fingerprint,
            tier=tier,
            principal=str(principal),
        )

    if principal.kind == PrincipalKind.LOCAL:
        if tier in (RiskTier.T0, RiskTier.T1):
            return None
        if tier == RiskTier.T2:
            return PolicyDecision(
                decision=Decision.REQUIRE_APPROVAL,
                risk_level=RiskLevel.HIGH,
                matched_rule=RULE_LOCAL_T2,
                reason=(
                    "Destructive operation from praxis:local — "
                    "OS-native 2FA required"
                ),
                policy_name="__tier_gate__",
                action_fingerprint=fingerprint,
                tier=tier,
                principal=str(principal),
            )

    if principal.kind == PrincipalKind.AGENT:
        if tier == RiskTier.T0:
            return None
        if tier == RiskTier.T1:
            return PolicyDecision(
                decision=Decision.REQUIRE_APPROVAL,
                risk_level=RiskLevel.MEDIUM,
                matched_rule=RULE_AGENT_T1,
                reason=(
                    f"Benign write from {principal} requires user "
                    f"approval"
                ),
                policy_name="__tier_gate__",
                action_fingerprint=fingerprint,
                tier=tier,
                principal=str(principal),
            )
        if tier == RiskTier.T2:
            return PolicyDecision(
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                matched_rule=RULE_AGENT_T2,
                reason=(
                    f"Destructive operation from {principal} is "
                    f"blocked by default.  A trusted-agent policy "
                    f"may re-enable with approval."
                ),
                policy_name="__tier_gate__",
                action_fingerprint=fingerprint,
                tier=tier,
                principal=str(principal),
            )

    return None


__all__ = [
    "RULE_AGENT_T1",
    "RULE_AGENT_T2",
    "RULE_LOCAL_T2",
    "RULE_T3_BLOCKED",
    "RULE_UNKNOWN_PRINCIPAL",
    "apply_tier_gate",
]
