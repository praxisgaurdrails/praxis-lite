"""
Praxis filesystem policy engine.

Wraps :func:`praxis.policy.tier_gate.apply_tier_gate` with an
additional path-safety pass so filesystem tools can't be tricked into
touching credential stores, system dirs, or the home root itself.

Decision order:

1. **Tier gate** — refuses UNKNOWN principals and T3 ops.
2. **Path safety** — refuses reads on SECRETS, refuses writes on
   SYSTEM / SECRETS / PSEUDO, refuses deletes on those + the home
   root.
3. **Per-policy YAML rules** — v1 does not ship any FS-specific YAML
   rules; the engine is structured so they slot in later without
   touching this file's public surface.

If none of the layers has an opinion, the op is allowed.
"""

from __future__ import annotations

from pathlib import Path

from praxis.filesystem.paths import (
    PathClass,
    classify_path,
    refuses_delete,
    refuses_read,
    refuses_write,
)
from praxis.filesystem.types import FSAction, FSActionEvent
from praxis.policy.engine import Decision, PolicyDecision, RiskLevel
from praxis.policy.tier_gate import apply_tier_gate
from praxis.tiers import RiskTier

RULE_PATH_UNSAFE_READ = "fs_path.refused_read"
RULE_PATH_UNSAFE_WRITE = "fs_path.refused_write"
RULE_PATH_UNSAFE_DELETE = "fs_path.refused_delete"


READ_ACTIONS = frozenset({
    FSAction.SEARCH,
    FSAction.READ,
    FSAction.STAT,
    FSAction.LIST_DIR,
})
WRITE_ACTIONS = frozenset({
    FSAction.CREATE_DIR,
    FSAction.CREATE_FILE,
    FSAction.WRITE,
    FSAction.OVERWRITE,
})
DELETE_ACTIONS = frozenset({
    FSAction.DELETE,
    FSAction.MOVE,
    FSAction.RENAME,
})


class FSPolicyEngine:
    """Evaluate an :class:`FSActionEvent` and return a decision.

    The engine is stateless — no loaded YAML in v1 — so callers may
    reuse a single instance across requests.
    """

    def evaluate(self, event: FSActionEvent) -> PolicyDecision:
        """Return the policy decision for one FS event."""

        # ------------------------------------------------------------
        # Layer 1 — tier gate
        # ------------------------------------------------------------
        gate = apply_tier_gate(
            principal=event.principal,
            tier=event.resolved_tier,
            fingerprint=event.fingerprint,
        )
        if gate is not None and gate.decision == Decision.BLOCK:
            return gate

        # ------------------------------------------------------------
        # Layer 2 — path safety on every targeted path
        # ------------------------------------------------------------
        path_check = self._check_paths(event)
        if path_check is not None:
            return path_check

        # ------------------------------------------------------------
        # If the tier gate returned a non-BLOCK opinion, honour it.
        # ------------------------------------------------------------
        if gate is not None:
            return gate

        return PolicyDecision(
            decision=Decision.ALLOW,
            risk_level=self._risk_for_tier(event.resolved_tier),
            reason="fs op allowed by policy",
            policy_name="__fs_default__",
            action_fingerprint=event.fingerprint,
            tier=event.resolved_tier,
            principal=str(event.principal),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check_paths(self, event: FSActionEvent) -> PolicyDecision | None:
        """Refuse if any targeted path lands on the T3 path denylist."""
        candidates: list[str] = []
        candidates.extend(event.paths)
        if event.target_dir:
            candidates.append(event.target_dir)

        for raw in candidates:
            if not raw:
                continue
            verdict = classify_path(raw)
            refused = self._refuses(event.action, verdict)
            if refused is not None:
                rule, reason = refused
                return PolicyDecision(
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                    matched_rule=rule,
                    reason=(
                        f"refused for path {raw!r}: {reason} "
                        f"(class={verdict.path_class.value})"
                    ),
                    policy_name="__fs_path_safety__",
                    action_fingerprint=event.fingerprint,
                    tier=event.resolved_tier,
                    principal=str(event.principal),
                )
        return None

    def _refuses(
        self,
        action: FSAction,
        verdict,
    ) -> tuple[str, str] | None:
        """Return ``(rule, reason)`` iff the action is refused for this
        path class, else ``None``."""
        if action in READ_ACTIONS:
            if refuses_read(verdict):
                return RULE_PATH_UNSAFE_READ, verdict.reason
        if action in WRITE_ACTIONS:
            if refuses_write(verdict):
                return RULE_PATH_UNSAFE_WRITE, verdict.reason
        if action in DELETE_ACTIONS:
            if refuses_delete(verdict):
                return RULE_PATH_UNSAFE_DELETE, verdict.reason
        return None

    def _risk_for_tier(self, tier: RiskTier) -> RiskLevel:
        return {
            RiskTier.T0: RiskLevel.LOW,
            RiskTier.T1: RiskLevel.MEDIUM,
            RiskTier.T2: RiskLevel.HIGH,
            RiskTier.T3: RiskLevel.CRITICAL,
        }[tier]


__all__ = [
    "FSPolicyEngine",
    "RULE_PATH_UNSAFE_DELETE",
    "RULE_PATH_UNSAFE_READ",
    "RULE_PATH_UNSAFE_WRITE",
]
