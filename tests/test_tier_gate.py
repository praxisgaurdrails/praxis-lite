"""Integration tests for the tier x principal decision matrix."""

import pytest

from praxis.policy.engine import (
    ActionEvent,
    ActionType,
    Decision,
    Policy,
    PolicyEngine,
    RiskLevel,
    create_permissive_policy,
)
from praxis.principal import Principal
from praxis.tiers import RiskTier


def _event(action_type: ActionType, principal=None, tier=None, **kw):
    """Convenience builder."""
    return ActionEvent(
        action_type=action_type,
        principal=principal,
        tier=tier,
        agent_id="test",
        session_id="ses_test",
        **kw,
    )


@pytest.fixture
def engine():
    e = PolicyEngine()
    e.load_policy(create_permissive_policy())
    return e


# ---------------------------------------------------------------------------
# Opt-in: without a principal, gate is inert (legacy behaviour preserved)
# ---------------------------------------------------------------------------


class TestTierGateIsOptIn:
    def test_no_principal_no_gate(self, engine):
        # Legacy caller: no principal, no tier.  Should behave exactly
        # as before Phase 1 — permissive policy allows a click.
        event = _event(ActionType.CLICK)
        assert event.principal is None
        d = engine.evaluate(event)
        assert d.decision == Decision.ALLOW
        # The stamp helper still fills tier for auditability.
        assert d.tier == RiskTier.T1
        # No principal on event → no principal on decision.
        assert d.principal == ""


# ---------------------------------------------------------------------------
# Unknown principal: everything blocked
# ---------------------------------------------------------------------------


class TestUnknownPrincipal:
    def test_unknown_blocked_on_t0(self, engine):
        d = engine.evaluate(
            _event(ActionType.NAVIGATE, principal=Principal.unknown())
        )
        assert d.decision == Decision.BLOCK
        assert "tier_gate.unknown_principal" in d.matched_rule

    def test_unknown_blocked_on_t1(self, engine):
        d = engine.evaluate(
            _event(ActionType.CLICK, principal=Principal.unknown())
        )
        assert d.decision == Decision.BLOCK

    def test_unknown_blocked_on_t3(self, engine):
        d = engine.evaluate(
            _event(ActionType.EVALUATE_JS, principal=Principal.unknown())
        )
        assert d.decision == Decision.BLOCK


# ---------------------------------------------------------------------------
# praxis:local — the trusted user
# ---------------------------------------------------------------------------


class TestLocalPrincipal:
    def test_local_t0_allow(self, engine):
        d = engine.evaluate(
            _event(ActionType.NAVIGATE, principal=Principal.local())
        )
        assert d.decision == Decision.ALLOW
        assert d.tier == RiskTier.T0
        assert d.principal == "praxis:local"

    def test_local_t1_allow(self, engine):
        d = engine.evaluate(
            _event(ActionType.CLICK, principal=Principal.local())
        )
        assert d.decision == Decision.ALLOW

    def test_local_t2_requires_approval(self, engine):
        d = engine.evaluate(
            _event(ActionType.DOWNLOAD, principal=Principal.local())
        )
        assert d.decision == Decision.REQUIRE_APPROVAL
        assert "tier_gate.local_t2" in d.matched_rule
        assert d.principal == "praxis:local"

    def test_local_t3_blocked(self, engine):
        d = engine.evaluate(
            _event(ActionType.EVALUATE_JS, principal=Principal.local())
        )
        assert d.decision == Decision.BLOCK
        assert "t3_blocked" in d.matched_rule


# ---------------------------------------------------------------------------
# agent:<name> — external caller
# ---------------------------------------------------------------------------


class TestAgentPrincipal:
    def test_agent_t0_allow(self, engine):
        d = engine.evaluate(
            _event(
                ActionType.NAVIGATE,
                principal=Principal.agent("claude-desktop"),
            )
        )
        assert d.decision == Decision.ALLOW
        assert d.principal == "agent:claude-desktop"

    def test_agent_t1_requires_approval(self, engine):
        d = engine.evaluate(
            _event(
                ActionType.CLICK,
                principal=Principal.agent("claude-desktop"),
            )
        )
        assert d.decision == Decision.REQUIRE_APPROVAL
        assert "tier_gate.agent_t1" in d.matched_rule

    def test_agent_t2_blocked_by_default(self, engine):
        d = engine.evaluate(
            _event(
                ActionType.DOWNLOAD,
                principal=Principal.agent("claude-desktop"),
            )
        )
        assert d.decision == Decision.BLOCK
        assert "tier_gate.agent_t2" in d.matched_rule

    def test_agent_t3_blocked(self, engine):
        d = engine.evaluate(
            _event(
                ActionType.EVALUATE_JS,
                principal=Principal.agent("claude-desktop"),
            )
        )
        assert d.decision == Decision.BLOCK


# ---------------------------------------------------------------------------
# Symmetry between local + agent for same action → different outcomes
# ---------------------------------------------------------------------------


class TestPrincipalSplitBehaviour:
    def test_same_click_different_principals_different_outcomes(self, engine):
        local = engine.evaluate(
            _event(ActionType.CLICK, principal=Principal.local())
        )
        agent = engine.evaluate(
            _event(
                ActionType.CLICK,
                principal=Principal.agent("openclaw"),
            )
        )
        assert local.decision == Decision.ALLOW
        assert agent.decision == Decision.REQUIRE_APPROVAL
        assert local.tier == agent.tier == RiskTier.T1

    def test_t3_is_blocked_regardless_of_principal(self, engine):
        for p in (Principal.local(), Principal.agent("openclaw")):
            d = engine.evaluate(
                _event(ActionType.EVALUATE_JS, principal=p)
            )
            assert d.decision == Decision.BLOCK


# ---------------------------------------------------------------------------
# Explicit tier override on the event
# ---------------------------------------------------------------------------


class TestExplicitTierOverride:
    def test_explicit_tier_wins_over_action_default(self, engine):
        # A future FS tool might report itself with an explicit tier
        # instead of relying on the browser action_type table.  Verify
        # that path.
        event = _event(
            ActionType.CLICK,
            principal=Principal.agent("claude-desktop"),
            tier=RiskTier.T2,
        )
        d = engine.evaluate(event)
        assert d.decision == Decision.BLOCK
        assert d.tier == RiskTier.T2
