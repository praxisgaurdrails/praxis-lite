"""Tests for the Praxis risk-tier abstraction."""

import pytest

from praxis.tiers import RiskTier, default_tier_for_browser_action


class TestRiskTier:
    def test_ordering(self):
        assert RiskTier.T0 < RiskTier.T1 < RiskTier.T2 < RiskTier.T3
        assert RiskTier.T3 > RiskTier.T0
        assert RiskTier.T1 >= RiskTier.T1
        assert RiskTier.T2 <= RiskTier.T2

    def test_numeric_rank(self):
        assert RiskTier.T0.numeric == 0
        assert RiskTier.T3.numeric == 3

    def test_labels_are_human_readable(self):
        assert RiskTier.T0.label == "read"
        assert RiskTier.T3.label == "root/irreversible"

    def test_string_values_are_stable(self):
        # These values leak into JSON on disk — must not silently change.
        assert RiskTier.T0.value == "t0"
        assert RiskTier.T2.value == "t2"

    def test_comparison_within_tiers_only(self):
        # RiskTier inherits from str, so ``< "banana"`` becomes a str
        # compare and works.  What we care about is that
        # tier-to-tier compares use the numeric rank, not the string
        # value (e.g. "t2" < "t3" happens to work lexicographically,
        # but we want "t1" < "t10" to keep working if we ever add
        # tiers, which requires the numeric override).
        assert RiskTier.T0 < RiskTier.T3
        # And explicit numeric rank access does not confuse compare.
        assert RiskTier.T2.numeric > RiskTier.T0.numeric


class TestBrowserActionTiering:
    @pytest.mark.parametrize(
        "action,expected",
        [
            ("navigate", RiskTier.T0),
            ("screenshot", RiskTier.T0),
            ("click", RiskTier.T1),
            ("type", RiskTier.T1),
            ("submit", RiskTier.T2),
            ("download", RiskTier.T2),
            ("upload", RiskTier.T2),
            ("copy", RiskTier.T2),
            ("evaluate_js", RiskTier.T3),
        ],
    )
    def test_known_actions(self, action, expected):
        assert default_tier_for_browser_action(action) == expected

    def test_unknown_action_is_treated_as_destructive(self):
        # Unknown ops must default up, not down.
        assert default_tier_for_browser_action("teleport") == RiskTier.T2
        assert default_tier_for_browser_action("") == RiskTier.T2
