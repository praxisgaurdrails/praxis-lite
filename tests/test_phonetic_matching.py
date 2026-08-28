"""Tests for phonetic matching in the policy engine.

Validates that typos, morphological variants, and misspellings are caught
by the phonetic matching layer while exact/substring matches still work
unchanged, and false positives are correctly rejected.
"""

import pytest

from praxis.policy.intent_matcher import (
    phonetic_code,
    phonetic_match_keywords,
    phonetic_match_intent,
    phonetic_detect_intents,
    match_intent,
    detect_intents,
    INTENT_SYNONYMS,
)
from praxis.policy.engine import (
    ActionEvent,
    ActionType,
    Decision,
    ElementRule,
    RiskLevel,
    classify_risk,
)


# ═══════════════════════════════════════════════════════════════════════════
# phonetic_code — unit tests for the encoding function
# ═══════════════════════════════════════════════════════════════════════════

class TestPhoneticCode:
    """Test the phonetic encoding function."""

    def test_basic_word(self):
        code = phonetic_code("checkout")
        assert isinstance(code, str)
        assert len(code) >= 2

    def test_typo_same_code(self):
        """Typo should produce the same phonetic code."""
        assert phonetic_code("checkout") == phonetic_code("chekout")

    def test_typo_purchase(self):
        assert phonetic_code("purchase") == phonetic_code("purchse")

    def test_typo_payment(self):
        assert phonetic_code("payment") == phonetic_code("paymnet")

    def test_typo_delete(self):
        assert phonetic_code("delete") == phonetic_code("delet")

    def test_typo_submit(self):
        assert phonetic_code("submit") == phonetic_code("sbumit")

    def test_typo_admin(self):
        assert phonetic_code("admin") == phonetic_code("adimn")

    def test_typo_transfer(self):
        assert phonetic_code("transfer") == phonetic_code("transefr")

    def test_typo_confirm(self):
        assert phonetic_code("confirm") == phonetic_code("conform")

    def test_doubled_consonant(self):
        """Doubled consonants should be collapsed."""
        assert phonetic_code("submit") == phonetic_code("submitt")

    def test_different_words_different_codes(self):
        """Unrelated words should produce different codes."""
        assert phonetic_code("export") != phonetic_code("report")

    def test_false_positive_billing_filling(self):
        """Different first character -> different code."""
        assert phonetic_code("billing") != phonetic_code("filling")

    def test_false_positive_login_signin(self):
        """Completely different words -> different codes."""
        assert phonetic_code("login") != phonetic_code("signin")

    def test_case_insensitive(self):
        assert phonetic_code("DELETE") == phonetic_code("delete")

    def test_empty_string(self):
        assert phonetic_code("") == ""

    def test_single_char(self):
        assert phonetic_code("a") == "a"

    def test_ck_normalization(self):
        """'ck' should be normalized to 'c'."""
        assert phonetic_code("click") == phonetic_code("clic")

    def test_authorize(self):
        assert phonetic_code("authorize") == phonetic_code("authorze")


# ═══════════════════════════════════════════════════════════════════════════
# phonetic_match_keywords — keyword list matching
# ═══════════════════════════════════════════════════════════════════════════

class TestPhoneticMatchKeywords:
    """Test phonetic matching with a keyword list."""

    def test_exact_hit(self):
        matched, kw = phonetic_match_keywords(
            ["pay", "purchase", "checkout"], "Checkout Now"
        )
        assert matched is True
        assert kw == "checkout"

    def test_typo_hit(self):
        """A typo should still match the closest keyword."""
        matched, kw = phonetic_match_keywords(
            ["pay", "purchase", "checkout"], "Compleet Purchse"
        )
        assert matched is True

    def test_no_hit(self):
        matched, kw = phonetic_match_keywords(
            ["pay", "purchase", "checkout"], "View Reports"
        )
        assert matched is False

    def test_empty_list(self):
        matched, kw = phonetic_match_keywords([], "some text")
        assert matched is False

    def test_empty_text(self):
        matched, kw = phonetic_match_keywords(["pay"], "")
        assert matched is False

    def test_inflected_form(self):
        """Inflected form 'Purchasing' should match 'purchase'."""
        matched, kw = phonetic_match_keywords(
            ["purchase"], "Purchasing Items"
        )
        assert matched is True
        assert kw == "purchase"

    def test_past_tense(self):
        """Phonetic should match 'purchase' in 'Purchasing'."""
        matched, kw = phonetic_match_keywords(
            ["purchase"], "Purchasing items now"
        )
        assert matched is True

    def test_false_positive_export_report(self):
        """'export' should NOT match 'report'."""
        matched, kw = phonetic_match_keywords(
            ["export"], "View Quarterly Report"
        )
        assert matched is False

    def test_false_positive_submit_order_vs_report(self):
        """'submit order' should NOT match 'Submit Report'."""
        matched, kw = phonetic_match_keywords(
            ["submit order"], "Submit Report"
        )
        assert matched is False


# ═══════════════════════════════════════════════════════════════════════════
# phonetic_match_intent — intent-level matching
# ═══════════════════════════════════════════════════════════════════════════

class TestPhoneticMatchIntent:
    """Test intent-level phonetic matching."""

    def test_payment_typo(self):
        matched, syn = phonetic_match_intent("payment", "Compleet Purchse")
        assert matched is True

    def test_delete_typo(self):
        matched, syn = phonetic_match_intent("delete", "Delet All Files")
        assert matched is True

    def test_admin_typo(self):
        matched, syn = phonetic_match_intent("admin", "Manag Users")
        assert matched is True

    def test_authentication_typo(self):
        """'Sing In' (typo for 'Sign In') should match authentication."""
        matched, syn = phonetic_match_intent("authentication", "Sing In Now")
        assert matched is True

    def test_no_match_wrong_intent(self):
        """Payment text should NOT match delete intent."""
        matched, syn = phonetic_match_intent("delete", "Checkout Now")
        assert matched is False

    def test_unknown_intent(self):
        """Unknown intent name should not match anything."""
        matched, syn = phonetic_match_intent("nonexistent", "Pay Now")
        assert matched is False
        assert syn is None

    def test_exact_still_works(self):
        """Exact text should also match via phonetic."""
        matched, syn = phonetic_match_intent("payment", "Checkout")
        assert matched is True


# ═══════════════════════════════════════════════════════════════════════════
# phonetic_detect_intents — detect all intents
# ═══════════════════════════════════════════════════════════════════════════

class TestPhoneticDetectIntents:
    """Test phonetic intent detection."""

    def test_typo_detected(self):
        results = phonetic_detect_intents("Compleet Purchse")
        intent_names = [r[0] for r in results]
        assert "payment" in intent_names

    def test_clean_text_detected(self):
        results = phonetic_detect_intents("Delete All Records")
        intent_names = [r[0] for r in results]
        assert "delete" in intent_names

    def test_unrelated_text_nothing(self):
        """Truly unrelated text should detect no intents."""
        results = phonetic_detect_intents("Open the blue widget")
        intent_names = [r[0] for r in results]
        for dangerous in ["payment", "delete", "admin", "authentication"]:
            assert dangerous not in intent_names

    def test_returns_sorted(self):
        results = phonetic_detect_intents("Delete the payment record now")
        if len(results) >= 2:
            intent_names = [r[0] for r in results]
            assert intent_names == sorted(intent_names)

    def test_inflected_forms_detected(self):
        """Inflected forms like 'Purchasing' should detect payment intent."""
        results = phonetic_detect_intents("Purchasing items online")
        intent_names = [r[0] for r in results]
        assert "payment" in intent_names


# ═══════════════════════════════════════════════════════════════════════════
# ElementRule.matches() — phonetic fallback integration
# ═══════════════════════════════════════════════════════════════════════════

class TestElementRulePhoneticMatching:
    """Test that ElementRule uses phonetic fallback when exact match fails."""

    def _make_event(self, text: str, selector: str = "#btn", url: str = "https://example.com"):
        return ActionEvent(
            action_type=ActionType.CLICK,
            selector=selector,
            url=url,
            element_text=text,
        )

    def test_exact_match_still_works(self):
        rule = ElementRule(intent="payment")
        event = self._make_event("Pay Now")
        assert rule.matches(event) is True

    def test_typo_caught_by_phonetic(self):
        rule = ElementRule(intent="payment")
        event = self._make_event("Compleet Purchse")
        assert rule.matches(event) is True

    def test_delete_typo_caught(self):
        rule = ElementRule(intent="delete")
        event = self._make_event("Delet Record")
        assert rule.matches(event) is True

    def test_no_false_positive(self):
        rule = ElementRule(intent="payment")
        event = self._make_event("View Reports")
        assert rule.matches(event) is False

    def test_text_contains_phonetic(self):
        """text_contains with typo should also benefit from phonetic."""
        rule = ElementRule(text_contains=["checkout"])
        event = self._make_event("Chekout Now")
        assert rule.matches(event) is True

    def test_phonetic_disabled(self):
        """Setting phonetic=False should disable phonetic matching."""
        rule = ElementRule(intent="payment", phonetic=False)
        event = self._make_event("Compleet Purchse")  # typo
        assert rule.matches(event) is False

    def test_inflected_form_caught(self):
        """Inflected forms like 'Purchasing' should be caught."""
        rule = ElementRule(intent="payment")
        event = self._make_event("Purchasing Items")
        assert rule.matches(event) is True

    def test_page_restriction_still_works(self):
        rule = ElementRule(intent="payment", on_pages="*/checkout/*")
        event = self._make_event("Purchse Now", url="https://example.com/home")
        assert rule.matches(event) is False

    def test_page_restriction_passes(self):
        rule = ElementRule(intent="payment", on_pages="*/checkout/*")
        event = self._make_event("Purchse Now", url="https://example.com/checkout/step1")
        assert rule.matches(event) is True


# ═══════════════════════════════════════════════════════════════════════════
# classify_risk — phonetic fallback in risk classification
# ═══════════════════════════════════════════════════════════════════════════

class TestClassifyRiskPhonetic:
    """Test that classify_risk uses phonetic intent detection for typos."""

    def _make_event(self, text: str, action: ActionType = ActionType.CLICK):
        return ActionEvent(
            action_type=action,
            selector="#btn",
            url="https://example.com",
            element_text=text,
        )

    def test_clean_text_high_risk(self):
        event = self._make_event("Complete Purchase")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_typo_text_high_risk(self):
        """Typo in payment text should STILL be HIGH risk."""
        event = self._make_event("Compleet Purchse")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_delete_typo_high_risk(self):
        event = self._make_event("Delet Everything")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_low_risk_unchanged(self):
        """Low-risk text should remain LOW."""
        event = self._make_event("Open Blue Widget")
        assert classify_risk(event) == RiskLevel.LOW

    def test_js_eval_still_critical(self):
        event = self._make_event("console.log", ActionType.EVALUATE_JS)
        assert classify_risk(event) == RiskLevel.CRITICAL

    def test_inflected_form_high_risk(self):
        """'Deleting' should be HIGH risk."""
        event = self._make_event("Deleting Records")
        assert classify_risk(event) == RiskLevel.HIGH


# ═══════════════════════════════════════════════════════════════════════════
# False positive regression tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPhoneticFalsePositiveRegression:
    """Ensure known false positives are ALWAYS rejected."""

    def test_export_vs_report(self):
        matched, _ = phonetic_match_keywords(["export"], "View Report")
        assert matched is False

    def test_billing_vs_filling(self):
        matched, _ = phonetic_match_keywords(["billing"], "Filling Form")
        assert matched is False

    def test_submit_order_vs_submit_report(self):
        matched, _ = phonetic_match_keywords(["submit order"], "Submit Report")
        assert matched is False

    def test_dashboard_is_admin(self):
        """'Dashboard' IS a real admin synonym — should match."""
        matched, _ = phonetic_match_intent("admin", "Dashboard")
        assert matched is True

    def test_all_intents_have_synonyms(self):
        for intent, synonyms in INTENT_SYNONYMS.items():
            assert len(synonyms) > 0, f"Intent '{intent}' has no synonyms"

    def test_phonetic_does_not_break_exact(self):
        """Phonetic layer should find at least the same intents as exact."""
        for text in ["Pay Now", "Delete", "Login", "Checkout"]:
            intents_exact = detect_intents(text)
            intents_phon = [r[0] for r in phonetic_detect_intents(text)]
            for intent in intents_exact:
                assert intent in intents_phon, (
                    f"Phonetic missed intent '{intent}' for text '{text}'"
                )
