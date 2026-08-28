"""Tests for smart intent matching in the policy engine."""

import pytest

from praxis.policy.intent_matcher import (
    match_intent,
    expand_keywords,
    detect_intents,
    get_all_intents,
    get_intent_keywords,
    INTENT_SYNONYMS,
)
from praxis.policy.engine import (
    ActionEvent,
    ActionType,
    Decision,
    ElementRule,
    RiskLevel,
    classify_risk,
    Policy,
    PolicyEngine,
)


# ═══════════════════════════════════════════════════════════════════════════
# Intent Matcher Unit Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestMatchIntent:
    """Test the core match_intent function."""

    def test_payment_exact(self):
        assert match_intent("payment", "Pay Now") is True

    def test_payment_checkout(self):
        assert match_intent("payment", "Proceed to Checkout") is True

    def test_payment_complete_purchase(self):
        assert match_intent("payment", "Complete Purchase") is True

    def test_payment_place_order(self):
        assert match_intent("payment", "Place Order") is True

    def test_payment_buy_now(self):
        assert match_intent("payment", "Buy Now") is True

    def test_payment_subscribe(self):
        assert match_intent("payment", "Subscribe Now") is True

    def test_payment_continue_to_payment(self):
        assert match_intent("payment", "Continue to Payment") is True

    def test_payment_donate(self):
        assert match_intent("payment", "Make a Donation") is True

    def test_payment_review_and_pay(self):
        assert match_intent("payment", "Review & Pay") is True

    def test_payment_no_match(self):
        assert match_intent("payment", "Read Report") is False

    def test_payment_no_match_browse(self):
        assert match_intent("payment", "View Dashboard") is False

    def test_delete_remove(self):
        assert match_intent("delete", "Remove this item") is True

    def test_delete_trash(self):
        assert match_intent("delete", "Move to Trash") is True

    def test_delete_discard(self):
        assert match_intent("delete", "Discard Changes") is True

    def test_delete_permanently(self):
        assert match_intent("delete", "Permanently Delete") is True

    def test_delete_erase(self):
        assert match_intent("delete", "Erase all data") is True

    def test_delete_no_match(self):
        assert match_intent("delete", "View Details") is False

    def test_admin_control_panel(self):
        assert match_intent("admin", "Open Control Panel") is True

    def test_admin_manage(self):
        assert match_intent("admin", "Manage Users") is True

    def test_admin_settings(self):
        assert match_intent("admin", "Account Settings") is True

    def test_admin_grant_permission(self):
        assert match_intent("admin", "Grant Permission to user") is True

    def test_auth_sign_in(self):
        assert match_intent("authentication", "Sign In") is True

    def test_auth_login(self):
        assert match_intent("authentication", "Log In to your account") is True

    def test_auth_create_account(self):
        assert match_intent("authentication", "Create Account") is True

    def test_auth_forgot_password(self):
        assert match_intent("authentication", "Forgot Password?") is True

    def test_auth_2fa(self):
        assert match_intent("authentication", "Enter 2FA code") is True

    def test_sensitive_credit_card(self):
        assert match_intent("sensitive_field", "Enter credit card number") is True

    def test_sensitive_ssn(self):
        assert match_intent("sensitive_field", "Social Security Number") is True

    def test_sensitive_cvv(self):
        assert match_intent("sensitive_field", "Enter CVV") is True

    def test_sensitive_iban(self):
        assert match_intent("sensitive_field", "IBAN number") is True

    def test_unknown_intent(self):
        assert match_intent("nonexistent_intent", "anything") is False

    def test_case_insensitive(self):
        assert match_intent("payment", "CHECKOUT NOW") is True
        assert match_intent("delete", "PERMANENTLY DELETE") is True


class TestExpandKeywords:
    """Test keyword expansion through synonym groups."""

    def test_pay_expands_to_payment_synonyms(self):
        expanded = expand_keywords(["Pay"])
        assert "checkout" in expanded
        assert "purchase" in expanded
        assert "buy now" in expanded
        assert "place order" in expanded

    def test_delete_expands(self):
        expanded = expand_keywords(["Delete"])
        assert "remove" in expanded
        assert "destroy" in expanded
        assert "purge" in expanded
        assert "trash" in expanded

    def test_unknown_keyword_kept_as_is(self):
        expanded = expand_keywords(["xyzzy123"])
        assert "xyzzy123" in expanded

    def test_mixed_known_unknown(self):
        expanded = expand_keywords(["Pay", "custom_word"])
        assert "checkout" in expanded     # expanded from Pay
        assert "custom_word" in expanded  # kept as-is

    def test_empty_list(self):
        assert expand_keywords([]) == []

    def test_no_duplicates(self):
        expanded = expand_keywords(["Pay", "payment", "purchase"])
        # All three are in the same group — should not duplicate
        assert len(expanded) == len(set(expanded))


class TestDetectIntents:
    """Test intent detection from arbitrary text."""

    def test_checkout_detected_as_payment(self):
        assert "payment" in detect_intents("Click the Checkout button")

    def test_delete_detected(self):
        assert "delete" in detect_intents("Permanently delete all records")

    def test_multiple_intents(self):
        intents = detect_intents("Delete the payment record")
        assert "delete" in intents
        assert "payment" in intents

    def test_no_intents_in_neutral_text(self):
        intents = detect_intents("Read the quarterly report")
        assert len(intents) == 0

    def test_admin_detected(self):
        assert "admin" in detect_intents("Go to Admin Panel")


# ═══════════════════════════════════════════════════════════════════════════
# ElementRule Smart Matching Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestElementRuleIntentMatching:
    """Test ElementRule with the new intent field."""

    def _make_event(self, text: str, url: str = "https://example.com") -> ActionEvent:
        return ActionEvent(
            action_type=ActionType.CLICK,
            url=url,
            element_text=text,
        )

    def test_intent_payment_blocks_checkout(self):
        rule = ElementRule(intent="payment", decision=Decision.BLOCK)
        event = self._make_event("Proceed to Checkout")
        assert rule.matches(event) is True

    def test_intent_payment_blocks_complete_purchase(self):
        rule = ElementRule(intent="payment", decision=Decision.BLOCK)
        event = self._make_event("Complete Purchase")
        assert rule.matches(event) is True

    def test_intent_payment_blocks_place_order(self):
        rule = ElementRule(intent="payment", decision=Decision.BLOCK)
        event = self._make_event("Place Order")
        assert rule.matches(event) is True

    def test_intent_payment_blocks_buy_now(self):
        rule = ElementRule(intent="payment", decision=Decision.BLOCK)
        event = self._make_event("Buy Now")
        assert rule.matches(event) is True

    def test_intent_payment_blocks_subscribe(self):
        rule = ElementRule(intent="payment", decision=Decision.BLOCK)
        event = self._make_event("Start Subscription")
        assert rule.matches(event) is True

    def test_intent_payment_allows_read(self):
        """Non-financial text should NOT match payment intent."""
        rule = ElementRule(intent="payment", decision=Decision.BLOCK)
        event = self._make_event("Open Settings Menu")
        assert rule.matches(event) is False

    def test_intent_delete_blocks_trash(self):
        rule = ElementRule(intent="delete", decision=Decision.BLOCK)
        event = self._make_event("Move to Trash")
        assert rule.matches(event) is True

    def test_intent_delete_blocks_discard(self):
        rule = ElementRule(intent="delete", decision=Decision.BLOCK)
        event = self._make_event("Discard Draft")
        assert rule.matches(event) is True

    def test_intent_admin_blocks_control_panel(self):
        rule = ElementRule(intent="admin", decision=Decision.BLOCK)
        event = self._make_event("Open Control Panel")
        assert rule.matches(event) is True

    def test_text_contains_still_works(self):
        """Old-style text_contains still works."""
        rule = ElementRule(text_contains=["Special Button"], decision=Decision.BLOCK)
        event = self._make_event("Click Special Button Here")
        assert rule.matches(event) is True

    def test_text_contains_auto_expands(self):
        """text_contains: ['Pay'] now also catches 'Checkout'."""
        rule = ElementRule(text_contains=["Pay"], decision=Decision.BLOCK)
        event = self._make_event("Proceed to Checkout")
        assert rule.matches(event) is True

    def test_text_contains_auto_expands_purchase(self):
        rule = ElementRule(text_contains=["Pay"], decision=Decision.BLOCK)
        event = self._make_event("Complete Purchase")
        assert rule.matches(event) is True

    def test_intent_with_on_pages(self):
        """Intent matching respects page restrictions."""
        rule = ElementRule(intent="payment", on_pages="*/checkout/*", decision=Decision.BLOCK)
        event_match = self._make_event("Place Order", "https://shop.com/checkout/step2")
        event_no = self._make_event("Place Order", "https://shop.com/browse/items")
        assert rule.matches(event_match) is True
        assert rule.matches(event_no) is False

    def test_empty_rule_matches_everything(self):
        """A rule with no constraints matches anything (catch-all)."""
        rule = ElementRule(decision=Decision.BLOCK)
        event = self._make_event("Anything at all")
        assert rule.matches(event) is True


# ═══════════════════════════════════════════════════════════════════════════
# Risk Classification with Intent Detection
# ═══════════════════════════════════════════════════════════════════════════

class TestSmartRiskClassification:
    """Test that risk classifier catches variations via intents."""

    def _make_event(self, text: str, action: ActionType = ActionType.CLICK) -> ActionEvent:
        return ActionEvent(action_type=action, url="https://example.com", element_text=text)

    def test_checkout_is_high_risk(self):
        event = self._make_event("Proceed to Checkout")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_complete_purchase_is_high_risk(self):
        event = self._make_event("Complete Purchase")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_place_order_is_high_risk(self):
        event = self._make_event("Place Order")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_buy_now_is_high_risk(self):
        event = self._make_event("Buy Now")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_subscribe_is_high_risk(self):
        event = self._make_event("Subscribe Now")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_trash_is_high_risk(self):
        event = self._make_event("Move to Trash")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_discard_is_high_risk(self):
        event = self._make_event("Discard Changes")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_forgot_password_is_high_risk(self):
        event = self._make_event("Forgot Password")
        assert classify_risk(event) == RiskLevel.HIGH

    def test_neutral_text_is_low_risk(self):
        event = self._make_event("Show the results")
        assert classify_risk(event) == RiskLevel.LOW

    def test_save_changes_is_medium_risk(self):
        event = self._make_event("Save Changes")
        assert classify_risk(event) == RiskLevel.MEDIUM


# ═══════════════════════════════════════════════════════════════════════════
# Policy YAML Parsing with Intents
# ═══════════════════════════════════════════════════════════════════════════

class TestPolicyYAMLIntents:
    """Test that intent field is correctly parsed from YAML."""

    def test_intent_parsed_from_yaml(self):
        yaml_str = """
name: test-intent
description: Testing intent-based rules
rules:
  - action: click
    block_elements:
      - intent: payment
        risk: high
      - intent: delete
        risk: high
    require_approval:
      - intent: confirm
        risk: medium
"""
        policy = Policy.from_yaml_string(yaml_str)
        assert len(policy.rules) == 1
        click_rule = policy.rules[0]
        assert len(click_rule.block_elements) == 2
        assert click_rule.block_elements[0].intent == "payment"
        assert click_rule.block_elements[1].intent == "delete"
        assert len(click_rule.require_approval_elements) == 1
        assert click_rule.require_approval_elements[0].intent == "confirm"

    def test_intent_policy_blocks_checkout(self):
        yaml_str = """
name: test-blocks
rules:
  - action: click
    block_elements:
      - intent: payment
"""
        policy = Policy.from_yaml_string(yaml_str)
        event = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://shop.com/cart",
            element_text="Proceed to Checkout",
        )
        # Check if the rule matches
        click_rule = policy.rules[0]
        assert click_rule.block_elements[0].matches(event) is True

    def test_intent_policy_allows_neutral_actions(self):
        yaml_str = """
name: test-allows
rules:
  - action: click
    block_elements:
      - intent: payment
"""
        policy = Policy.from_yaml_string(yaml_str)
        event = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://shop.com/products",
            element_text="View Product Details",
        )
        click_rule = policy.rules[0]
        assert click_rule.block_elements[0].matches(event) is False

    def test_mixed_intent_and_text_contains(self):
        """Policy can mix intent and text_contains in the same rule set."""
        yaml_str = """
name: test-mixed
rules:
  - action: click
    block_elements:
      - intent: payment
      - text_contains: ["Special Custom Action"]
"""
        policy = Policy.from_yaml_string(yaml_str)
        click_rule = policy.rules[0]

        # Intent match
        event1 = ActionEvent(
            action_type=ActionType.CLICK, url="https://x.com",
            element_text="Complete Purchase",
        )
        assert click_rule.block_elements[0].matches(event1) is True

        # text_contains match
        event2 = ActionEvent(
            action_type=ActionType.CLICK, url="https://x.com",
            element_text="Do Special Custom Action Now",
        )
        assert click_rule.block_elements[1].matches(event2) is True


# ═══════════════════════════════════════════════════════════════════════════
# Full Policy Engine Integration
# ═══════════════════════════════════════════════════════════════════════════

class TestPolicyEngineSmartMatching:
    """End-to-end test: policy engine with intent-based rules."""

    def _engine_with_intent_policy(self) -> PolicyEngine:
        yaml_str = """
name: smart-policy
description: Intent-based blocking
rules:
  - action: click
    block_elements:
      - intent: payment
        risk: high
      - intent: delete
        risk: high
    require_approval:
      - intent: confirm
        risk: medium
  - action: type
    block_elements:
      - intent: sensitive_field
"""
        engine = PolicyEngine()
        policy = Policy.from_yaml_string(yaml_str)
        engine.load_policy(policy)
        return engine

    def test_blocks_checkout(self):
        engine = self._engine_with_intent_policy()
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.CLICK,
            url="https://shop.com/cart",
            element_text="Proceed to Checkout",
        ))
        assert result.decision == Decision.BLOCK

    def test_blocks_complete_purchase(self):
        engine = self._engine_with_intent_policy()
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.CLICK,
            url="https://shop.com/cart",
            element_text="Complete Purchase",
        ))
        assert result.decision == Decision.BLOCK

    def test_blocks_place_order(self):
        engine = self._engine_with_intent_policy()
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.CLICK,
            url="https://shop.com/cart",
            element_text="Place Order",
        ))
        assert result.decision == Decision.BLOCK

    def test_blocks_subscribe(self):
        engine = self._engine_with_intent_policy()
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.CLICK,
            url="https://shop.com/pricing",
            element_text="Start Subscription",
        ))
        assert result.decision == Decision.BLOCK

    def test_blocks_trash(self):
        engine = self._engine_with_intent_policy()
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.CLICK,
            url="https://app.com/items",
            element_text="Move to Trash",
        ))
        assert result.decision == Decision.BLOCK

    def test_allows_view(self):
        engine = self._engine_with_intent_policy()
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.CLICK,
            url="https://app.com/report",
            element_text="View Report",
        ))
        assert result.decision == Decision.ALLOW

    def test_blocks_typing_credit_card(self):
        engine = self._engine_with_intent_policy()
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.TYPE,
            url="https://shop.com/checkout",
            selector="input[name='card_number']",
            element_text="Credit Card Number",
            value="4111111111111111",
        ))
        assert result.decision == Decision.BLOCK

    def test_blocks_typing_ssn(self):
        engine = self._engine_with_intent_policy()
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.TYPE,
            url="https://app.com/profile",
            element_text="Social Security Number",
            value="123-45-6789",
        ))
        assert result.decision == Decision.BLOCK

    def test_loaded_yaml_policies_still_work(self):
        """Ensure the updated YAML policies load and work correctly."""
        engine = PolicyEngine()
        policy = Policy.from_yaml("policies/finance-safe.yaml")
        engine.load_policy(policy)

        # "Complete Purchase" should be BLOCKED (payment intent)
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.CLICK,
            url="https://bank.com/account",
            element_text="Complete Purchase",
        ))
        assert result.decision == Decision.BLOCK

        # "View Balance" should be ALLOWED
        result = engine.evaluate(ActionEvent(
            action_type=ActionType.CLICK,
            url="https://bank.com/account",
            element_text="View Balance",
        ))
        assert result.decision == Decision.ALLOW
