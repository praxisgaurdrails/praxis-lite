"""Tests for the Praxis Policy Engine."""

import pytest
from praxis.policy.engine import (
    ActionEvent,
    ActionType,
    Decision,
    Policy,
    PolicyEngine,
    RiskLevel,
    classify_risk,
    create_finance_safe_policy,
    create_readonly_policy,
    create_permissive_policy,
)


# ---------------------------------------------------------------------------
# Risk Classification Tests
# ---------------------------------------------------------------------------

class TestRiskClassification:
    def test_high_risk_payment(self):
        event = ActionEvent(
            action_type=ActionType.CLICK,
            element_text="Pay Now",
        )
        assert classify_risk(event) == RiskLevel.HIGH

    def test_high_risk_delete(self):
        event = ActionEvent(
            action_type=ActionType.CLICK,
            element_text="Delete Account",
        )
        assert classify_risk(event) == RiskLevel.HIGH

    def test_high_risk_password_field(self):
        event = ActionEvent(
            action_type=ActionType.TYPE,
            selector="input[type='password']",
            value="secret123",
        )
        assert classify_risk(event) == RiskLevel.HIGH

    def test_medium_risk_submit(self):
        event = ActionEvent(
            action_type=ActionType.CLICK,
            element_text="Submit Form",
        )
        assert classify_risk(event) == RiskLevel.MEDIUM

    def test_low_risk_navigation(self):
        event = ActionEvent(
            action_type=ActionType.NAVIGATE,
            url="https://example.com/home",
            element_text="Go to homepage",
        )
        assert classify_risk(event) == RiskLevel.LOW

    def test_critical_risk_js_eval(self):
        event = ActionEvent(
            action_type=ActionType.EVALUATE_JS,
            value="document.cookie",
        )
        assert classify_risk(event) == RiskLevel.CRITICAL

    def test_medium_risk_download(self):
        event = ActionEvent(action_type=ActionType.DOWNLOAD)
        assert classify_risk(event) == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Policy Loading Tests
# ---------------------------------------------------------------------------

class TestPolicyLoading:
    def test_load_finance_safe_preset(self):
        policy = create_finance_safe_policy()
        assert policy.name == "finance-safe"
        assert policy.enabled is True
        assert len(policy.rules) > 0

    def test_load_readonly_preset(self):
        policy = create_readonly_policy()
        assert policy.name == "readonly"
        assert policy.block_all_downloads is True

    def test_load_permissive_preset(self):
        policy = create_permissive_policy()
        assert policy.name == "permissive"

    def test_load_from_yaml_string(self):
        yaml_str = """
name: test-policy
description: A test policy
rules:
  - action: click
    block_elements:
      - text_contains: ["Pay"]
        risk: high
"""
        policy = Policy.from_yaml_string(yaml_str)
        assert policy.name == "test-policy"
        assert len(policy.rules) == 1

    def test_policy_to_yaml(self):
        policy = create_finance_safe_policy()
        yaml_output = policy.to_yaml()
        assert "finance-safe" in yaml_output


# ---------------------------------------------------------------------------
# Policy Engine Tests
# ---------------------------------------------------------------------------

class TestPolicyEngine:
    def setup_method(self):
        self.engine = PolicyEngine()
        self.engine.load_policy(create_finance_safe_policy())

    def test_allow_safe_navigation(self):
        event = ActionEvent(
            action_type=ActionType.NAVIGATE,
            url="https://bank.com/invoices/list",
        )
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.ALLOW

    def test_block_admin_navigation(self):
        event = ActionEvent(
            action_type=ActionType.NAVIGATE,
            url="https://bank.com/admin/users",
        )
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.BLOCK

    def test_block_payment_click(self):
        event = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://bank.com/invoices/123",
            element_text="Pay Now",
        )
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.BLOCK

    def test_block_delete_click(self):
        event = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://bank.com/invoices/123",
            element_text="Delete Invoice",
        )
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.BLOCK

    def test_require_approval_submit(self):
        event = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://bank.com/reports/new",
            element_text="Submit Report",
        )
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.REQUIRE_APPROVAL

    def test_block_password_typing(self):
        event = ActionEvent(
            action_type=ActionType.TYPE,
            url="https://bank.com/login",
            selector="input[type='password']",
            value="mypassword",
        )
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.BLOCK

    def test_block_js_evaluation(self):
        event = ActionEvent(
            action_type=ActionType.EVALUATE_JS,
            value="document.cookie",
        )
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.BLOCK

    def test_block_clipboard(self):
        event = ActionEvent(
            action_type=ActionType.COPY,
            url="https://bank.com/data",
        )
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.BLOCK

    def test_no_policies_allows_all(self):
        engine = PolicyEngine()
        event = ActionEvent(
            action_type=ActionType.CLICK,
            element_text="Delete Everything",
        )
        decision = engine.evaluate(event)
        assert decision.decision == Decision.ALLOW

    def test_decision_has_fingerprint(self):
        event = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://example.com",
            element_text="Pay",
        )
        decision = self.engine.evaluate(event)
        assert decision.action_fingerprint != ""

    def test_decision_has_policy_name(self):
        event = ActionEvent(
            action_type=ActionType.CLICK,
            element_text="Transfer Money",
        )
        decision = self.engine.evaluate(event)
        assert decision.policy_name == "finance-safe"


# ---------------------------------------------------------------------------
# Domain Restriction Tests
# ---------------------------------------------------------------------------

class TestDomainRestrictions:
    def test_blocked_domain(self):
        policy = Policy.from_yaml_string("""
name: domain-test
blocked_domains:
  - evil.com
  - malware.example.com
rules: []
""")
        engine = PolicyEngine()
        engine.load_policy(policy)

        event = ActionEvent(
            action_type=ActionType.NAVIGATE,
            url="https://evil.com/steal-data",
        )
        decision = engine.evaluate(event)
        assert decision.decision == Decision.BLOCK

    def test_allowed_domain(self):
        policy = Policy.from_yaml_string("""
name: domain-test
allowed_domains:
  - safe.com
rules: []
""")
        engine = PolicyEngine()
        engine.load_policy(policy)

        event = ActionEvent(
            action_type=ActionType.NAVIGATE,
            url="https://other.com/page",
        )
        decision = engine.evaluate(event)
        assert decision.decision == Decision.BLOCK


# ---------------------------------------------------------------------------
# Readonly Policy Tests
# ---------------------------------------------------------------------------

class TestReadonlyPolicy:
    def setup_method(self):
        self.engine = PolicyEngine()
        self.engine.load_policy(create_readonly_policy())

    def test_blocks_downloads(self):
        event = ActionEvent(action_type=ActionType.DOWNLOAD)
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.BLOCK

    def test_blocks_uploads(self):
        event = ActionEvent(action_type=ActionType.UPLOAD)
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.BLOCK

    def test_blocks_js(self):
        event = ActionEvent(
            action_type=ActionType.EVALUATE_JS,
            value="alert(1)",
        )
        decision = self.engine.evaluate(event)
        assert decision.decision == Decision.BLOCK


# ---------------------------------------------------------------------------
# OpenClaw YAML Format Tests (url_rules / element_rules / action_rules)
# ---------------------------------------------------------------------------

class TestOpenClawYamlFormat:
    """Tests for the alternative YAML format used by OpenClaw policies."""

    def test_url_rules_block_navigation(self):
        policy = Policy.from_yaml_string("""
name: test-url-rules
description: Test url_rules parsing
version: "1.0"
url_rules:
  - pattern: ".*/admin/.*"
    decision: block
    reason: "Admin blocked"
  - pattern: ".*/settings/billing.*"
    decision: block
    reason: "Billing blocked"
""")
        assert len(policy.rules) == 2

        engine = PolicyEngine()
        engine.load_policy(policy)

        # Should block admin URL
        event = ActionEvent(action_type=ActionType.NAVIGATE, url="https://example.com/admin/users")
        assert engine.evaluate(event).decision == Decision.BLOCK

        # Should allow safe URL
        event2 = ActionEvent(action_type=ActionType.NAVIGATE, url="https://example.com/dashboard")
        assert engine.evaluate(event2).decision == Decision.ALLOW

    def test_element_rules_block_clicks(self):
        policy = Policy.from_yaml_string("""
name: test-element-rules
description: Test element_rules parsing
version: "1.0"
element_rules:
  - text_pattern: "(?i)(pay|transfer|wire)"
    decision: block
    reason: "Payment blocked"
  - text_pattern: "(?i)(submit|confirm)"
    decision: require_approval
    reason: "Needs approval"
""")
        engine = PolicyEngine()
        engine.load_policy(policy)

        # Should block payment click
        event = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://bank.com",
            element_text="Pay Now",
        )
        result = engine.evaluate(event)
        assert result.decision == Decision.BLOCK

        # Should require approval for submit
        event2 = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://bank.com",
            element_text="Submit Form",
        )
        result2 = engine.evaluate(event2)
        assert result2.decision == Decision.REQUIRE_APPROVAL

        # Should allow safe click
        event3 = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://bank.com",
            element_text="View Details",
        )
        result3 = engine.evaluate(event3)
        assert result3.decision == Decision.ALLOW

    def test_action_rules_block_actions(self):
        policy = Policy.from_yaml_string("""
name: test-action-rules
description: Test action_rules parsing
version: "1.0"
block_js_evaluation: false
action_rules:
  - action_type: evaluate_js
    decision: block
    reason: "JS blocked"
  - action_type: upload
    decision: require_approval
    reason: "Uploads need approval"
""")
        engine = PolicyEngine()
        engine.load_policy(policy)

        # Should block JS execution
        event = ActionEvent(action_type=ActionType.EVALUATE_JS, url="https://example.com", value="alert(1)")
        assert engine.evaluate(event).decision == Decision.BLOCK

        # Should require approval for upload
        event2 = ActionEvent(action_type=ActionType.UPLOAD, url="https://example.com")
        assert engine.evaluate(event2).decision == Decision.REQUIRE_APPROVAL

    def test_rate_limit_from_nested(self):
        policy = Policy.from_yaml_string("""
name: test-rate-limit
description: Test rate_limit block parsing
version: "1.0"
rate_limit:
  max_actions_per_minute: 30
""")
        assert policy.max_actions_per_minute == 30

    def test_openclaw_default_yaml_file(self):
        """Load the actual OpenClaw default policy file and verify it works."""
        policy = Policy.from_yaml("skills/praxis/policies/openclaw-default.yaml")
        assert policy.name == "openclaw-default"
        assert len(policy.rules) > 0

        engine = PolicyEngine()
        engine.load_policy(policy)

        # Should block payment click
        event = ActionEvent(action_type=ActionType.CLICK, url="https://bank.com", element_text="Pay Now")
        assert engine.evaluate(event).decision == Decision.BLOCK

        # Should block admin navigation
        event2 = ActionEvent(action_type=ActionType.NAVIGATE, url="https://example.com/admin/panel")
        assert engine.evaluate(event2).decision == Decision.BLOCK

        # Should allow safe navigation
        event3 = ActionEvent(action_type=ActionType.NAVIGATE, url="https://example.com/dashboard")
        assert engine.evaluate(event3).decision == Decision.ALLOW

    def test_openclaw_strict_yaml_file(self):
        """Load the actual OpenClaw strict policy file and verify it works."""
        policy = Policy.from_yaml("skills/praxis/policies/openclaw-strict.yaml")
        assert policy.name == "openclaw-strict"
        assert len(policy.rules) > 0

        engine = PolicyEngine()
        engine.load_policy(policy)

        # Should block HTTP (non-HTTPS)
        event = ActionEvent(action_type=ActionType.NAVIGATE, url="http://insecure.com")
        assert engine.evaluate(event).decision == Decision.BLOCK

        # Should block payment click
        event2 = ActionEvent(action_type=ActionType.CLICK, url="https://bank.com", element_text="Purchase")
        assert engine.evaluate(event2).decision == Decision.BLOCK

    def test_mixed_format_not_supported(self):
        """Both formats can coexist in the same YAML (rules + url_rules)."""
        policy = Policy.from_yaml_string("""
name: test-mixed
description: Both formats together
version: "1.0"
rules:
  - action: click
    block_elements:
      - text_contains: ["Delete"]
        risk: high
url_rules:
  - pattern: ".*/admin/.*"
    decision: block
""")
        engine = PolicyEngine()
        engine.load_policy(policy)

        # rules format should work
        event = ActionEvent(action_type=ActionType.CLICK, url="https://example.com", element_text="Delete Item")
        assert engine.evaluate(event).decision == Decision.BLOCK

        # url_rules format should also work
        event2 = ActionEvent(action_type=ActionType.NAVIGATE, url="https://example.com/admin/settings")
        assert engine.evaluate(event2).decision == Decision.BLOCK

    def test_keyword_extraction_from_pattern(self):
        """Test the regex-to-keyword extraction helper."""
        keywords = Policy._extract_keywords_from_pattern("(?i)(pay|transfer|wire)")
        assert "pay" in keywords
        assert "transfer" in keywords
        assert "wire" in keywords

    def test_keyword_extraction_complex_pattern(self):
        """Test extraction from more complex regex patterns."""
        keywords = Policy._extract_keywords_from_pattern("(?i)(sign.?in|sign.?up|forgot.?password)")
        assert len(keywords) == 3
