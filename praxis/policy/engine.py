"""
Praxis Policy Engine — Action-level control for AI agents.

This is the core of Praxis. The policy engine evaluates every action
an agent attempts to take and decides: ALLOW, BLOCK, or REQUIRE_APPROVAL.

Policies are defined in YAML and loaded at runtime. They can match on:
- URL patterns (which pages the agent can access)
- Element selectors (which buttons/forms/fields can be interacted with)
- Action types (click, type, navigate, download, etc.)
- Risk classification (auto-detected high-risk actions)
- Content patterns (sensitive data in fields)

Example policy (YAML):
    name: finance-safe
    description: Allow reading invoices, block payments
    rules:
      - action: navigate
        allow:
          - pattern: "*/invoices/*"
          - pattern: "*/reports/*"
        block:
          - pattern: "*/payments/*"
          - pattern: "*/admin/*"
      - action: click
        block_elements:
          - selector: "button[type='submit']"
            on_pages: "*/payments/*"
          - text_contains: ["Pay", "Transfer", "Delete", "Remove"]
            risk: HIGH
        require_approval:
          - text_contains: ["Submit", "Confirm", "Send"]
            risk: MEDIUM
      - action: type
        block_fields:
          - selector: "input[name='credit_card']"
          - selector: "input[name='password']"
"""

from __future__ import annotations

import re
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from praxis.policy.intent_matcher import (
    match_intent,
    expand_keywords,
    detect_intents,
    phonetic_match_keywords,
    phonetic_detect_intents,
    INTENT_SYNONYMS,
)
from praxis.principal import Principal, PrincipalKind
from praxis.tiers import RiskTier, default_tier_for_browser_action
from praxis.policy.semantic_matcher import (
    semantic_classify,
    semantic_detect_intents,
    semantic_risk,
    semantic_matches_intent,
    is_semantic_available,
    SemanticMatch,
    SEMANTIC_RISK_MAP,
)


# ---------------------------------------------------------------------------
# Core enums
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    """Every action an agent can take through a browser."""
    NAVIGATE = "navigate"
    CLICK = "click"
    TYPE = "type"
    SELECT = "select"
    SUBMIT = "submit"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    COPY = "copy"
    SCREENSHOT = "screenshot"
    SCROLL = "scroll"
    HOVER = "hover"
    DRAG = "drag"
    KEY_PRESS = "key_press"
    EVALUATE_JS = "evaluate_js"
    # --- Praxis Phase 2 additions ---
    # Umbrella type used when routing a filesystem-tool call through
    # the shared evidence vault.  The specific fs.* op name is stored
    # in ``ActionEvent.selector`` (and in the metadata), and the tier
    # is set explicitly via ``ActionEvent.tier``.
    FILESYSTEM = "filesystem"


class RiskLevel(str, Enum):
    """Risk classification for actions."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    """What the policy engine decides for an action."""
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    LOG_ONLY = "log_only"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class ActionEvent(BaseModel):
    """Represents a single action an agent is attempting."""
    action_type: ActionType
    url: str = ""
    selector: str = ""
    element_tag: str = ""
    element_text: str = ""
    element_type: str = ""
    element_id: str = ""
    element_classes: list[str] = Field(default_factory=list)
    value: str = ""  # for type actions
    timestamp: float = Field(default_factory=time.time)
    agent_id: str = ""
    session_id: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    # --- Praxis Phase 1 additions ---
    # Caller identity resolved by the transport layer.  Defaults to the
    # ``unknown`` principal so legacy callers that instantiate an
    # ``ActionEvent`` without setting it still get a sensible value.
    principal: Principal | None = None
    # Risk tier of the operation.  If omitted, derived from ``action_type``
    # at access time via :meth:`resolved_tier`.  We keep the field
    # optional so existing tests that construct ``ActionEvent`` without
    # a tier continue to work unchanged.
    tier: RiskTier | None = None

    model_config = {"arbitrary_types_allowed": True}

    @property
    def fingerprint(self) -> str:
        """Unique hash for this action event."""
        raw = f"{self.action_type}:{self.url}:{self.selector}:{self.element_text}:{self.value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def resolved_principal(self) -> Principal:
        """Principal for this event, defaulting to ``unknown``."""
        if self.principal is not None:
            return self.principal
        return Principal(kind=PrincipalKind.UNKNOWN)

    @property
    def resolved_tier(self) -> RiskTier:
        """Risk tier for this event.

        Uses ``self.tier`` when the caller has set it, otherwise
        derives from ``action_type`` via the browser default table.
        """
        if self.tier is not None:
            return self.tier
        return default_tier_for_browser_action(self.action_type.value)


class PolicyDecision(BaseModel):
    """The result of evaluating an action against policies."""
    decision: Decision
    risk_level: RiskLevel
    matched_rule: str = ""
    reason: str = ""
    policy_name: str = ""
    timestamp: float = Field(default_factory=time.time)
    action_fingerprint: str = ""

    # --- Praxis Phase 1 additions ---
    # The tier the engine decided against.  Recorded in the evidence
    # chain so replay + audit can see the tier context of every
    # decision.  Optional to preserve backwards compatibility with
    # existing tests that construct decisions positionally.
    tier: RiskTier | None = None
    # String rendering of the principal the decision was made against.
    # We store the string form (``"agent:claude-desktop"`` /
    # ``"praxis:local"`` / ``"unknown"``) rather than a :class:`Principal`
    # object so ``PolicyDecision`` can round-trip through JSON without
    # dragging the dataclass along.
    principal: str = ""

    @property
    def is_blocked(self) -> bool:
        return self.decision == Decision.BLOCK

    @property
    def needs_approval(self) -> bool:
        return self.decision == Decision.REQUIRE_APPROVAL


# ---------------------------------------------------------------------------
# High-risk keywords auto-detection
# ---------------------------------------------------------------------------

HIGH_RISK_KEYWORDS = [
    "pay", "payment", "transfer", "wire", "send money",
    "delete", "remove", "destroy", "purge", "erase",
    "admin", "administrator", "root", "superuser",
    "export", "download all", "bulk download",
    "password", "credential", "secret", "api key",
    "confirm purchase", "place order", "checkout",
    "terminate", "shutdown", "disable",
    "grant access", "change permission", "elevate",
]

MEDIUM_RISK_KEYWORDS = [
    "submit", "confirm", "send", "approve", "accept",
    "update", "modify", "change", "edit",
    "upload", "import", "install",
    "share", "publish", "post",
]

SENSITIVE_FIELD_PATTERNS = [
    r"password",
    r"credit.?card",
    r"card.?number",
    r"cvv",
    r"ssn",
    r"social.?security",
    r"api.?key",
    r"secret",
    r"token",
    r"account.?number",
    r"routing.?number",
]


# ── Intent-based risk mapping (replaces hardcoded keyword lists) ──────
# Maps intents to their risk levels. This is the SINGLE source of truth
# for auto-risk-classification. No more hardcoded keyword lists that
# miss variations.

CRITICAL_INTENTS: list[str] = ["destructive_system"]
HIGH_RISK_INTENTS: list[str] = [
    "payment", "delete", "admin", "authentication",
    "sensitive_field", "financial", "system_destructive",
    # Semantic-only intents (not in keyword synonym list)
    "system", "permission", "api_call",
]
MEDIUM_RISK_INTENTS: list[str] = [
    "confirm", "modify", "share", "export", "upload", "messaging",
    # Semantic-only intents
    "modifying", "sharing", "posting", "uploading", "downloading",
    "data_entry",
]


def classify_risk(event: ActionEvent) -> RiskLevel:
    """Auto-classify risk using semantic intent detection.

    Instead of matching against a hardcoded list of 30 keywords, this uses
    the full intent vocabulary (200+ synonyms across 12 intent categories)
    to understand what the action is TRYING TO DO.

    "Complete Purchase" → detected intent: payment → HIGH risk
    "Place Order"       → detected intent: payment → HIGH risk
    "Delete forever"    → detected intent: delete  → HIGH risk
    """
    text_lower = event.element_text.lower()
    value_lower = event.value.lower()
    selector_lower = event.selector.lower()
    url_lower = event.url.lower()
    combined = f"{text_lower} {value_lower} {selector_lower} {url_lower}"

    # Check for critical patterns (JS evaluation, etc.)
    if event.action_type == ActionType.EVALUATE_JS:
        return RiskLevel.CRITICAL

    # Detect intents from the combined text
    matched_intents = detect_intents(combined)

    # If no exact intents found, try phonetic detection (catches typos)
    if not matched_intents:
        phonetic_results = phonetic_detect_intents(combined)
        matched_intents = [intent for intent, _ in phonetic_results]

    # If still nothing, try semantic NLP (catches novel phrasings)
    if not matched_intents:
        semantic_results = semantic_detect_intents(combined, threshold=0.65)
        if semantic_results:
            matched_intents = [intent for intent, _ in semantic_results]

    # Check CRITICAL risk intents (destructive system actions)
    for intent in matched_intents:
        if intent in CRITICAL_INTENTS:
            return RiskLevel.CRITICAL

    # Check HIGH risk intents
    for intent in matched_intents:
        if intent in HIGH_RISK_INTENTS:
            return RiskLevel.HIGH

    # Check sensitive field patterns (regex-based, catches field names)
    for pattern in SENSITIVE_FIELD_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return RiskLevel.HIGH

    # Also keep the hardcoded keywords as fallback for edge cases
    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in combined:
            return RiskLevel.HIGH

    # Check MEDIUM risk intents
    for intent in matched_intents:
        if intent in MEDIUM_RISK_INTENTS:
            return RiskLevel.MEDIUM

    for keyword in MEDIUM_RISK_KEYWORDS:
        if keyword in combined:
            return RiskLevel.MEDIUM

    # Downloads and uploads are at least medium risk
    if event.action_type in (ActionType.DOWNLOAD, ActionType.UPLOAD):
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


# ---------------------------------------------------------------------------
# Policy rule models
# ---------------------------------------------------------------------------

class URLRule(BaseModel):
    """A rule that matches URL patterns."""
    pattern: str
    decision: Decision = Decision.BLOCK

    def matches(self, url: str) -> bool:
        """Check if URL matches the glob-style pattern."""
        regex = self.pattern.replace("*", ".*")
        return bool(re.search(regex, url, re.IGNORECASE))


class ElementRule(BaseModel):
    """A rule that matches DOM elements — with smart intent matching.

    Supports three matching modes:
        1. intent: "payment"           → matches 50+ payment-related words
        2. text_contains: ["Pay"]       → auto-expanded with synonyms
        3. text_contains_exact: ["Pay"] → old-style exact substring (no expansion)
    """
    selector: str = ""
    text_contains: list[str] = Field(default_factory=list)
    intent: str = ""  # Smart intent: "payment", "delete", "admin", etc.
    element_tag: str = ""
    element_type: str = ""
    on_pages: str = ""  # URL pattern where this rule applies
    risk: RiskLevel = RiskLevel.NONE
    decision: Decision = Decision.BLOCK
    phonetic: bool = True  # Enable phonetic matching (typo/variant detection)
    semantic: bool = True   # Enable NLP semantic matching (novel phrasings)
    _expanded: bool = False  # Internal: whether text_contains was already expanded

    model_config = {"arbitrary_types_allowed": True}

    def _get_effective_keywords(self) -> list[str]:
        """Get the full keyword list after smart expansion."""
        keywords = []
        # Intent-based: pull all synonyms for that intent
        if self.intent:
            keywords.extend(INTENT_SYNONYMS.get(self.intent.lower(), []))
        # text_contains: auto-expand through synonym groups
        if self.text_contains:
            keywords.extend(expand_keywords(self.text_contains))
        return keywords

    def matches(self, event: ActionEvent) -> bool:
        """Check if an action event matches this element rule (smart matching)."""
        # Check page restriction
        if self.on_pages:
            regex = self.on_pages.replace("*", ".*")
            if not re.search(regex, event.url, re.IGNORECASE):
                return False

        # Check selector match
        if self.selector and self.selector.lower() not in event.selector.lower():
            if self.selector.lower() not in event.element_id.lower():
                return False

        # Check text content — SMART matching with phonetic fallback
        effective_keywords = self._get_effective_keywords()
        if effective_keywords:
            text_lower = event.element_text.lower()
            selector_lower = event.selector.lower()
            combined = f"{text_lower} {selector_lower}"

            # 1) Exact substring match (fast path)
            exact_hit = any(kw.lower() in combined for kw in effective_keywords)

            if not exact_hit:
                # 2) Phonetic fallback — catches typos & morphological variants
                phon_hit = False
                if self.phonetic:
                    phon_hit, _ = phonetic_match_keywords(
                        effective_keywords, combined
                    )

                if not phon_hit:
                    # 3) Semantic NLP fallback — catches novel phrasings
                    if self.semantic and self.intent:
                        if not semantic_matches_intent(
                            self.intent, combined, threshold=0.65
                        ):
                            return False
                    else:
                        return False

        # Check element tag
        if self.element_tag and self.element_tag.lower() != event.element_tag.lower():
            return False

        # Check element type
        if self.element_type and self.element_type.lower() != event.element_type.lower():
            return False

        return True


class ActionRule(BaseModel):
    """A complete rule for a specific action type."""
    action: ActionType
    allow_urls: list[URLRule] = Field(default_factory=list)
    block_urls: list[URLRule] = Field(default_factory=list)
    block_elements: list[ElementRule] = Field(default_factory=list)
    require_approval_elements: list[ElementRule] = Field(default_factory=list)
    allow_elements: list[ElementRule] = Field(default_factory=list)
    block_risk_above: RiskLevel = RiskLevel.NONE  # Block if risk >= this level
    require_approval_risk_above: RiskLevel = RiskLevel.NONE


# ---------------------------------------------------------------------------
# Policy definition
# ---------------------------------------------------------------------------

class Policy(BaseModel):
    """A complete policy defining what an agent can and cannot do."""
    name: str
    description: str = ""
    version: str = "1.0"
    enabled: bool = True
    rules: list[ActionRule] = Field(default_factory=list)

    # Global settings
    default_decision: Decision = Decision.ALLOW
    block_all_downloads: bool = False
    block_all_uploads: bool = False
    block_js_evaluation: bool = True
    block_clipboard: bool = False
    max_actions_per_minute: int = 0  # 0 = unlimited
    allowed_domains: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        """Load a policy from a YAML file."""
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls._from_dict(data)

    @classmethod
    def from_yaml_string(cls, yaml_string: str) -> Policy:
        """Load a policy from a YAML string."""
        data = yaml.safe_load(yaml_string)
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Policy:
        """Parse a policy from a dictionary (loaded from YAML).

        Supports two YAML formats:

        **Format A (action-grouped rules):**
            rules:
              - action: click
                block_elements:
                  - text_contains: ["Pay"]

        **Format B (type-grouped rules — OpenClaw style):**
            url_rules:
              - pattern: ".*/admin/.*"
                decision: block
            element_rules:
              - text_pattern: "(?i)(pay|delete)"
                decision: block
            action_rules:
              - action_type: evaluate_js
                decision: block
        """
        rules: list[ActionRule] = []

        # -----------------------------------------------------------
        # Format A: action-grouped rules (standard format)
        # -----------------------------------------------------------
        for rule_data in data.get("rules", []):
            action_type = ActionType(rule_data["action"])

            # Parse URL rules
            allow_urls = [
                URLRule(pattern=u["pattern"], decision=Decision.ALLOW)
                for u in rule_data.get("allow", [])
                if "pattern" in u
            ]
            block_urls = [
                URLRule(pattern=u["pattern"], decision=Decision.BLOCK)
                for u in rule_data.get("block", [])
                if "pattern" in u
            ]

            # Parse element rules
            block_elements = []
            for elem in rule_data.get("block_elements", []):
                block_elements.append(ElementRule(
                    selector=elem.get("selector", ""),
                    text_contains=elem.get("text_contains", []),
                    intent=elem.get("intent", ""),
                    element_tag=elem.get("element_tag", ""),
                    element_type=elem.get("element_type", ""),
                    on_pages=elem.get("on_pages", ""),
                    risk=RiskLevel(elem.get("risk", "none").lower()),
                    decision=Decision.BLOCK,
                ))

            require_approval_elements = []
            for elem in rule_data.get("require_approval", []):
                require_approval_elements.append(ElementRule(
                    selector=elem.get("selector", ""),
                    text_contains=elem.get("text_contains", []),
                    intent=elem.get("intent", ""),
                    element_tag=elem.get("element_tag", ""),
                    on_pages=elem.get("on_pages", ""),
                    risk=RiskLevel(elem.get("risk", "none").lower()),
                    decision=Decision.REQUIRE_APPROVAL,
                ))

            rules.append(ActionRule(
                action=action_type,
                allow_urls=allow_urls,
                block_urls=block_urls,
                block_elements=block_elements,
                require_approval_elements=require_approval_elements,
                block_risk_above=RiskLevel(
                    rule_data.get("block_risk_above", "none").lower()
                ),
                require_approval_risk_above=RiskLevel(
                    rule_data.get("require_approval_risk_above", "none").lower()
                ),
            ))

        # -----------------------------------------------------------
        # Format B: type-grouped rules (OpenClaw / alternative style)
        # -----------------------------------------------------------

        # url_rules → convert to navigate ActionRules
        for url_rule_data in data.get("url_rules", []):
            pattern = url_rule_data.get("pattern", "")
            decision_str = url_rule_data.get("decision", "block").lower()
            decision = Decision(decision_str) if decision_str in [d.value for d in Decision] else Decision.BLOCK

            if decision == Decision.BLOCK:
                rules.append(ActionRule(
                    action=ActionType.NAVIGATE,
                    block_urls=[URLRule(pattern=pattern, decision=Decision.BLOCK)],
                ))
            elif decision == Decision.ALLOW:
                rules.append(ActionRule(
                    action=ActionType.NAVIGATE,
                    allow_urls=[URLRule(pattern=pattern, decision=Decision.ALLOW)],
                ))

        # element_rules → convert to click ActionRules with text_contains
        # These apply to click actions since they match on element text
        element_block_elements: list[ElementRule] = []
        element_approval_elements: list[ElementRule] = []
        for elem_data in data.get("element_rules", []):
            text_pattern = elem_data.get("text_pattern", "")
            decision_str = elem_data.get("decision", "block").lower()

            # Extract keywords from regex pattern for text_contains matching
            # Pattern like (?i)(pay|delete|remove) → ["pay", "delete", "remove"]
            keywords = cls._extract_keywords_from_pattern(text_pattern)

            elem_rule = ElementRule(
                text_contains=keywords,
                risk=RiskLevel(elem_data.get("risk", "high").lower())
                    if elem_data.get("risk") else RiskLevel.HIGH,
                decision=Decision(decision_str) if decision_str in [d.value for d in Decision] else Decision.BLOCK,
            )

            if decision_str == "require_approval":
                element_approval_elements.append(elem_rule)
            else:
                element_block_elements.append(elem_rule)

        if element_block_elements or element_approval_elements:
            rules.append(ActionRule(
                action=ActionType.CLICK,
                block_elements=element_block_elements,
                require_approval_elements=element_approval_elements,
            ))

        # action_rules → convert to ActionRules for specific action types
        for action_data in data.get("action_rules", []):
            action_type_str = action_data.get("action_type", "")
            decision_str = action_data.get("decision", "block").lower()

            try:
                action_type = ActionType(action_type_str)
            except ValueError:
                continue  # Skip unknown action types

            # Map to global policy flags for common cases
            # These are handled as rules with block_risk_above=none (block everything)
            if decision_str == "block":
                rules.append(ActionRule(
                    action=action_type,
                    block_risk_above=RiskLevel.LOW,  # Block all risk levels
                ))
            elif decision_str == "require_approval":
                rules.append(ActionRule(
                    action=action_type,
                    require_approval_risk_above=RiskLevel.LOW,
                ))

        # -----------------------------------------------------------
        # Handle rate_limit from Format B
        # -----------------------------------------------------------
        rate_limit = data.get("rate_limit", {})
        max_actions = rate_limit.get(
            "max_actions_per_minute",
            data.get("max_actions_per_minute", 0),
        )

        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            enabled=data.get("enabled", True),
            rules=rules,
            default_decision=Decision(data.get("default_decision", "allow").lower()),
            block_all_downloads=data.get("block_all_downloads", False),
            block_all_uploads=data.get("block_all_uploads", False),
            block_js_evaluation=data.get("block_js_evaluation", True),
            block_clipboard=data.get("block_clipboard", False),
            max_actions_per_minute=max_actions,
            allowed_domains=data.get("allowed_domains", []),
            blocked_domains=data.get("blocked_domains", []),
        )

    @classmethod
    def _extract_keywords_from_pattern(cls, pattern: str) -> list[str]:
        """Extract keyword list from a regex pattern.

        Handles common patterns like:
            (?i)(pay|delete|remove) → ["pay", "delete", "remove"]
            (?i)(sign.?in|sign.?up) → ["sign in", "sign up"]
        """
        import re as _re
        # Remove flags like (?i)
        cleaned = _re.sub(r'\(\?[imsx]+\)', '', pattern)
        # Remove outer parens
        cleaned = cleaned.strip('()')
        # Split on | (alternation)
        parts = [p.strip() for p in cleaned.split('|') if p.strip()]
        # Replace regex wildcards with spaces for readability
        keywords = []
        for part in parts:
            # Replace .? .* .+ with space (for patterns like sign.?in)
            kw = _re.sub(r'\.\??|\.\*|\.\+', ' ', part)
            # Remove remaining regex metacharacters
            kw = _re.sub(r'[\\^$*+?{}[\]|()]', '', kw)
            kw = kw.strip()
            if kw:
                keywords.append(kw)
        return keywords

    def to_yaml(self) -> str:
        """Serialize the policy to YAML."""
        return yaml.dump(self.model_dump(), default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Policy Engine — the evaluator
# ---------------------------------------------------------------------------

RISK_ORDER = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def _stamp_decision(decision: PolicyDecision, event: ActionEvent) -> PolicyDecision:
    """Attach the event's tier + principal to a decision if not set.

    Per-policy branches construct decisions without knowing about the
    tier/principal on the event.  We stamp them at the exit point so
    every ``PolicyDecision`` returned from the engine carries both
    fields — the evidence chain needs them.
    """
    if decision.tier is None and event.tier is not None:
        decision.tier = event.tier
    elif decision.tier is None:
        decision.tier = event.resolved_tier
    if not decision.principal and event.principal is not None:
        decision.principal = str(event.resolved_principal)
    return decision


class PolicyEngine:
    """
    Evaluates action events against loaded policies.

    Usage:
        engine = PolicyEngine()
        engine.load_policy(Policy.from_yaml("policies/finance-safe.yaml"))
        decision = engine.evaluate(action_event)

        if decision.is_blocked:
            # Prevent the action
            ...
    """

    def __init__(self) -> None:
        self._policies: list[Policy] = []
        self._action_counts: dict[str, list[float]] = {}  # agent_id -> timestamps

    def load_policy(self, policy: Policy) -> None:
        """Load a policy into the engine."""
        # License check: enforce max_policies limit
        from praxis.licensing.license_manager import LicenseManager
        lm = LicenseManager()
        lm.check_policy_count(len(self._policies))

        self._policies.append(policy)

    def load_policies_from_dir(self, directory: str | Path) -> int:
        """Load all YAML policy files from a directory. Returns count loaded."""
        directory = Path(directory)
        count = 0
        for yaml_file in directory.glob("*.yaml"):
            policy = Policy.from_yaml(yaml_file)
            self.load_policy(policy)
            count += 1
        for yml_file in directory.glob("*.yml"):
            policy = Policy.from_yaml(yml_file)
            self.load_policy(policy)
            count += 1
        return count

    def clear_policies(self) -> None:
        """Remove all loaded policies."""
        self._policies.clear()

    def evaluate(self, event: ActionEvent) -> PolicyDecision:
        """
        Evaluate an action event against all loaded policies.

        The most restrictive decision wins:
        BLOCK > REQUIRE_APPROVAL > LOG_ONLY > ALLOW
        """
        risk = classify_risk(event)

        # ------------------------------------------------------------------
        # Praxis Phase 1: principal + tier gate
        # ------------------------------------------------------------------
        # Runs BEFORE per-policy rules so tier/principal decisions are
        # deterministic regardless of what YAML policies are loaded.  A
        # per-policy rule can escalate a T0 to BLOCK, but it can never
        # take a T3 the tier gate refused and turn it into ALLOW.
        tier_decision = self._tier_gate(event, risk)
        if tier_decision is not None and tier_decision.decision == Decision.BLOCK:
            # Hard block from tier gate short-circuits: no policy can
            # unblock a T3 or an unknown principal.
            return tier_decision

        decisions: list[PolicyDecision] = []
        if tier_decision is not None:
            decisions.append(tier_decision)

        for policy in self._policies:
            if not policy.enabled:
                continue
            decision = self._evaluate_single_policy(event, policy, risk)
            decisions.append(decision)

        if not decisions:
            return _stamp_decision(
                PolicyDecision(
                    decision=Decision.ALLOW,
                    risk_level=risk,
                    reason="No policies loaded",
                    action_fingerprint=event.fingerprint,
                ),
                event,
            )

        # Most restrictive wins
        priority = {
            Decision.BLOCK: 4,
            Decision.REQUIRE_APPROVAL: 3,
            Decision.LOG_ONLY: 2,
            Decision.ALLOW: 1,
        }
        decisions.sort(key=lambda d: priority.get(d.decision, 0), reverse=True)
        return _stamp_decision(decisions[0], event)

    # ------------------------------------------------------------------
    # Tier gate — Praxis Phase 1
    # ------------------------------------------------------------------

    def _tier_gate(
        self, event: ActionEvent, risk: RiskLevel
    ) -> PolicyDecision | None:
        """Apply the tier x principal decision matrix.

        Delegates to :func:`praxis.policy.tier_gate.apply_tier_gate`
        so the browser and filesystem engines stay in lockstep.

        The gate is **opt-in**: it only fires when the caller has
        explicitly attached a ``principal`` to the event.  Legacy
        browser-interceptor code paths that construct an
        ``ActionEvent`` with no principal are left untouched to keep
        the existing test suite passing while Phase 2 code migrates
        callers over.
        """
        if event.principal is None:
            return None
        from praxis.policy.tier_gate import apply_tier_gate

        return apply_tier_gate(
            principal=event.resolved_principal,
            tier=event.resolved_tier,
            fingerprint=event.fingerprint,
        )

    def _evaluate_single_policy(
        self, event: ActionEvent, policy: Policy, risk: RiskLevel
    ) -> PolicyDecision:
        """Evaluate an event against a single policy."""

        # --- Global checks first ---

        # Rate limiting
        if policy.max_actions_per_minute > 0:
            if self._check_rate_limit(event.agent_id, policy.max_actions_per_minute):
                return PolicyDecision(
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel.HIGH,
                    matched_rule="rate_limit",
                    reason=f"Rate limit exceeded: {policy.max_actions_per_minute}/min",
                    policy_name=policy.name,
                    action_fingerprint=event.fingerprint,
                )

        # Domain restrictions
        if policy.allowed_domains:
            if not self._domain_matches(event.url, policy.allowed_domains):
                return PolicyDecision(
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel.HIGH,
                    matched_rule="domain_allowlist",
                    reason=f"Domain not in allowlist",
                    policy_name=policy.name,
                    action_fingerprint=event.fingerprint,
                )

        if policy.blocked_domains:
            if self._domain_matches(event.url, policy.blocked_domains):
                return PolicyDecision(
                    decision=Decision.BLOCK,
                    risk_level=RiskLevel.HIGH,
                    matched_rule="domain_blocklist",
                    reason=f"Domain is blocked",
                    policy_name=policy.name,
                    action_fingerprint=event.fingerprint,
                )

        # Global action blocks
        if policy.block_all_downloads and event.action_type == ActionType.DOWNLOAD:
            return PolicyDecision(
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                matched_rule="block_all_downloads",
                reason="Downloads are blocked by policy",
                policy_name=policy.name,
                action_fingerprint=event.fingerprint,
            )

        if policy.block_all_uploads and event.action_type == ActionType.UPLOAD:
            return PolicyDecision(
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                matched_rule="block_all_uploads",
                reason="Uploads are blocked by policy",
                policy_name=policy.name,
                action_fingerprint=event.fingerprint,
            )

        if policy.block_js_evaluation and event.action_type == ActionType.EVALUATE_JS:
            return PolicyDecision(
                decision=Decision.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                matched_rule="block_js_evaluation",
                reason="JavaScript evaluation is blocked by policy",
                policy_name=policy.name,
                action_fingerprint=event.fingerprint,
            )

        if policy.block_clipboard and event.action_type == ActionType.COPY:
            return PolicyDecision(
                decision=Decision.BLOCK,
                risk_level=RiskLevel.MEDIUM,
                matched_rule="block_clipboard",
                reason="Clipboard access is blocked by policy",
                policy_name=policy.name,
                action_fingerprint=event.fingerprint,
            )

        # --- Rule-level checks ---
        for rule in policy.rules:
            if rule.action != event.action_type:
                continue

            # Check blocked URLs
            for url_rule in rule.block_urls:
                if url_rule.matches(event.url):
                    return PolicyDecision(
                        decision=Decision.BLOCK,
                        risk_level=risk,
                        matched_rule=f"block_url:{url_rule.pattern}",
                        reason=f"URL blocked by pattern: {url_rule.pattern}",
                        policy_name=policy.name,
                        action_fingerprint=event.fingerprint,
                    )

            # Check blocked elements
            for elem_rule in rule.block_elements:
                if elem_rule.matches(event):
                    return PolicyDecision(
                        decision=Decision.BLOCK,
                        risk_level=risk if risk != RiskLevel.LOW else RiskLevel.HIGH,
                        matched_rule=f"block_element:{elem_rule.selector or elem_rule.text_contains}",
                        reason=f"Element blocked: {elem_rule.selector or elem_rule.text_contains}",
                        policy_name=policy.name,
                        action_fingerprint=event.fingerprint,
                    )

            # Check risk-level blocks
            if rule.block_risk_above != RiskLevel.NONE:
                if RISK_ORDER[risk] >= RISK_ORDER[rule.block_risk_above]:
                    return PolicyDecision(
                        decision=Decision.BLOCK,
                        risk_level=risk,
                        matched_rule=f"risk_level:{risk.value}>={rule.block_risk_above.value}",
                        reason=f"Risk level {risk.value} exceeds threshold {rule.block_risk_above.value}",
                        policy_name=policy.name,
                        action_fingerprint=event.fingerprint,
                    )

            # Check require-approval elements
            for elem_rule in rule.require_approval_elements:
                if elem_rule.matches(event):
                    return PolicyDecision(
                        decision=Decision.REQUIRE_APPROVAL,
                        risk_level=risk,
                        matched_rule=f"require_approval:{elem_rule.selector or elem_rule.text_contains}",
                        reason=f"Approval required: {elem_rule.selector or elem_rule.text_contains}",
                        policy_name=policy.name,
                        action_fingerprint=event.fingerprint,
                    )

            # Check risk-level approval requirements
            if rule.require_approval_risk_above != RiskLevel.NONE:
                if RISK_ORDER[risk] >= RISK_ORDER[rule.require_approval_risk_above]:
                    return PolicyDecision(
                        decision=Decision.REQUIRE_APPROVAL,
                        risk_level=risk,
                        matched_rule=f"risk_approval:{risk.value}>={rule.require_approval_risk_above.value}",
                        reason=f"Approval required: risk {risk.value}",
                        policy_name=policy.name,
                        action_fingerprint=event.fingerprint,
                    )

            # Check allowed URLs (if specified, only these are allowed)
            if rule.allow_urls:
                if not any(u.matches(event.url) for u in rule.allow_urls):
                    return PolicyDecision(
                        decision=Decision.BLOCK,
                        risk_level=risk,
                        matched_rule="url_not_in_allowlist",
                        reason="URL not in allowed list for this action type",
                        policy_name=policy.name,
                        action_fingerprint=event.fingerprint,
                    )

        # Default decision
        return PolicyDecision(
            decision=policy.default_decision,
            risk_level=risk,
            matched_rule="default",
            reason=f"Default policy decision: {policy.default_decision.value}",
            policy_name=policy.name,
            action_fingerprint=event.fingerprint,
        )

    def _check_rate_limit(self, agent_id: str, max_per_minute: int) -> bool:
        """Check if an agent has exceeded its rate limit."""
        now = time.time()
        if agent_id not in self._action_counts:
            self._action_counts[agent_id] = []

        # Clean old entries
        self._action_counts[agent_id] = [
            ts for ts in self._action_counts[agent_id] if now - ts < 60
        ]
        self._action_counts[agent_id].append(now)

        return len(self._action_counts[agent_id]) > max_per_minute

    @staticmethod
    def _domain_matches(url: str, domains: list[str]) -> bool:
        """Check if a URL's domain matches any in the list."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            return any(
                hostname == d or hostname.endswith(f".{d}")
                for d in domains
            )
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Preset policies for common use cases
# ---------------------------------------------------------------------------

def create_finance_safe_policy() -> Policy:
    """Pre-built policy: allow reading financial data, block all payments."""
    return Policy.from_yaml_string("""
name: finance-safe
description: Allow reading financial data, block all payment actions
version: "1.0"
block_all_downloads: false
block_js_evaluation: true
block_clipboard: true
rules:
  - action: navigate
    block:
      - pattern: "*/admin/*"
      - pattern: "*/settings/*"
  - action: click
    block_elements:
      - text_contains: ["Pay", "Transfer", "Wire", "Send Money"]
        risk: high
      - text_contains: ["Delete", "Remove", "Purge"]
        risk: high
      - selector: "button[type='submit']"
        on_pages: "*/payments/*"
    require_approval:
      - text_contains: ["Submit", "Confirm", "Approve"]
        risk: medium
  - action: type
    block_elements:
      - selector: "input[name='credit_card']"
      - selector: "input[name='card_number']"
      - selector: "input[type='password']"
""")


def create_readonly_policy() -> Policy:
    """Pre-built policy: read-only — block all mutations."""
    return Policy.from_yaml_string("""
name: readonly
description: Read-only mode — no clicks, no typing, no downloads
version: "1.0"
block_all_downloads: true
block_all_uploads: true
block_js_evaluation: true
block_clipboard: true
rules:
  - action: click
    block_risk_above: low
  - action: type
    block_risk_above: none
  - action: submit
    block_risk_above: none
""")


def create_permissive_policy() -> Policy:
    """Pre-built policy: allow most things, block only critical actions."""
    return Policy.from_yaml_string("""
name: permissive
description: Allow most actions, block only critical-risk operations
version: "1.0"
block_js_evaluation: true
rules:
  - action: click
    block_risk_above: critical
    require_approval_risk_above: high
  - action: type
    block_elements:
      - selector: "input[type='password']"
  - action: navigate
    block:
      - pattern: "*/admin/*"
""")


# ---------------------------------------------------------------------------
# Preset policy registry
# ---------------------------------------------------------------------------

PRESET_POLICIES: dict[str, callable] = {
    "finance-safe": create_finance_safe_policy,
    "readonly": create_readonly_policy,
    "permissive": create_permissive_policy,
}
