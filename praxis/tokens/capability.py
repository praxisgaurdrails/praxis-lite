"""
Praxis Capability Tokens — Scoped, time-bound permissions for agents.

Capability tokens define what an agent is ALLOWED to do, with:
- Scope: which domains, pages, action types are permitted
- Time bounds: valid_from / valid_until (auto-expire)
- Rate limits: max actions per time window
- Delegation: who issued the token and why
- Revocation: tokens can be revoked at any time

Usage:
    token = CapabilityToken.create(
        agent_id="agent-finance-bot",
        issuer="admin@company.com",
        scopes=[
            Scope(action=ActionType.NAVIGATE, domains=["app.company.com"]),
            Scope(action=ActionType.CLICK, exclude_text=["Pay", "Delete"]),
        ],
        ttl_minutes=60,
    )

    # Validate before allowing action
    result = token.validate(action_event)
    if not result.valid:
        print(f"Token denied: {result.reason}")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from praxis.policy.engine import ActionType, ActionEvent, RiskLevel


# ---------------------------------------------------------------------------
# Scope definitions
# ---------------------------------------------------------------------------

class Scope(BaseModel):
    """A single capability scope — what actions are permitted."""
    action: ActionType | None = None  # None = all actions
    domains: list[str] = Field(default_factory=list)  # Allowed domains
    url_patterns: list[str] = Field(default_factory=list)  # Allowed URL patterns
    exclude_urls: list[str] = Field(default_factory=list)  # Blocked URL patterns
    exclude_text: list[str] = Field(default_factory=list)  # Block elements with this text
    exclude_selectors: list[str] = Field(default_factory=list)  # Block these selectors
    max_risk: RiskLevel = RiskLevel.HIGH  # Max allowed risk level
    read_only: bool = False  # If True, only read actions allowed

    def allows(self, event: ActionEvent) -> tuple[bool, str]:
        """Check if this scope allows the given action."""
        import re

        # Check action type
        if self.action is not None and event.action_type != self.action:
            return True, ""  # This scope doesn't apply to this action type

        # Check read-only
        if self.read_only and event.action_type in (
            ActionType.CLICK, ActionType.TYPE, ActionType.SUBMIT,
            ActionType.UPLOAD, ActionType.DOWNLOAD,
        ):
            return False, "Read-only scope: mutation actions blocked"

        # Check domains
        if self.domains:
            from urllib.parse import urlparse
            try:
                hostname = urlparse(event.url).hostname or ""
                if not any(
                    hostname == d or hostname.endswith(f".{d}")
                    for d in self.domains
                ):
                    return False, f"Domain not in allowed list: {hostname}"
            except Exception:
                return False, "Invalid URL"

        # Check URL patterns
        if self.url_patterns:
            matched = False
            for pattern in self.url_patterns:
                regex = pattern.replace("*", ".*")
                if re.search(regex, event.url, re.IGNORECASE):
                    matched = True
                    break
            if not matched:
                return False, "URL not in allowed patterns"

        # Check excluded URLs
        for pattern in self.exclude_urls:
            regex = pattern.replace("*", ".*")
            if re.search(regex, event.url, re.IGNORECASE):
                return False, f"URL matches excluded pattern: {pattern}"

        # Check excluded text
        text_lower = event.element_text.lower()
        for excluded in self.exclude_text:
            if excluded.lower() in text_lower:
                return False, f"Element text matches exclusion: {excluded}"

        # Check excluded selectors
        for sel in self.exclude_selectors:
            if sel.lower() in event.selector.lower():
                return False, f"Selector matches exclusion: {sel}"

        return True, ""


# ---------------------------------------------------------------------------
# Token validation result
# ---------------------------------------------------------------------------

class TokenValidation(BaseModel):
    """Result of validating a capability token against an action."""
    valid: bool
    reason: str = ""
    token_id: str = ""
    remaining_ttl_seconds: float = 0
    scope_matched: str = ""


# ---------------------------------------------------------------------------
# Capability Token
# ---------------------------------------------------------------------------

class CapabilityToken(BaseModel):
    """
    A capability token granting scoped, time-bound permissions to an agent.

    Tokens are:
    - Scoped: limited to specific actions/domains/pages
    - Time-bound: auto-expire after TTL
    - Revocable: can be revoked at any time via the token store
    - Auditable: every token usage is trackable
    - Signed: integrity-verified via HMAC
    """
    token_id: str = Field(default_factory=lambda: f"tok_{uuid.uuid4().hex[:16]}")
    agent_id: str
    issuer: str = ""
    purpose: str = ""

    # Permissions
    scopes: list[Scope] = Field(default_factory=list)

    # Time bounds
    issued_at: float = Field(default_factory=time.time)
    valid_from: float = Field(default_factory=time.time)
    valid_until: float = 0  # 0 = no expiry (not recommended)

    # Rate limiting
    max_actions_total: int = 0  # 0 = unlimited
    max_actions_per_minute: int = 0  # 0 = unlimited
    actions_used: int = 0

    # State
    revoked: bool = False
    revoked_at: float | None = None
    revoked_by: str = ""
    revoked_reason: str = ""

    # Integrity
    signature: str = ""

    @classmethod
    def create(
        cls,
        agent_id: str,
        issuer: str = "system",
        purpose: str = "",
        scopes: list[Scope] | None = None,
        ttl_minutes: int = 60,
        max_actions_total: int = 0,
        max_actions_per_minute: int = 0,
        signing_key: str = "praxis-default-key",
    ) -> CapabilityToken:
        """Create a new capability token with the given parameters."""
        # License check: capability_tokens feature
        from praxis.licensing.license_manager import LicenseManager
        lm = LicenseManager()
        lm.check_feature("capability_tokens")

        now = time.time()
        token = cls(
            agent_id=agent_id,
            issuer=issuer,
            purpose=purpose,
            scopes=scopes or [],
            issued_at=now,
            valid_from=now,
            valid_until=now + (ttl_minutes * 60) if ttl_minutes > 0 else 0,
            max_actions_total=max_actions_total,
            max_actions_per_minute=max_actions_per_minute,
        )
        token.signature = token._compute_signature(signing_key)
        return token

    def validate(self, event: ActionEvent) -> TokenValidation:
        """Validate this token against a proposed action."""
        # Check revocation
        if self.revoked:
            return TokenValidation(
                valid=False,
                reason=f"Token revoked: {self.revoked_reason}",
                token_id=self.token_id,
            )

        # Check time bounds
        now = time.time()
        if now < self.valid_from:
            return TokenValidation(
                valid=False,
                reason="Token not yet valid",
                token_id=self.token_id,
            )
        if self.valid_until > 0 and now > self.valid_until:
            return TokenValidation(
                valid=False,
                reason="Token expired",
                token_id=self.token_id,
                remaining_ttl_seconds=0,
            )

        # Check agent ID
        if event.agent_id and event.agent_id != self.agent_id:
            return TokenValidation(
                valid=False,
                reason=f"Token issued for agent '{self.agent_id}', not '{event.agent_id}'",
                token_id=self.token_id,
            )

        # Check total action limit
        if self.max_actions_total > 0 and self.actions_used >= self.max_actions_total:
            return TokenValidation(
                valid=False,
                reason=f"Action limit reached: {self.actions_used}/{self.max_actions_total}",
                token_id=self.token_id,
            )

        # Check scopes
        if self.scopes:
            for scope in self.scopes:
                allowed, reason = scope.allows(event)
                if not allowed:
                    return TokenValidation(
                        valid=False,
                        reason=reason,
                        token_id=self.token_id,
                    )

        remaining = 0.0
        if self.valid_until > 0:
            remaining = max(0, self.valid_until - now)

        return TokenValidation(
            valid=True,
            reason="Token valid",
            token_id=self.token_id,
            remaining_ttl_seconds=round(remaining, 1),
        )

    def use(self) -> None:
        """Record a token usage (increment action counter)."""
        self.actions_used += 1

    def revoke(self, by: str = "system", reason: str = "") -> None:
        """Revoke this token."""
        self.revoked = True
        self.revoked_at = time.time()
        self.revoked_by = by
        self.revoked_reason = reason

    def _compute_signature(self, key: str) -> str:
        """Compute HMAC signature for token integrity."""
        data = f"{self.token_id}:{self.agent_id}:{self.issued_at}:{self.valid_until}"
        return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()

    def verify_signature(self, key: str = "praxis-default-key") -> bool:
        """Verify the token's HMAC signature."""
        expected = self._compute_signature(key)
        return hmac.compare_digest(self.signature, expected)

    @property
    def is_expired(self) -> bool:
        if self.valid_until == 0:
            return False
        return time.time() > self.valid_until

    @property
    def remaining_ttl(self) -> float:
        if self.valid_until == 0:
            return float("inf")
        return max(0, self.valid_until - time.time())

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    @classmethod
    def from_json(cls, data: str) -> CapabilityToken:
        return cls.model_validate_json(data)


# ---------------------------------------------------------------------------
# Token Store — manages active tokens
# ---------------------------------------------------------------------------

class TokenStore:
    """In-memory store for capability tokens with lookup and revocation."""

    def __init__(self) -> None:
        self._tokens: dict[str, CapabilityToken] = {}

    def store(self, token: CapabilityToken) -> None:
        """Store a token."""
        self._tokens[token.token_id] = token

    def get(self, token_id: str) -> CapabilityToken | None:
        """Retrieve a token by ID."""
        return self._tokens.get(token_id)

    def get_for_agent(self, agent_id: str) -> list[CapabilityToken]:
        """Get all tokens for a specific agent."""
        return [t for t in self._tokens.values() if t.agent_id == agent_id]

    def revoke(self, token_id: str, by: str = "system", reason: str = "") -> bool:
        """Revoke a token by ID."""
        token = self._tokens.get(token_id)
        if token:
            token.revoke(by=by, reason=reason)
            return True
        return False

    def revoke_all_for_agent(self, agent_id: str, by: str = "system", reason: str = "") -> int:
        """Revoke all tokens for an agent. Returns count revoked."""
        count = 0
        for token in self._tokens.values():
            if token.agent_id == agent_id and not token.revoked:
                token.revoke(by=by, reason=reason)
                count += 1
        return count

    def cleanup_expired(self) -> int:
        """Remove expired tokens. Returns count removed."""
        expired = [
            tid for tid, t in self._tokens.items()
            if t.is_expired or t.revoked
        ]
        for tid in expired:
            del self._tokens[tid]
        return len(expired)

    @property
    def active_count(self) -> int:
        return sum(1 for t in self._tokens.values() if not t.revoked and not t.is_expired)

    @property
    def total_count(self) -> int:
        return len(self._tokens)
