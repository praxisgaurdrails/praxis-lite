"""Tests for Praxis Capability Tokens."""

import time

import pytest

from praxis.tokens.capability import (
    CapabilityToken,
    Scope,
    TokenStore,
    TokenValidation,
)
from praxis.policy.engine import ActionEvent, ActionType, RiskLevel


def make_event(
    action=ActionType.CLICK,
    url="https://app.example.com/page",
    text="Button",
    agent_id="test-agent",
):
    return ActionEvent(
        action_type=action,
        url=url,
        element_text=text,
        agent_id=agent_id,
    )


class TestCapabilityToken:
    def test_create_token(self):
        token = CapabilityToken.create(
            agent_id="agent-1",
            issuer="admin",
            ttl_minutes=60,
        )
        assert token.agent_id == "agent-1"
        assert token.issuer == "admin"
        assert token.token_id.startswith("tok_")
        assert not token.is_expired

    def test_token_expiry(self):
        token = CapabilityToken.create(
            agent_id="agent-1",
            ttl_minutes=0,  # no expiry
        )
        # With ttl_minutes=0, valid_until will be set to now
        # Actually let's test a very short TTL
        token2 = CapabilityToken.create(
            agent_id="agent-1",
            ttl_minutes=1,
        )
        assert not token2.is_expired
        assert token2.remaining_ttl > 0

    def test_token_revocation(self):
        token = CapabilityToken.create(agent_id="agent-1", ttl_minutes=60)
        assert not token.revoked

        token.revoke(by="admin", reason="Security concern")
        assert token.revoked
        assert token.revoked_by == "admin"

        result = token.validate(make_event())
        assert not result.valid
        assert "revoked" in result.reason.lower()

    def test_domain_scope(self):
        token = CapabilityToken.create(
            agent_id="test-agent",
            scopes=[Scope(domains=["app.example.com"])],
            ttl_minutes=60,
        )

        # Allowed domain
        result = token.validate(make_event(url="https://app.example.com/page"))
        assert result.valid

        # Blocked domain
        result = token.validate(make_event(url="https://evil.com/page"))
        assert not result.valid

    def test_exclude_text_scope(self):
        token = CapabilityToken.create(
            agent_id="test-agent",
            scopes=[Scope(exclude_text=["Pay", "Delete"])],
            ttl_minutes=60,
        )

        # Allowed text
        result = token.validate(make_event(text="View Invoice"))
        assert result.valid

        # Blocked text
        result = token.validate(make_event(text="Pay Now"))
        assert not result.valid

    def test_action_limit(self):
        token = CapabilityToken.create(
            agent_id="test-agent",
            max_actions_total=2,
            ttl_minutes=60,
        )

        result1 = token.validate(make_event())
        assert result1.valid
        token.use()

        result2 = token.validate(make_event())
        assert result2.valid
        token.use()

        # Third action should fail
        result3 = token.validate(make_event())
        assert not result3.valid
        assert "limit" in result3.reason.lower()

    def test_agent_id_mismatch(self):
        token = CapabilityToken.create(agent_id="agent-1", ttl_minutes=60)

        result = token.validate(make_event(agent_id="agent-2"))
        assert not result.valid
        assert "agent" in result.reason.lower()

    def test_signature_verification(self):
        token = CapabilityToken.create(agent_id="agent-1", ttl_minutes=60)
        assert token.verify_signature()

        # Tamper with token
        token.agent_id = "hacked-agent"
        assert not token.verify_signature()

    def test_token_serialization(self):
        token = CapabilityToken.create(
            agent_id="agent-1",
            issuer="admin",
            purpose="Test",
            ttl_minutes=30,
        )
        json_str = token.to_json()
        loaded = CapabilityToken.from_json(json_str)
        assert loaded.token_id == token.token_id
        assert loaded.agent_id == token.agent_id


class TestTokenStore:
    def test_store_and_retrieve(self):
        store = TokenStore()
        token = CapabilityToken.create(agent_id="agent-1", ttl_minutes=60)
        store.store(token)

        retrieved = store.get(token.token_id)
        assert retrieved is not None
        assert retrieved.agent_id == "agent-1"

    def test_get_for_agent(self):
        store = TokenStore()
        t1 = CapabilityToken.create(agent_id="agent-1", ttl_minutes=60)
        t2 = CapabilityToken.create(agent_id="agent-1", ttl_minutes=60)
        t3 = CapabilityToken.create(agent_id="agent-2", ttl_minutes=60)

        store.store(t1)
        store.store(t2)
        store.store(t3)

        agent1_tokens = store.get_for_agent("agent-1")
        assert len(agent1_tokens) == 2

    def test_revoke_all_for_agent(self):
        store = TokenStore()
        t1 = CapabilityToken.create(agent_id="agent-1", ttl_minutes=60)
        t2 = CapabilityToken.create(agent_id="agent-1", ttl_minutes=60)
        store.store(t1)
        store.store(t2)

        count = store.revoke_all_for_agent("agent-1", reason="Emergency")
        assert count == 2

    def test_active_count(self):
        store = TokenStore()
        t1 = CapabilityToken.create(agent_id="agent-1", ttl_minutes=60)
        t2 = CapabilityToken.create(agent_id="agent-2", ttl_minutes=60)
        store.store(t1)
        store.store(t2)

        assert store.active_count == 2

        store.revoke(t1.token_id)
        assert store.active_count == 1
