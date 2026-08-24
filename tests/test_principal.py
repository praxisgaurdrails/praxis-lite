"""Tests for the Praxis principal system."""

import os
import stat
import tempfile
from pathlib import Path

import pytest

from praxis.principal import (
    Principal,
    PrincipalKind,
    PrincipalResolver,
    compute_local_response,
    ensure_local_key,
    local_key_permissions_ok,
    make_local_challenge,
    rotate_local_key,
    verify_local_response,
)
from praxis.tokens.capability import CapabilityToken, Scope


@pytest.fixture
def key_path(tmp_path):
    return tmp_path / "praxis" / "local_key"


class TestPrincipalDataclass:
    def test_local_str(self):
        p = Principal.local()
        assert str(p) == "praxis:local"
        assert p.is_local
        assert not p.is_agent

    def test_agent_str(self):
        p = Principal.agent("claude-desktop")
        assert str(p) == "agent:claude-desktop"
        assert p.is_agent

    def test_unknown_str(self):
        p = Principal.unknown()
        assert str(p) == "unknown"
        assert p.is_unknown

    def test_agent_requires_name(self):
        with pytest.raises(ValueError, match="requires a non-empty name"):
            Principal(kind=PrincipalKind.AGENT)

    def test_local_rejects_name(self):
        with pytest.raises(ValueError, match="does not take a name"):
            Principal(kind=PrincipalKind.LOCAL, name="oops")

    def test_agent_name_sanitisation_rejects_bad_chars(self):
        # Characters that could be trouble in logs / display / file
        # paths.  Dots are permitted (e.g. "claude.mac"), so
        # names like ".." are allowed by design — they're just weird
        # labels, not path components.
        for bad in [
            "claude/desktop",       # slash
            "claude desktop",       # space
            "claude:desktop",       # colon — confusable with principal delim
            "a" * 65,               # too long
            "",                     # empty
        ]:
            with pytest.raises(ValueError):
                Principal.agent(bad)

    def test_agent_name_accepts_typical_agent_ids(self):
        # Positive assertions — these must not raise.
        for good in [
            "claude-desktop",
            "openai_gpt",
            "cursor.mac",
            "langchain",
            "a",
            "AGENT_42",
        ]:
            Principal.agent(good)

    def test_frozen(self):
        p = Principal.local()
        with pytest.raises(Exception):
            p.name = "hacked"  # type: ignore[misc]


class TestLocalKey:
    def test_ensure_creates_and_persists(self, key_path):
        assert not key_path.exists()
        key = ensure_local_key(key_path)
        assert key_path.exists()
        assert len(key) == 32
        # Second call returns same bytes.
        assert ensure_local_key(key_path) == key

    def test_ensure_sets_0600_mode(self, key_path):
        ensure_local_key(key_path)
        if os.name == "posix":
            mode = stat.S_IMODE(key_path.stat().st_mode)
            assert mode == 0o600, f"expected 0600 got {oct(mode)}"

    def test_permissions_ok_check(self, key_path):
        assert not local_key_permissions_ok(key_path)  # doesn't exist yet
        ensure_local_key(key_path)
        assert local_key_permissions_ok(key_path)

    def test_permissions_ok_detects_relaxed_mode(self, key_path):
        if os.name != "posix":
            pytest.skip("posix-only")
        ensure_local_key(key_path)
        os.chmod(key_path, 0o644)
        assert not local_key_permissions_ok(key_path)

    def test_rotate_generates_new_key(self, key_path):
        old = ensure_local_key(key_path)
        new = rotate_local_key(key_path)
        assert new != old
        assert len(new) == 32
        assert key_path.read_bytes() == new


class TestChallengeResponse:
    def test_correct_response_verifies(self):
        key = os.urandom(32)
        challenge = make_local_challenge()
        response = compute_local_response(challenge, key)
        assert verify_local_response(challenge, response, key)

    def test_wrong_response_rejected(self):
        key = os.urandom(32)
        challenge = make_local_challenge()
        response = compute_local_response(challenge, key)
        # Flip a bit.
        tampered = response[:-1] + ("0" if response[-1] != "0" else "1")
        assert not verify_local_response(challenge, tampered, key)

    def test_wrong_key_rejected(self):
        key = os.urandom(32)
        other = os.urandom(32)
        challenge = make_local_challenge()
        response = compute_local_response(challenge, key)
        assert not verify_local_response(challenge, response, other)

    def test_empty_response_rejected(self):
        key = os.urandom(32)
        challenge = make_local_challenge()
        assert not verify_local_response(challenge, "", key)

    def test_challenge_is_fresh_each_time(self):
        a = make_local_challenge()
        b = make_local_challenge()
        assert a != b


class TestPrincipalResolver:
    def test_local_socket_success(self, key_path):
        resolver = PrincipalResolver(local_key_path=key_path)
        challenge = make_local_challenge()
        response = compute_local_response(challenge, resolver.local_key)
        p = resolver.from_local_socket(challenge, response)
        assert p.is_local
        assert p.proven_via == "local_socket:hmac"

    def test_local_socket_wrong_response(self, key_path):
        resolver = PrincipalResolver(local_key_path=key_path)
        challenge = make_local_challenge()
        p = resolver.from_local_socket(challenge, "0" * 64)
        assert p.is_unknown
        assert "bad_response" in p.proven_via

    def test_local_socket_empty_response(self, key_path):
        resolver = PrincipalResolver(local_key_path=key_path)
        challenge = make_local_challenge()
        p = resolver.from_local_socket(challenge, "")
        assert p.is_unknown
        assert "no_response" in p.proven_via

    def test_no_credential_is_unknown(self, key_path):
        resolver = PrincipalResolver(local_key_path=key_path)
        assert resolver.from_no_credential().is_unknown

    def test_agent_token_valid(self, key_path):
        signing = "test-signing-key"
        resolver = PrincipalResolver(
            local_key_path=key_path, token_signing_key=signing
        )
        token = CapabilityToken.create(
            agent_id="claude-desktop",
            issuer="tests",
            purpose="test",
            scopes=[Scope(read_only=True)],
            ttl_minutes=5,
            signing_key=signing,
        )
        p = resolver.from_agent_token(token)
        assert p.is_agent
        assert p.name == "claude-desktop"
        assert p.proven_via == "agent_token:verified"

    def test_agent_token_missing_returns_unknown(self, key_path):
        resolver = PrincipalResolver(local_key_path=key_path)
        p = resolver.from_agent_token(None)
        assert p.is_unknown
        assert "no token" in p.proven_via

    def test_agent_token_wrong_signature(self, key_path):
        resolver = PrincipalResolver(
            local_key_path=key_path, token_signing_key="key-A"
        )
        # Token signed with a different key.
        token = CapabilityToken.create(
            agent_id="claude-desktop",
            issuer="tests",
            ttl_minutes=5,
            signing_key="key-B",
        )
        p = resolver.from_agent_token(token)
        assert p.is_unknown
        assert "invalid signature" in p.proven_via

    def test_agent_token_revoked(self, key_path):
        signing = "test-signing-key"
        resolver = PrincipalResolver(
            local_key_path=key_path, token_signing_key=signing
        )
        token = CapabilityToken.create(
            agent_id="claude-desktop",
            issuer="tests",
            ttl_minutes=5,
            signing_key=signing,
        )
        token.revoke(by="tests", reason="unit test")
        p = resolver.from_agent_token(token)
        assert p.is_unknown
        assert "revoked" in p.proven_via

    def test_from_agent_name_trusted_transport(self, key_path):
        resolver = PrincipalResolver(local_key_path=key_path)
        p = resolver.from_agent_name("openclaw", proven_via="stdio_mcp")
        assert p.is_agent
        assert p.name == "openclaw"
        assert p.proven_via == "stdio_mcp"

    def test_tcp_caller_cannot_become_local(self, key_path):
        """The security-critical property: no path from a token to LOCAL."""
        signing = "test-signing-key"
        resolver = PrincipalResolver(
            local_key_path=key_path, token_signing_key=signing
        )
        # Even if an attacker somehow crafted a token whose agent_id looked
        # like "praxis:local" or something similarly evil, the resolver only
        # ever emits an ``agent:*`` principal from tokens.  And the colon
        # would fail the agent-name regex anyway → unknown.
        token = CapabilityToken.create(
            agent_id="claude-desktop",
            issuer="tests",
            ttl_minutes=5,
            signing_key=signing,
        )
        # Then someone edits the agent_id post-hoc (mimicking a tampered
        # token in transit).  Signature no longer matches → unknown.
        token.agent_id = "praxis:local"
        p = resolver.from_agent_token(token)
        assert p.is_unknown, (
            f"tampered token should be unknown, got {p}"
        )
