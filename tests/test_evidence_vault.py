"""Tests for the Praxis Evidence Vault."""

import asyncio
import shutil
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from praxis.evidence.vault import (
    EvidenceVault,
    EvidenceSession,
    EvidenceRecord,
    SessionSummary,
)
from praxis.policy.engine import (
    ActionEvent,
    ActionType,
    Decision,
    PolicyDecision,
    RiskLevel,
)


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def vault(temp_dir):
    return EvidenceVault(temp_dir)


def make_event(action_type=ActionType.CLICK, url="https://example.com", text="Button"):
    return ActionEvent(
        action_type=action_type,
        url=url,
        element_text=text,
        agent_id="test-agent",
        session_id="test-session",
    )


def make_decision(decision=Decision.ALLOW, risk=RiskLevel.LOW):
    return PolicyDecision(
        decision=decision,
        risk_level=risk,
        matched_rule="test-rule",
        reason="test reason",
        policy_name="test-policy",
    )


class TestEvidenceVault:
    @pytest.mark.asyncio
    async def test_start_session(self, vault):
        session = await vault.start_session("agent-1")
        assert session.agent_id == "agent-1"
        assert session.session_id.startswith("ses_")

    @pytest.mark.asyncio
    async def test_record_action(self, vault):
        session = await vault.start_session("agent-1")
        event = make_event()
        decision = make_decision()

        record = await session.record(event, decision)

        assert record.sequence == 1
        assert record.action_type == "click"
        assert record.decision == "allow"
        assert record.record_hash != ""
        assert record.previous_hash == "genesis"

    @pytest.mark.asyncio
    async def test_chain_integrity(self, vault):
        session = await vault.start_session("agent-1")

        record1 = await session.record(make_event(text="Button 1"), make_decision())
        record2 = await session.record(make_event(text="Button 2"), make_decision())
        record3 = await session.record(make_event(text="Button 3"), make_decision())

        # Check chain
        assert record1.previous_hash == "genesis"
        assert record2.previous_hash == record1.record_hash
        assert record3.previous_hash == record2.record_hash

    @pytest.mark.asyncio
    async def test_session_summary(self, vault):
        session = await vault.start_session("agent-1")

        await session.record(make_event(text="View"), make_decision(Decision.ALLOW))
        await session.record(make_event(text="Pay"), make_decision(Decision.BLOCK, RiskLevel.HIGH))
        await session.record(make_event(text="Submit"), make_decision(Decision.REQUIRE_APPROVAL, RiskLevel.MEDIUM))

        summary = await session.end()

        assert summary.total_actions == 3
        assert summary.actions_allowed == 1
        assert summary.actions_blocked == 1
        assert summary.actions_approval_required == 1
        assert summary.highest_risk == "high"
        assert summary.chain_valid is True

    @pytest.mark.asyncio
    async def test_verify_session_from_disk(self, vault):
        session = await vault.start_session("agent-1")
        await session.record(make_event(), make_decision())
        await session.record(make_event(), make_decision())
        await session.end()

        valid = await vault.verify_session(session.session_id)
        assert valid is True

    @pytest.mark.asyncio
    async def test_list_sessions(self, vault):
        session1 = await vault.start_session("agent-1")
        await session1.record(make_event(), make_decision())
        await session1.end()

        session2 = await vault.start_session("agent-2")
        await session2.record(make_event(), make_decision())
        await session2.end()

        sessions = await vault.list_sessions()
        assert len(sessions) == 2

    @pytest.mark.asyncio
    async def test_export_session(self, vault, temp_dir):
        session = await vault.start_session("agent-1")
        await session.record(make_event(), make_decision())
        await session.end()

        path = await vault.export_session(session.session_id)
        assert Path(path).exists()

        import json
        with open(path) as f:
            data = json.load(f)
        assert data["session_id"] == session.session_id
        assert data["chain_valid"] is True

    @pytest.mark.asyncio
    async def test_value_redaction(self, vault):
        session = await vault.start_session("agent-1")
        event = ActionEvent(
            action_type=ActionType.TYPE,
            url="https://example.com",
            selector="input[name='password']",
            value="supersecretpassword123",
            agent_id="test",
        )
        decision = make_decision()
        record = await session.record(event, decision)

        # Password values should be redacted
        assert "supersecret" not in record.value_redacted
        assert "***" in record.value_redacted
