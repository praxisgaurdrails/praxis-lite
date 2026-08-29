"""Evidence-vault tests for Phase 1: principal + tier propagation."""

import shutil
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from praxis.evidence.vault import EvidenceRecord, EvidenceVault
from praxis.policy.engine import (
    ActionEvent,
    ActionType,
    Decision,
    PolicyDecision,
    PolicyEngine,
    RiskLevel,
    create_permissive_policy,
)
from praxis.principal import Principal
from praxis.tiers import RiskTier


@pytest.fixture
def vault_dir():
    d = tempfile.mkdtemp()
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def vault(vault_dir):
    return EvidenceVault(vault_dir)


# ---------------------------------------------------------------------------
# Backwards compat: pre-Phase-1 records verify unchanged
# ---------------------------------------------------------------------------


class TestBackwardsCompat:
    def test_legacy_hash_unchanged_when_principal_empty(self):
        # A record with no principal/tier must produce exactly the same
        # hash it did before Phase 1.  We validate by hand-building the
        # payload and comparing.
        import hashlib

        r = EvidenceRecord(
            record_id="rec_legacy",
            sequence=1,
            session_id="ses_legacy",
            agent_id="a",
            timestamp=1000.0,
            action_type="click",
            url="https://example.com",
            selector="#b",
            element_text="OK",
            decision="allow",
            risk_level="low",
            matched_rule="",
            dom_snapshot_hash="",
            screenshot_hash="",
            previous_hash="genesis",
        )
        legacy_payload = (
            f"{r.record_id}:{r.sequence}:{r.session_id}:"
            f"{r.agent_id}:{r.timestamp}:{r.action_type}:"
            f"{r.url}:{r.selector}:{r.element_text}:"
            f"{r.decision}:{r.risk_level}:{r.matched_rule}:"
            f":{r.screenshot_hash}:"  # dom_snapshot_hash is empty
            f"{r.previous_hash}"
        )
        expected = hashlib.sha256(legacy_payload.encode()).hexdigest()
        assert r.compute_hash() == expected

    def test_principal_and_tier_extend_the_hash(self):
        base = EvidenceRecord(
            record_id="rec_new",
            sequence=1,
            session_id="ses_new",
            timestamp=1000.0,
            action_type="click",
            decision="allow",
        )
        h_bare = base.compute_hash()

        with_principal = base.model_copy(
            update={"principal": "praxis:local", "tier": "t1"}
        )
        h_new = with_principal.compute_hash()
        assert h_bare != h_new


# ---------------------------------------------------------------------------
# End-to-end: engine → vault → chain still verifies
# ---------------------------------------------------------------------------


class TestPipeline:
    @pytest.mark.asyncio
    async def test_mixed_principals_chain_verifies(self, vault):
        engine = PolicyEngine()
        engine.load_policy(create_permissive_policy())
        session = await vault.start_session(agent_id="mixed-test")

        # A run with a local principal (allowed T0).
        e1 = ActionEvent(
            action_type=ActionType.NAVIGATE,
            url="https://example.com",
            principal=Principal.local(),
        )
        d1 = engine.evaluate(e1)
        await session.record(e1, d1)

        # And an agent principal at T1 (approval).
        e2 = ActionEvent(
            action_type=ActionType.CLICK,
            url="https://example.com",
            element_text="OK",
            principal=Principal.agent("claude-desktop"),
        )
        d2 = engine.evaluate(e2)
        await session.record(e2, d2)

        summary = await session.end()
        assert summary.chain_valid, "hash chain must verify"
        assert summary.total_actions == 2

        # Records on disk carry the new columns.
        records = await vault.get_session_records(session.session_id)
        assert records[0].principal == "praxis:local"
        assert records[0].tier == "t0"
        assert records[1].principal == "agent:claude-desktop"
        assert records[1].tier == "t1"

        assert await vault.verify_session(session.session_id)

    @pytest.mark.asyncio
    async def test_manual_record_without_principal_still_verifies(
        self, vault
    ):
        """Backwards compat: legacy /api/v1/record callers.

        A caller that constructs an ``ActionEvent`` with no principal
        and hands us a ``PolicyDecision`` fabricated by hand must still
        produce records whose chain verifies.
        """
        session = await vault.start_session(agent_id="legacy-test")

        e = ActionEvent(action_type=ActionType.CLICK, url="https://x")
        d = PolicyDecision(
            decision=Decision.ALLOW,
            risk_level=RiskLevel.LOW,
            reason="manual",
        )
        await session.record(e, d)
        summary = await session.end()
        assert summary.chain_valid
        assert summary.total_actions == 1
