"""
Praxis Evidence Vault — Tamper-evident audit trails for agent sessions.

Every action an agent takes is recorded with:
- Full action event details
- Policy decision and reason
- DOM snapshot hash
- Screenshot hash (optional)
- Timestamp with cryptographic chaining

Evidence is stored locally and can be exported for compliance/audit.
The chain of records is tamper-evident: each record's hash includes
the previous record's hash, creating an append-only verifiable log.

Usage:
    vault = EvidenceVault("./evidence")
    session = await vault.start_session(agent_id="agent-1")
    await session.record(action_event, policy_decision, screenshot_bytes)
    summary = await session.end()
    await vault.export_session(session.session_id, format="json")
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles
from pydantic import BaseModel, Field

from praxis.policy.engine import ActionEvent, PolicyDecision, RiskLevel, Decision
from praxis import __version__ as _praxis_version


# ---------------------------------------------------------------------------
# Evidence Record
# ---------------------------------------------------------------------------

class EvidenceRecord(BaseModel):
    """A single tamper-evident record of an agent action."""
    record_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    sequence: int = 0
    session_id: str = ""
    agent_id: str = ""
    timestamp: float = Field(default_factory=time.time)
    timestamp_iso: str = ""

    # Action details
    action_type: str = ""
    url: str = ""
    selector: str = ""
    element_text: str = ""
    value_redacted: str = ""  # We redact sensitive values

    # Policy decision
    decision: str = ""
    risk_level: str = ""
    matched_rule: str = ""
    reason: str = ""
    policy_name: str = ""

    # --- Praxis Phase 1 additions ---
    # Optional to preserve backwards compatibility with existing JSONL
    # records on disk (older records deserialise cleanly because the
    # defaults kick in).  Both fields are folded into ``compute_hash``
    # only when non-empty so a fresh record built without them still
    # produces the exact same hash as before.
    principal: str = ""
    tier: str = ""

    # Integrity
    dom_snapshot_hash: str = ""
    screenshot_hash: str = ""
    previous_hash: str = ""  # Hash of the previous record (chain)
    record_hash: str = ""  # Hash of this record (computed)

    def compute_hash(self) -> str:
        """Compute the integrity hash of this record.

        Older records (before Phase 1) did not include ``principal``
        and ``tier`` in the hash.  We keep the pre-Phase-1 canonical
        form when both are empty so existing sessions on disk still
        verify.  When either is populated they extend the hashed
        payload — meaning any Phase-1-or-later record incorporates its
        principal + tier into the chain.
        """
        data = (
            f"{self.record_id}:{self.sequence}:{self.session_id}:"
            f"{self.agent_id}:{self.timestamp}:{self.action_type}:"
            f"{self.url}:{self.selector}:{self.element_text}:"
            f"{self.decision}:{self.risk_level}:{self.matched_rule}:"
            f"{self.dom_snapshot_hash}:{self.screenshot_hash}:"
            f"{self.previous_hash}"
        )
        if self.principal or self.tier:
            data += f":{self.principal}:{self.tier}"
        return hashlib.sha256(data.encode()).hexdigest()


class SessionSummary(BaseModel):
    """Summary of a completed evidence session."""
    session_id: str
    agent_id: str
    start_time: float
    end_time: float
    duration_seconds: float = 0
    total_actions: int = 0
    actions_allowed: int = 0
    actions_blocked: int = 0
    actions_approval_required: int = 0
    highest_risk: str = "none"
    policies_applied: list[str] = Field(default_factory=list)
    chain_valid: bool = True
    first_hash: str = ""
    last_hash: str = ""


# ---------------------------------------------------------------------------
# Evidence Session
# ---------------------------------------------------------------------------

SENSITIVE_PATTERNS = ["password", "secret", "token", "key", "card", "cvv", "ssn"]


def _redact_value(value: str, field_hint: str = "") -> str:
    """Redact sensitive values in evidence records."""
    hint_lower = field_hint.lower()
    for pattern in SENSITIVE_PATTERNS:
        if pattern in hint_lower:
            if len(value) > 4:
                return f"***{value[-4:]}"
            return "****"
    # Don't store very long values (could be pasted secrets)
    if len(value) > 200:
        return f"{value[:50]}... [TRUNCATED {len(value)} chars]"
    return value


class EvidenceSession:
    """An active evidence recording session for one agent run."""

    def __init__(self, session_id: str, agent_id: str, storage_dir: Path) -> None:
        self.session_id = session_id
        self.agent_id = agent_id
        self.storage_dir = storage_dir
        self.start_time = time.time()
        self._records: list[EvidenceRecord] = []
        self._sequence = 0
        self._previous_hash = "genesis"
        self._policies_seen: set[str] = set()
        self._ended = False

        # Create session directory
        self.session_dir = storage_dir / session_id
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.screenshots_dir = self.session_dir / "screenshots"
        self.screenshots_dir.mkdir(exist_ok=True)

    async def record(
        self,
        event: ActionEvent,
        decision: PolicyDecision,
        screenshot: bytes | None = None,
        dom_snapshot: str | None = None,
    ) -> EvidenceRecord:
        """Record an action + decision as a tamper-evident evidence entry."""
        if self._ended:
            raise RuntimeError("Session has already ended")

        self._sequence += 1

        # Hash screenshot if provided
        screenshot_hash = ""
        if screenshot:
            screenshot_hash = hashlib.sha256(screenshot).hexdigest()
            screenshot_path = self.screenshots_dir / f"{self._sequence:06d}.png"
            async with aiofiles.open(screenshot_path, "wb") as f:
                await f.write(screenshot)

        # Hash DOM snapshot if provided
        dom_hash = ""
        if dom_snapshot:
            dom_hash = hashlib.sha256(dom_snapshot.encode()).hexdigest()

        # Track policies
        if decision.policy_name:
            self._policies_seen.add(decision.policy_name)

        # Create evidence record
        record = EvidenceRecord(
            sequence=self._sequence,
            session_id=self.session_id,
            agent_id=self.agent_id,
            timestamp=time.time(),
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            action_type=event.action_type.value,
            url=event.url,
            selector=event.selector,
            element_text=event.element_text[:200],
            value_redacted=_redact_value(event.value, event.selector),
            decision=decision.decision.value,
            risk_level=decision.risk_level.value,
            matched_rule=decision.matched_rule,
            reason=decision.reason,
            policy_name=decision.policy_name,
            # --- Praxis Phase 1 ---
            # Prefer the decision's stamped fields (populated by the
            # engine's ``_stamp_decision``); fall back to the event when
            # a caller passes a decision that hasn't been through the
            # engine (e.g. a manual /record entry).
            principal=(
                decision.principal
                or (str(event.principal) if event.principal is not None else "")
            ),
            tier=(
                decision.tier.value
                if decision.tier is not None
                else (event.tier.value if event.tier is not None else "")
            ),
            dom_snapshot_hash=dom_hash,
            screenshot_hash=screenshot_hash,
            previous_hash=self._previous_hash,
        )

        # Compute and set the hash
        record.record_hash = record.compute_hash()
        self._previous_hash = record.record_hash

        self._records.append(record)

        # Write record to disk immediately (append-only)
        record_path = self.session_dir / "evidence.jsonl"
        async with aiofiles.open(record_path, "a") as f:
            await f.write(record.model_dump_json() + "\n")

        return record

    async def end(self) -> SessionSummary:
        """End the session and generate a summary."""
        self._ended = True
        end_time = time.time()

        # Compute statistics
        allowed = sum(1 for r in self._records if r.decision == Decision.ALLOW.value)
        blocked = sum(1 for r in self._records if r.decision == Decision.BLOCK.value)
        approval = sum(
            1 for r in self._records if r.decision == Decision.REQUIRE_APPROVAL.value
        )

        # Find highest risk
        risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        highest = max(
            (r.risk_level for r in self._records),
            key=lambda x: risk_order.get(x, 0),
            default="none",
        )

        # Verify chain integrity
        chain_valid = self._verify_chain()

        summary = SessionSummary(
            session_id=self.session_id,
            agent_id=self.agent_id,
            start_time=self.start_time,
            end_time=end_time,
            duration_seconds=round(end_time - self.start_time, 2),
            total_actions=len(self._records),
            actions_allowed=allowed,
            actions_blocked=blocked,
            actions_approval_required=approval,
            highest_risk=highest,
            policies_applied=list(self._policies_seen),
            chain_valid=chain_valid,
            first_hash=self._records[0].record_hash if self._records else "",
            last_hash=self._records[-1].record_hash if self._records else "",
        )

        # Write summary
        summary_path = self.session_dir / "summary.json"
        async with aiofiles.open(summary_path, "w") as f:
            await f.write(summary.model_dump_json(indent=2))

        return summary

    def _verify_chain(self) -> bool:
        """Verify the integrity chain of all records."""
        if not self._records:
            return True

        prev_hash = "genesis"
        for record in self._records:
            if record.previous_hash != prev_hash:
                return False
            computed = record.compute_hash()
            if computed != record.record_hash:
                return False
            prev_hash = record.record_hash

        return True

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def records(self) -> list[EvidenceRecord]:
        return list(self._records)


# ---------------------------------------------------------------------------
# Evidence Vault — manages sessions and storage
# ---------------------------------------------------------------------------

class EvidenceVault:
    """
    Manages evidence sessions, storage, and retrieval.

    Usage:
        vault = EvidenceVault("./evidence")
        session = await vault.start_session("agent-1")
        await session.record(event, decision)
        summary = await session.end()

        # Later: retrieve and replay
        records = await vault.get_session_records(session.session_id)
        valid = await vault.verify_session(session.session_id)
    """

    def __init__(
        self,
        storage_dir: str | Path = "./praxis_evidence",
        enforce_license: bool = True,
    ) -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._active_sessions: dict[str, EvidenceSession] = {}
        # When False, the vault records evidence without consulting the
        # legacy Praxis license gate.  Praxis treats the tamper-proof
        # audit trail as a core (free) capability, so the daemon
        # constructs the vault with enforce_license=False.  Existing
        # Praxis callers keep the default (True) and the old paywall.
        self._enforce_license = enforce_license

    async def start_session(
        self, agent_id: str, session_id: str | None = None
    ) -> EvidenceSession:
        """Start a new evidence recording session."""
        # License check: evidence_vault feature + session count limit
        if self._enforce_license:
            from praxis.licensing.license_manager import LicenseManager
            lm = LicenseManager()
            lm.check_feature("evidence_vault")
            lm.check_session_count()

        if session_id is None:
            session_id = f"ses_{uuid.uuid4().hex[:16]}"

        session = EvidenceSession(
            session_id=session_id,
            agent_id=agent_id,
            storage_dir=self.storage_dir,
        )
        self._active_sessions[session_id] = session
        return session

    async def end_session(self, session_id: str) -> SessionSummary:
        """End an active session and return its summary."""
        session = self._active_sessions.pop(session_id, None)
        if session is None:
            raise ValueError(f"No active session: {session_id}")
        return await session.end()

    async def get_session_records(self, session_id: str) -> list[EvidenceRecord]:
        """Load evidence records for a session from disk."""
        session_dir = self.storage_dir / session_id
        evidence_file = session_dir / "evidence.jsonl"

        if not evidence_file.exists():
            return []

        records = []
        async with aiofiles.open(evidence_file, "r") as f:
            async for line in f:
                line = line.strip()
                if line:
                    records.append(EvidenceRecord.model_validate_json(line))
        return records

    async def get_session_summary(self, session_id: str) -> SessionSummary | None:
        """Load a session summary from disk."""
        summary_file = self.storage_dir / session_id / "summary.json"
        if not summary_file.exists():
            return None
        async with aiofiles.open(summary_file, "r") as f:
            data = await f.read()
        return SessionSummary.model_validate_json(data)

    async def verify_session(self, session_id: str) -> bool:
        """Verify the integrity chain of a stored session."""
        records = await self.get_session_records(session_id)
        if not records:
            return True

        prev_hash = "genesis"
        for record in records:
            if record.previous_hash != prev_hash:
                return False
            computed = record.compute_hash()
            if computed != record.record_hash:
                return False
            prev_hash = record.record_hash

        return True

    async def list_sessions(self) -> list[dict[str, Any]]:
        """List all stored sessions with basic info."""
        sessions = []
        for session_dir in sorted(self.storage_dir.iterdir()):
            if session_dir.is_dir() and session_dir.name.startswith("ses_"):
                summary = await self.get_session_summary(session_dir.name)
                if summary:
                    sessions.append(summary.model_dump())
                else:
                    sessions.append({
                        "session_id": session_dir.name,
                        "status": "incomplete",
                    })
        return sessions

    async def export_session(
        self, session_id: str, output_path: str | Path | None = None
    ) -> str:
        """Export a session's evidence as a JSON file."""
        # License check: export_evidence feature
        from praxis.licensing.license_manager import LicenseManager
        lm = LicenseManager()
        lm.check_feature("export_evidence")

        records = await self.get_session_records(session_id)
        summary = await self.get_session_summary(session_id)

        export_data = {
            "praxis_version": _praxis_version,
            "export_time": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "summary": summary.model_dump() if summary else None,
            "records": [r.model_dump() for r in records],
            "chain_valid": await self.verify_session(session_id),
        }

        if output_path is None:
            output_path = self.storage_dir / session_id / "export.json"

        output_path = Path(output_path)
        async with aiofiles.open(output_path, "w") as f:
            await f.write(json.dumps(export_data, indent=2))

        return str(output_path)

    async def delete_session(self, session_id: str) -> bool:
        """Delete a session's evidence (use with caution)."""
        import shutil
        session_dir = self.storage_dir / session_id
        if session_dir.exists():
            shutil.rmtree(session_dir)
            return True
        return False

    # ------------------------------------------------------------------
    # Log Retention Cleanup
    # ------------------------------------------------------------------

    async def cleanup_expired_sessions(self) -> int:
        """
        Delete sessions older than the current tier's retention limit.

        Retention is controlled by audit_log_retention_days in the license tier:
            Community: 1 day
            Trial: 1 day
            Pro: 30 days
            Enterprise: 365 days

        Returns the number of sessions deleted.
        """
        from praxis.licensing.license_manager import LicenseManager, TIER_FEATURES
        lm = LicenseManager()
        features = TIER_FEATURES.get(lm.tier, {})
        retention_days = features.get("audit_log_retention_days", 1)
        cutoff_seconds = retention_days * 86400
        now = time.time()
        deleted = 0

        if not self.storage_dir.exists():
            return 0

        for session_dir in self.storage_dir.iterdir():
            if not session_dir.is_dir() or not session_dir.name.startswith("ses_"):
                continue

            # Determine session age from summary.json or evidence.jsonl mtime
            session_time = None
            summary_file = session_dir / "summary.json"
            evidence_file = session_dir / "evidence.jsonl"

            if summary_file.exists():
                try:
                    data = json.loads(summary_file.read_text())
                    # Use end_time if available, else start_time
                    session_time = data.get("end_time") or data.get("start_time")
                except Exception:
                    pass

            if session_time is None and evidence_file.exists():
                # Fall back to file modification time
                session_time = evidence_file.stat().st_mtime

            if session_time is None:
                # Use directory modification time as last resort
                session_time = session_dir.stat().st_mtime

            age_seconds = now - session_time
            if age_seconds > cutoff_seconds:
                await self.delete_session(session_dir.name)
                deleted += 1

        return deleted

    async def start_retention_cleanup_task(self, interval_hours: int = 6) -> None:
        """
        Start a background task that periodically cleans up expired sessions.

        Runs immediately on first call, then every `interval_hours` hours.
        """
        import asyncio

        async def _cleanup_loop():
            while True:
                try:
                    deleted = await self.cleanup_expired_sessions()
                    if deleted > 0:
                        import logging
                        logging.getLogger("praxis").info(
                            f"Retention cleanup: deleted {deleted} expired session(s)"
                        )
                except Exception:
                    pass
                await asyncio.sleep(interval_hours * 3600)

        asyncio.create_task(_cleanup_loop())
