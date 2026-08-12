"""
Praxis runbook cache — SQLite-backed store of proven tool-call chains.

A **runbook** is a series of T0–T2 tool calls that completed
successfully.  When an external agent (Claude / Codex / OpenClaw) drives
Praxis online, we snapshot every successful chain here.  Offline, the
same phrase triggers a deterministic replay: no LLM planning required.

Storage: one SQLite file at ``~/.praxis/runbooks.db`` with a single
table and a small BLOB per row.  Cheap, single-file, portable, no
background service.

Design notes:

* Match on a **trigger fingerprint**, not embeddings.  Fingerprint is
  a normalised bag-of-tokens of the trigger phrase, scored via Jaccard
  similarity.  Works well for repeated user phrasings ("clean up
  Downloads" ≈ "clean the downloads folder") without an ML dep.
* Each runbook binds to the policy version at capture time.  On replay
  the current policy re-evaluates the chain — a cached runbook can be
  refused if the policy has tightened.
* Runbooks are **per-user**, not global.  The DB path is inside the
  user's ``~/.praxis``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger("praxis.runbook.cache")


DEFAULT_CACHE_FILE = Path.home() / ".praxis" / "runbooks.db"


def default_cache_path() -> Path:
    return DEFAULT_CACHE_FILE


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class RunbookStep:
    """One tool call inside a runbook."""

    tool_name: str
    """FS tool name — 'fs.search' / 'fs.delete' / etc."""
    arguments: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"tool_name": self.tool_name, "arguments": self.arguments}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunbookStep:
        return cls(
            tool_name=str(d.get("tool_name", "")),
            arguments=dict(d.get("arguments", {}) or {}),
        )


@dataclass
class Runbook:
    """A snapshotted chain of successful tool calls."""

    runbook_id: str
    trigger_phrase: str
    """Human-readable label ('clean up Downloads')."""
    steps: list[RunbookStep] = field(default_factory=list)
    principal_at_capture: str = ""
    policy_version_at_capture: str = ""
    captured_at: float = field(default_factory=time.time)
    last_verified: float = field(default_factory=time.time)
    verified_success: bool = True
    replay_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def trigger_tokens(self) -> set[str]:
        return _tokenize(self.trigger_phrase)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runbook_id": self.runbook_id,
            "trigger_phrase": self.trigger_phrase,
            "steps": [s.to_dict() for s in self.steps],
            "principal_at_capture": self.principal_at_capture,
            "policy_version_at_capture": self.policy_version_at_capture,
            "captured_at": self.captured_at,
            "last_verified": self.last_verified,
            "verified_success": self.verified_success,
            "replay_count": self.replay_count,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Runbook:
        return cls(
            runbook_id=str(d["runbook_id"]),
            trigger_phrase=str(d.get("trigger_phrase", "")),
            steps=[RunbookStep.from_dict(s) for s in d.get("steps", [])],
            principal_at_capture=str(d.get("principal_at_capture", "")),
            policy_version_at_capture=str(d.get("policy_version_at_capture", "")),
            captured_at=float(d.get("captured_at", 0.0)),
            last_verified=float(d.get("last_verified", 0.0)),
            verified_success=bool(d.get("verified_success", True)),
            replay_count=int(d.get("replay_count", 0)),
            metadata=dict(d.get("metadata", {}) or {}),
        )


@dataclass
class RunbookMatch:
    """A candidate runbook + its similarity score for the current query."""

    runbook: Runbook
    score: float
    """Jaccard similarity of the query tokens vs. trigger tokens."""


# ---------------------------------------------------------------------------
# Tokenisation + similarity
# ---------------------------------------------------------------------------


_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "but", "of", "for", "to", "in",
    "on", "at", "by", "with", "from", "as", "is", "was", "be", "been",
    "being", "are", "were", "am", "do", "does", "did", "please", "me",
    "my", "your", "you", "i", "this", "that", "these", "those", "any",
    "all", "some", "then", "now", "also", "just",
})

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> set[str]:
    if not text:
        return set()
    return {t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = a & b
    union = a | b
    return len(inter) / len(union) if union else 0.0


# ---------------------------------------------------------------------------
# The cache
# ---------------------------------------------------------------------------


class RunbookCache:
    """SQLite-backed runbook store."""

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path is not None else DEFAULT_CACHE_FILE
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._path.parent.chmod(0o700)
        except OSError:
            pass
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    @property
    def path(self) -> Path:
        return self._path

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runbooks (
                    runbook_id TEXT PRIMARY KEY,
                    trigger_phrase TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    principal_at_capture TEXT NOT NULL,
                    policy_version_at_capture TEXT NOT NULL,
                    captured_at REAL NOT NULL,
                    last_verified REAL NOT NULL,
                    verified_success INTEGER NOT NULL,
                    replay_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_runbooks_captured
                    ON runbooks(captured_at DESC);
                """
            )
            conn.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, runbook: Runbook) -> Runbook:
        """Insert or replace a runbook.  Returns it (id generated if missing)."""
        if not runbook.runbook_id:
            runbook.runbook_id = f"rb_{uuid.uuid4().hex[:12]}"
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runbooks (
                    runbook_id, trigger_phrase, payload_json,
                    principal_at_capture, policy_version_at_capture,
                    captured_at, last_verified, verified_success, replay_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    runbook.runbook_id,
                    runbook.trigger_phrase,
                    json.dumps(runbook.to_dict()),
                    runbook.principal_at_capture,
                    runbook.policy_version_at_capture,
                    runbook.captured_at,
                    runbook.last_verified,
                    int(runbook.verified_success),
                    runbook.replay_count,
                ),
            )
            conn.commit()
        return runbook

    def get(self, runbook_id: str) -> Runbook | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM runbooks WHERE runbook_id = ?",
                (runbook_id,),
            ).fetchone()
            if not row:
                return None
            return Runbook.from_dict(json.loads(row[0]))

    def delete(self, runbook_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM runbooks WHERE runbook_id = ?", (runbook_id,)
            )
            conn.commit()
            return cur.rowcount > 0

    def list_all(self, limit: int = 100) -> list[Runbook]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM runbooks "
                "ORDER BY captured_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [Runbook.from_dict(json.loads(r[0])) for r in rows]

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM runbooks").fetchone()
            return int(row[0]) if row else 0

    def record_replay(self, runbook_id: str, success: bool) -> None:
        """Update replay stats after an offline replay."""
        rb = self.get(runbook_id)
        if not rb:
            return
        rb.replay_count += 1
        rb.last_verified = time.time()
        rb.verified_success = bool(success)
        self.add(rb)

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match(
        self,
        query: str,
        min_score: float = 0.4,
        top_k: int = 5,
    ) -> list[RunbookMatch]:
        """Return top-K runbooks whose trigger tokens overlap the query."""
        q_tokens = _tokenize(query)
        if not q_tokens:
            return []
        matches: list[RunbookMatch] = []
        for rb in self.list_all(limit=500):
            score = _jaccard(q_tokens, rb.trigger_tokens)
            if score >= min_score:
                matches.append(RunbookMatch(runbook=rb, score=score))
        matches.sort(key=lambda m: (-m.score, -m.runbook.captured_at))
        return matches[: max(1, top_k)]


__all__ = [
    "DEFAULT_CACHE_FILE",
    "Runbook",
    "RunbookCache",
    "RunbookMatch",
    "RunbookStep",
    "default_cache_path",
]
