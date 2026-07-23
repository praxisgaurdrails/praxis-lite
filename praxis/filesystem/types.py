"""
Praxis filesystem tool types.

Every filesystem tool call is normalised into an :class:`FSActionEvent`
before it touches policy, approval, or the executor.  The event carries:

* The FS action (search / read / create / delete / …)
* The path(s) it targets
* Optional payload (bytes to write, target dir for a move, glob for a list)
* The resolved :class:`~praxis.principal.Principal`
* The :class:`~praxis.tiers.RiskTier` — always set explicitly, never
  inferred (unlike the browser side, where tier is derived from
  ``ActionType``)
* Optional session id for evidence chaining

The event is a Pydantic model so it serialises cleanly for logging,
MCP tool call marshalling, and the evidence chain.

See ``docs/DESIGN.md`` §6.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from praxis.policy.engine import ActionEvent, ActionType, Decision, PolicyDecision, RiskLevel
from praxis.principal import Principal
from praxis.tiers import RiskTier


# ---------------------------------------------------------------------------
# FSAction enum
# ---------------------------------------------------------------------------


class FSAction(str, Enum):
    """The filesystem tool surface for v1.

    Only the ops explicitly listed in ``docs/DESIGN.md`` §6 are
    included.  Adding a new op means adding it here + a tier mapping +
    an executor method + a policy rule slot.  There is no
    "arbitrary_shell" op — that's a v1.1 concern.
    """

    # T0 — read
    SEARCH = "fs.search"
    READ = "fs.read"
    STAT = "fs.stat"
    LIST_DIR = "fs.list_dir"

    # T1 — benign write
    CREATE_DIR = "fs.create_dir"
    CREATE_FILE = "fs.create_file"
    WRITE = "fs.write"

    # T2 — destructive
    DELETE = "fs.delete"
    MOVE = "fs.move"
    RENAME = "fs.rename"
    OVERWRITE = "fs.overwrite"


#: Tier assignment for each FS action.  This table is the single
#: source of truth — the executor consults it, the policy tests check
#: it, no other code should hard-code these tiers.
FS_TIER: dict[FSAction, RiskTier] = {
    FSAction.SEARCH: RiskTier.T0,
    FSAction.READ: RiskTier.T0,
    FSAction.STAT: RiskTier.T0,
    FSAction.LIST_DIR: RiskTier.T0,
    FSAction.CREATE_DIR: RiskTier.T1,
    FSAction.CREATE_FILE: RiskTier.T1,
    FSAction.WRITE: RiskTier.T1,
    FSAction.DELETE: RiskTier.T2,
    FSAction.MOVE: RiskTier.T2,
    FSAction.RENAME: RiskTier.T2,
    FSAction.OVERWRITE: RiskTier.T2,
}


def tier_for(action: FSAction) -> RiskTier:
    """Return the risk tier for a filesystem action."""
    return FS_TIER[action]


# ---------------------------------------------------------------------------
# FSActionEvent — the request
# ---------------------------------------------------------------------------


class FSActionEvent(BaseModel):
    """A single filesystem tool call, pre-policy.

    Only ``action`` and ``principal`` are required.  Optional fields
    are populated per-action:

    * ``paths`` — targets (delete, move, list_dir, stat, read)
    * ``query`` — search query (search)
    * ``target_dir`` / ``new_name`` — destination (move, rename)
    * ``content`` — bytes to write (write, create_file, overwrite)
    * ``if_exists`` — collision policy for writes
    * ``glob`` — pattern for list_dir
    * ``max_bytes`` — cap on reads

    ``tier`` is derived from ``action`` unless the caller explicitly
    overrides it.  Callers must supply a fully-resolved
    :class:`Principal` — building an event with ``principal=None`` is
    a programming error because the FS surface is *not* opt-in the way
    the browser surface was.
    """

    action: FSAction
    principal: Principal
    tier: RiskTier | None = None
    session_id: str = ""
    request_id: str = Field(default_factory=lambda: f"fs_{uuid.uuid4().hex[:12]}")
    timestamp: float = Field(default_factory=time.time)

    # Common path fields
    paths: list[str] = Field(default_factory=list)
    """Primary path(s) for the op.  For search/list_dir this is the
    root(s); for read/stat/delete/move the file(s); for
    create/write the destination file."""

    # Op-specific fields
    query: str = ""
    target_dir: str = ""
    new_name: str = ""
    glob: str = ""
    if_exists: str = "error"  # 'error' | 'append' | 'overwrite' (T2)
    max_bytes: int = 0
    content: bytes | None = None
    limit: int = 0
    ext: str = ""

    metadata: dict[str, Any] = Field(default_factory=dict)
    """Free-form additional context for policy rules + evidence."""

    model_config = {"arbitrary_types_allowed": True}

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def resolved_tier(self) -> RiskTier:
        return self.tier if self.tier is not None else tier_for(self.action)

    @property
    def primary_path(self) -> str:
        """A representative single path for logging / evidence."""
        if self.paths:
            return self.paths[0]
        if self.target_dir:
            return self.target_dir
        return ""

    @property
    def fingerprint(self) -> str:
        """Deterministic short hash for this event, for evidence.

        We include *action*, *primary_path*, and *query* — enough to
        deduplicate but not enough to leak content bytes.
        """
        raw = (
            f"{self.action.value}:{self.primary_path}:"
            f"{self.target_dir}:{self.query}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def blast_radius(self) -> str:
        """One-line human-readable summary of what this op will touch."""
        n = len(self.paths)
        if self.action == FSAction.SEARCH:
            return f"search {self.query!r}"
        if self.action == FSAction.LIST_DIR:
            return f"list {self.primary_path}"
        if self.action == FSAction.STAT:
            return f"stat {self.primary_path}"
        if self.action == FSAction.READ:
            return f"read {self.primary_path}"
        if self.action == FSAction.CREATE_DIR:
            return f"mkdir {self.primary_path}"
        if self.action == FSAction.CREATE_FILE:
            size = len(self.content or b"")
            return f"create {self.primary_path} ({size} bytes)"
        if self.action == FSAction.WRITE:
            size = len(self.content or b"")
            return f"write {self.primary_path} ({size} bytes, if_exists={self.if_exists})"
        if self.action == FSAction.DELETE:
            return f"delete {n} path(s)"
        if self.action == FSAction.MOVE:
            return f"move {n} path(s) → {self.target_dir}"
        if self.action == FSAction.RENAME:
            return f"rename {self.primary_path} → {self.new_name}"
        if self.action == FSAction.OVERWRITE:
            size = len(self.content or b"")
            return f"overwrite {self.primary_path} ({size} bytes)"
        return self.action.value

    def approval_summary(self) -> str:
        """Text shown in the OS approval notification."""
        return f"{self.principal} → {self.blast_radius()}"

    # ------------------------------------------------------------------
    # Adapter for the shared evidence vault
    # ------------------------------------------------------------------

    def to_action_event(self) -> ActionEvent:
        """Return a browser-side :class:`ActionEvent` view.

        The evidence vault is currently keyed on ``ActionEvent``; this
        adapter lets us record FS ops without forking the vault.  We
        stuff the FS-specific fields into fields the vault already
        knows how to serialise:

        * ``action_type`` = ``ActionType.FILESYSTEM`` (the umbrella)
        * ``selector`` = the concrete ``fs.*`` op name
        * ``url`` = the primary path
        * ``element_text`` = the blast-radius summary
        * ``value`` = compact JSON-ish rendering for redaction
        * ``metadata`` = the raw dict
        """
        # Compact "value" summary — never includes content bytes.
        value_bits = []
        if self.query:
            value_bits.append(f"query={self.query!r}")
        if self.target_dir:
            value_bits.append(f"to={self.target_dir}")
        if self.new_name:
            value_bits.append(f"new_name={self.new_name}")
        if self.glob:
            value_bits.append(f"glob={self.glob}")
        if self.max_bytes:
            value_bits.append(f"max_bytes={self.max_bytes}")
        if self.ext:
            value_bits.append(f"ext={self.ext}")
        value = " ".join(value_bits)

        return ActionEvent(
            action_type=ActionType.FILESYSTEM,
            url=self.primary_path,
            selector=self.action.value,
            element_text=self.blast_radius()[:200],
            value=value,
            timestamp=self.timestamp,
            agent_id=self.principal.name if self.principal.is_agent else "",
            session_id=self.session_id,
            metadata={
                **self.metadata,
                "fs_action": self.action.value,
                "paths_count": len(self.paths),
                "request_id": self.request_id,
            },
            principal=self.principal,
            tier=self.resolved_tier,
        )


# ---------------------------------------------------------------------------
# FSResult — the return value from the executor
# ---------------------------------------------------------------------------


class FSResultStatus(str, Enum):
    """Terminal states of an executor call."""

    SUCCESS = "success"
    BLOCKED = "blocked"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_TIMED_OUT = "approval_timed_out"
    APPROVAL_CANCELLED = "approval_cancelled"
    AUTH_FAILED = "auth_failed"
    KILLED = "killed"
    ERROR = "error"


class FSResult(BaseModel):
    """The full return value of an executor call — success or failure."""

    status: FSResultStatus
    action: FSAction
    request_id: str
    reason: str = ""
    """Human-readable explanation, especially for non-success statuses."""
    decision_matched_rule: str = ""
    """Which policy rule (or tier-gate marker) caused the outcome."""
    result: dict[str, Any] = Field(default_factory=dict)
    """Op-specific payload: search hits, file contents, stat metadata, etc."""
    trashed_paths: list[str] = Field(default_factory=list)
    """For deletes: where files were staged before actual removal."""
    approval_status: str = ""
    duration_ms: float = 0.0

    model_config = {"arbitrary_types_allowed": True}

    @property
    def ok(self) -> bool:
        return self.status == FSResultStatus.SUCCESS


# ---------------------------------------------------------------------------
# Utilities used by policy + executor
# ---------------------------------------------------------------------------


def normalise_path(p: str | Path) -> Path:
    """Return a resolved, expanded absolute :class:`Path`.

    Expands ``~`` to the user's home dir and resolves symlinks
    strictly enough to defeat trivial traversal (``../..``) — but
    without requiring the target to exist (so we can safely normalise
    a target path for a not-yet-created file).
    """
    return Path(str(p)).expanduser().resolve(strict=False)


__all__ = [
    "FS_TIER",
    "FSAction",
    "FSActionEvent",
    "FSResult",
    "FSResultStatus",
    "normalise_path",
    "tier_for",
]
