"""
Praxis filesystem executor.

The one and only place ``os.remove``, ``shutil.move``, ``Path.write_bytes``
and friends are actually called.  Every op goes through:

    FSActionEvent
       │
       ▼
    FSPolicyEngine.evaluate  →  PolicyDecision
       │
       ▼
    (if REQUIRE_APPROVAL) ApprovalCoordinator.request  →  ApprovalOutcome
       │
       ▼
    KillSwitch.is_fired?  →  refuse
       │
       ▼
    Executor method  →  filesystem side effect + FSResult
       │
       ▼
    EvidenceVault.record  (if a session is attached)

The executor is transport-agnostic — the MCP server, REST sidecar,
Unix-socket entry point, and menubar popover all wrap this same
object.
"""

from __future__ import annotations

import asyncio
import glob as _glob
import json
import logging
import os
import shutil
import stat
import time
from pathlib import Path
from typing import Any

from praxis.approval import (
    ApprovalCoordinator,
    ApprovalRequest,
    ApprovalStatus,
)
from praxis.evidence.vault import EvidenceSession
from praxis.filesystem.paths import classify_path
from praxis.filesystem.policy import FSPolicyEngine
from praxis.filesystem.search import SearchHit, search_filenames
from praxis.filesystem.search_backends import SearchBackend, pick_default_backend
from praxis.filesystem.trash import StagedTrash
from praxis.filesystem.types import (
    FSAction,
    FSActionEvent,
    FSResult,
    FSResultStatus,
    normalise_path,
)
from praxis.kill_switch import KillSwitch, get_kill_switch
from praxis.policy.engine import Decision, PolicyDecision

logger = logging.getLogger("praxis.filesystem.executor")


DEFAULT_READ_CAP_BYTES = 50 * 1024 * 1024  # 50 MB


class FSExecutor:
    """Runs Praxis filesystem tool calls with policy + approval + evidence.

    Every method is async.  Every method returns an :class:`FSResult` —
    it never raises for user-visible outcomes (blocked, denied,
    timed out).  It *does* raise on genuine programming errors
    (bad arg types).

    Usage::

        executor = FSExecutor(
            policy=FSPolicyEngine(),
            approvals=ApprovalCoordinator(...),
            trash=StagedTrash(),
        )
        result = await executor.execute(fs_event, session=vault_session)
    """

    def __init__(
        self,
        policy: FSPolicyEngine | None = None,
        approvals: ApprovalCoordinator | None = None,
        trash: StagedTrash | None = None,
        kill_switch: KillSwitch | None = None,
        search_backend: SearchBackend | None = None,
        read_cap_bytes: int = DEFAULT_READ_CAP_BYTES,
    ) -> None:
        self._policy = policy or FSPolicyEngine()
        self._approvals = approvals or ApprovalCoordinator()
        self._trash = trash or StagedTrash()
        self._kill = kill_switch or get_kill_switch()
        self._search_backend = search_backend or pick_default_backend()
        self._read_cap_bytes = read_cap_bytes
        # Wire the kill switch → approval-coordinator cancel_all if the
        # daemon hasn't already done it.  Idempotent.
        if self._kill._approval_cancel_all is None:  # noqa: SLF001
            self._kill.bind_approval_coordinator(self._approvals.cancel_all)

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def execute(
        self,
        event: FSActionEvent,
        session: EvidenceSession | None = None,
    ) -> FSResult:
        """Run the full pipeline on one event."""
        started = time.time()

        # Kill switch → refuse instantly.
        if self._kill.is_fired:
            return await self._finalize(
                FSResult(
                    status=FSResultStatus.KILLED,
                    action=event.action,
                    request_id=event.request_id,
                    reason="kill switch is fired; no ops permitted",
                    duration_ms=(time.time() - started) * 1000.0,
                ),
                event=event,
                decision=None,
                session=session,
            )

        # Layer 1+2: policy.
        decision = self._policy.evaluate(event)
        if decision.decision == Decision.BLOCK:
            return await self._finalize(
                FSResult(
                    status=FSResultStatus.BLOCKED,
                    action=event.action,
                    request_id=event.request_id,
                    reason=decision.reason,
                    decision_matched_rule=decision.matched_rule,
                    duration_ms=(time.time() - started) * 1000.0,
                ),
                event=event,
                decision=decision,
                session=session,
            )

        # Layer 3: approval, if needed.
        if decision.decision == Decision.REQUIRE_APPROVAL:
            approval = await self._approvals.request(
                ApprovalRequest(
                    request_id=event.request_id,
                    tool_name=event.action.value,
                    tier=event.resolved_tier,
                    principal=event.principal,
                    summary=event.approval_summary(),
                    details={
                        "paths": event.paths,
                        "target_dir": event.target_dir,
                        "query": event.query,
                        "matched_rule": decision.matched_rule,
                    },
                    blast_radius=event.blast_radius(),
                )
            )
            status_map = {
                ApprovalStatus.DENIED: FSResultStatus.APPROVAL_DENIED,
                ApprovalStatus.TIMED_OUT: FSResultStatus.APPROVAL_TIMED_OUT,
                ApprovalStatus.CANCELLED: FSResultStatus.APPROVAL_CANCELLED,
                ApprovalStatus.AUTH_FAILED: FSResultStatus.AUTH_FAILED,
            }
            if approval.status != ApprovalStatus.APPROVED:
                return await self._finalize(
                    FSResult(
                        status=status_map.get(
                            approval.status, FSResultStatus.APPROVAL_DENIED
                        ),
                        action=event.action,
                        request_id=event.request_id,
                        reason=approval.reason,
                        decision_matched_rule=decision.matched_rule,
                        approval_status=approval.status.value,
                        duration_ms=(time.time() - started) * 1000.0,
                    ),
                    event=event,
                    decision=decision,
                    session=session,
                )

        # Layer 4: dispatch to the concrete op.
        try:
            payload = await self._dispatch(event)
        except FileNotFoundError as e:
            return await self._finalize(
                FSResult(
                    status=FSResultStatus.ERROR,
                    action=event.action,
                    request_id=event.request_id,
                    reason=f"not found: {e}",
                    decision_matched_rule=decision.matched_rule,
                    duration_ms=(time.time() - started) * 1000.0,
                ),
                event=event,
                decision=decision,
                session=session,
            )
        except PermissionError as e:
            return await self._finalize(
                FSResult(
                    status=FSResultStatus.ERROR,
                    action=event.action,
                    request_id=event.request_id,
                    reason=f"permission denied: {e}",
                    decision_matched_rule=decision.matched_rule,
                    duration_ms=(time.time() - started) * 1000.0,
                ),
                event=event,
                decision=decision,
                session=session,
            )
        except Exception as e:  # never let a bad extractor crash the daemon
            logger.exception("fs op %s failed", event.action.value)
            return await self._finalize(
                FSResult(
                    status=FSResultStatus.ERROR,
                    action=event.action,
                    request_id=event.request_id,
                    reason=f"executor error: {type(e).__name__}: {e}",
                    decision_matched_rule=decision.matched_rule,
                    duration_ms=(time.time() - started) * 1000.0,
                ),
                event=event,
                decision=decision,
                session=session,
            )

        return await self._finalize(
            FSResult(
                status=FSResultStatus.SUCCESS,
                action=event.action,
                request_id=event.request_id,
                reason="ok",
                decision_matched_rule=decision.matched_rule,
                result=payload.get("result", {}),
                trashed_paths=payload.get("trashed", []),
                duration_ms=(time.time() - started) * 1000.0,
            ),
            event=event,
            decision=decision,
            session=session,
        )

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    async def _dispatch(self, event: FSActionEvent) -> dict[str, Any]:
        handler = self._HANDLERS.get(event.action)
        if handler is None:
            raise NotImplementedError(f"no handler for {event.action}")
        return await handler(self, event)

    # ------------------------------------------------------------------
    # T0 — Read
    # ------------------------------------------------------------------

    async def _handle_search(self, event: FSActionEvent) -> dict[str, Any]:
        roots = event.paths or None
        limit = event.limit or 10
        hits: list[SearchHit] = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: search_filenames(
                query=event.query,
                roots=roots,
                ext=event.ext,
                limit=limit,
                backend=self._search_backend,
            ),
        )
        return {"result": {"hits": [h.to_dict() for h in hits]}}

    async def _handle_read(self, event: FSActionEvent) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.read requires at least one path")
        path = normalise_path(event.paths[0])
        cap = event.max_bytes or self._read_cap_bytes
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            raise
        if size > cap:
            return {
                "result": {
                    "path": str(path),
                    "truncated": True,
                    "size": size,
                    "bytes": (path.read_bytes()[:cap]).decode(
                        "utf-8", errors="replace"
                    ),
                }
            }
        return {
            "result": {
                "path": str(path),
                "truncated": False,
                "size": size,
                "bytes": path.read_bytes().decode("utf-8", errors="replace"),
            }
        }

    async def _handle_stat(self, event: FSActionEvent) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.stat requires a path")
        p = normalise_path(event.paths[0])
        st = p.stat()
        return {
            "result": {
                "path": str(p),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "atime": st.st_atime,
                "ctime": st.st_ctime,
                "mode": stat.filemode(st.st_mode),
                "is_dir": p.is_dir(),
                "is_file": p.is_file(),
                "is_symlink": p.is_symlink(),
            }
        }

    async def _handle_list_dir(self, event: FSActionEvent) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.list_dir requires a path")
        p = normalise_path(event.paths[0])
        pat = event.glob or "*"
        entries: list[dict[str, Any]] = []
        for child in sorted(p.glob(pat)):
            try:
                st = child.stat()
                entries.append({
                    "name": child.name,
                    "path": str(child),
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "is_dir": child.is_dir(),
                })
            except OSError:
                continue
        return {"result": {"dir": str(p), "entries": entries}}

    # ------------------------------------------------------------------
    # T1 — Benign write
    # ------------------------------------------------------------------

    async def _handle_create_dir(self, event: FSActionEvent) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.create_dir requires a path")
        p = normalise_path(event.paths[0])
        p.mkdir(parents=True, exist_ok=True)
        return {"result": {"path": str(p), "created": True}}

    async def _handle_create_file(
        self, event: FSActionEvent
    ) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.create_file requires a path")
        p = normalise_path(event.paths[0])
        if p.exists():
            raise FileExistsError(f"cannot create existing path: {p}")
        p.parent.mkdir(parents=True, exist_ok=True)
        content = event.content or b""
        p.write_bytes(content)
        return {"result": {"path": str(p), "bytes_written": len(content)}}

    async def _handle_write(self, event: FSActionEvent) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.write requires a path")
        p = normalise_path(event.paths[0])
        p.parent.mkdir(parents=True, exist_ok=True)
        content = event.content or b""
        mode = event.if_exists
        if p.exists() and mode == "error":
            raise FileExistsError(
                f"fs.write refused: {p} exists and if_exists='error'. "
                f"Use fs.overwrite (T2) to replace it."
            )
        if mode == "append":
            with p.open("ab") as f:
                f.write(content)
        else:
            p.write_bytes(content)
        return {"result": {"path": str(p), "bytes_written": len(content)}}

    # ------------------------------------------------------------------
    # T2 — Destructive
    # ------------------------------------------------------------------

    async def _handle_delete(self, event: FSActionEvent) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.delete requires at least one path")
        trashed: list[str] = []
        deleted: list[dict[str, Any]] = []
        for raw in event.paths:
            p = normalise_path(raw)
            if not p.exists() and not p.is_symlink():
                deleted.append({"path": str(p), "status": "missing"})
                continue
            entry = self._trash.stage(
                original_path=p,
                principal=str(event.principal),
                request_id=event.request_id,
                reason="fs.delete",
            )
            trashed.append(entry.staged_path)
            deleted.append({
                "path": str(p),
                "status": "staged",
                "trash_entry_id": entry.entry_id,
            })
        return {"result": {"deleted": deleted}, "trashed": trashed}

    async def _handle_move(self, event: FSActionEvent) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.move requires at least one path")
        if not event.target_dir:
            raise ValueError("fs.move requires target_dir")
        dst_dir = normalise_path(event.target_dir)
        dst_dir.mkdir(parents=True, exist_ok=True)
        moved: list[dict[str, Any]] = []
        for raw in event.paths:
            src = normalise_path(raw)
            if not src.exists():
                moved.append({"path": str(src), "status": "missing"})
                continue
            dst = dst_dir / src.name
            if dst.exists():
                moved.append({
                    "path": str(src),
                    "status": "skipped",
                    "reason": "destination exists",
                })
                continue
            shutil.move(str(src), str(dst))
            moved.append({"path": str(src), "moved_to": str(dst)})
        return {"result": {"moved": moved}}

    async def _handle_rename(self, event: FSActionEvent) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.rename requires a path")
        if not event.new_name:
            raise ValueError("fs.rename requires new_name")
        # ``new_name`` is always a basename — never a path.
        if "/" in event.new_name or "\\" in event.new_name:
            raise ValueError(
                "fs.rename.new_name must be a basename, not a path"
            )
        src = normalise_path(event.paths[0])
        dst = src.parent / event.new_name
        if dst.exists():
            raise FileExistsError(f"cannot rename: {dst} exists")
        src.rename(dst)
        return {"result": {"path": str(src), "renamed_to": str(dst)}}

    async def _handle_overwrite(
        self, event: FSActionEvent
    ) -> dict[str, Any]:
        if not event.paths:
            raise ValueError("fs.overwrite requires a path")
        p = normalise_path(event.paths[0])
        trashed: list[str] = []
        if p.exists():
            # Backup to trash first.  This is what makes overwrite T2
            # rather than T1 — the original is recoverable.
            entry = self._trash.stage(
                original_path=p,
                principal=str(event.principal),
                request_id=event.request_id,
                reason="fs.overwrite backup",
            )
            trashed.append(entry.staged_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        content = event.content or b""
        p.write_bytes(content)
        return {
            "result": {"path": str(p), "bytes_written": len(content)},
            "trashed": trashed,
        }

    # ------------------------------------------------------------------
    # Dispatch table
    # ------------------------------------------------------------------

    _HANDLERS: dict[FSAction, Any] = {
        FSAction.SEARCH: _handle_search,
        FSAction.READ: _handle_read,
        FSAction.STAT: _handle_stat,
        FSAction.LIST_DIR: _handle_list_dir,
        FSAction.CREATE_DIR: _handle_create_dir,
        FSAction.CREATE_FILE: _handle_create_file,
        FSAction.WRITE: _handle_write,
        FSAction.DELETE: _handle_delete,
        FSAction.MOVE: _handle_move,
        FSAction.RENAME: _handle_rename,
        FSAction.OVERWRITE: _handle_overwrite,
    }

    # ------------------------------------------------------------------
    # Evidence recording
    # ------------------------------------------------------------------

    async def _finalize(
        self,
        result: FSResult,
        event: FSActionEvent,
        decision: PolicyDecision | None,
        session: EvidenceSession | None,
    ) -> FSResult:
        """Record the outcome in the evidence vault (if any)."""
        if session is None:
            return result
        # Synthesize a PolicyDecision for the recorder if one wasn't
        # produced (e.g. kill switch fired before evaluate).
        if decision is None:
            decision = PolicyDecision(
                decision=Decision.BLOCK,
                risk_level=self._policy._risk_for_tier(event.resolved_tier),
                matched_rule=result.decision_matched_rule
                or "kill_switch",
                reason=result.reason,
                policy_name="__executor__",
                action_fingerprint=event.fingerprint,
                tier=event.resolved_tier,
                principal=str(event.principal),
            )
        try:
            await session.record(event.to_action_event(), decision)
        except Exception:
            logger.exception("evidence record failed for %s", event.request_id)
        return result


__all__ = ["FSExecutor", "DEFAULT_READ_CAP_BYTES"]
