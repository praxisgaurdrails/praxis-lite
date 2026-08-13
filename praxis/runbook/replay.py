"""
Runbook replay — deterministic re-execution of a stored chain.

The replayer walks a :class:`~praxis.runbook.cache.Runbook` step by
step, rebuilds an :class:`~praxis.filesystem.types.FSActionEvent`
from each stored step, and drives them through the same executor the
online chain used.  Every step goes through the current policy + tier
gate + approval flow — the runbook is *not* a policy bypass.

The user is expected to confirm the replay before it starts (via the
popover: "I've done this before; run the same 3 steps?").  We don't
auto-execute stored chains without a fresh consent.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from praxis.evidence.vault import EvidenceSession
from praxis.filesystem.executor import FSExecutor
from praxis.filesystem.types import (
    FSAction,
    FSActionEvent,
    FSResult,
    FSResultStatus,
)
from praxis.principal import Principal
from praxis.runbook.cache import Runbook

logger = logging.getLogger("praxis.runbook.replay")


class ReplayStatus(str, Enum):
    """Terminal state of a replay run."""

    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    ABORTED = "aborted"


@dataclass
class ReplayOutcome:
    """Full result of a replay attempt."""

    status: ReplayStatus
    runbook_id: str
    results: list[FSResult] = field(default_factory=list)
    failed_step_index: int = -1
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status == ReplayStatus.SUCCESS


class RunbookReplayer:
    """Replays a stored runbook via the current executor."""

    def __init__(self, executor: FSExecutor) -> None:
        self._executor = executor

    async def replay(
        self,
        runbook: Runbook,
        principal: Principal,
        session: EvidenceSession | None = None,
        abort_on_first_failure: bool = True,
    ) -> ReplayOutcome:
        """Walk the runbook's steps, running each through the executor.

        ``principal`` is applied to every rebuilt event — a runbook
        captured under an agent principal can be replayed by the local
        user (typical offline path), which promotes it up the trust
        ladder and can unblock ops the agent originally had to ask
        approval for.
        """
        outcome = ReplayOutcome(
            status=ReplayStatus.SUCCESS,
            runbook_id=runbook.runbook_id,
        )

        for i, step in enumerate(runbook.steps):
            try:
                event = _rebuild_event(step, principal)
            except ValueError as e:
                outcome.status = ReplayStatus.FAILED
                outcome.failed_step_index = i
                outcome.reason = f"step {i} malformed: {e}"
                return outcome

            result = await self._executor.execute(event, session=session)
            outcome.results.append(result)

            if result.status == FSResultStatus.SUCCESS:
                continue
            if result.status == FSResultStatus.BLOCKED:
                outcome.status = ReplayStatus.BLOCKED
                outcome.failed_step_index = i
                outcome.reason = (
                    f"step {i} ({event.action.value}) blocked by policy: "
                    f"{result.reason}"
                )
                if abort_on_first_failure:
                    return outcome
            elif result.status in (
                FSResultStatus.APPROVAL_DENIED,
                FSResultStatus.APPROVAL_TIMED_OUT,
                FSResultStatus.APPROVAL_CANCELLED,
                FSResultStatus.AUTH_FAILED,
            ):
                outcome.status = ReplayStatus.ABORTED
                outcome.failed_step_index = i
                outcome.reason = (
                    f"step {i} ({event.action.value}) aborted at approval: "
                    f"{result.reason}"
                )
                if abort_on_first_failure:
                    return outcome
            elif result.status == FSResultStatus.KILLED:
                outcome.status = ReplayStatus.ABORTED
                outcome.failed_step_index = i
                outcome.reason = "kill switch fired"
                return outcome
            else:
                outcome.status = ReplayStatus.FAILED
                outcome.failed_step_index = i
                outcome.reason = (
                    f"step {i} ({event.action.value}) failed: {result.reason}"
                )
                if abort_on_first_failure:
                    return outcome

        return outcome


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rebuild_event(step, principal: Principal) -> FSActionEvent:
    """Turn a stored step back into an executable event."""
    try:
        action = FSAction(step.tool_name)
    except ValueError as e:
        raise ValueError(f"unknown fs action {step.tool_name!r}") from e

    args = dict(step.arguments or {})
    return FSActionEvent(
        action=action,
        principal=principal,
        paths=list(args.get("paths", []) or []),
        query=str(args.get("query", "") or ""),
        target_dir=str(args.get("target_dir", "") or ""),
        new_name=str(args.get("new_name", "") or ""),
        glob=str(args.get("glob", "") or ""),
        if_exists=str(args.get("if_exists", "error") or "error"),
        max_bytes=int(args.get("max_bytes", 0) or 0),
        limit=int(args.get("limit", 0) or 0),
        ext=str(args.get("ext", "") or ""),
    )


__all__ = [
    "ReplayOutcome",
    "ReplayStatus",
    "RunbookReplayer",
]
