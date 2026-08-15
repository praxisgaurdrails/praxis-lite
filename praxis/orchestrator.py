"""
Praxis orchestrator — the offline "ask" loop.

Turns a natural-language request into governed tool calls:

    user text
       │
       ▼
    LLM (Ollama offline / cloud online) proposes tool calls
       │
       ▼
    each proposed call → FSExecutor (policy + tier gate + approval)
       │
       ▼
    tool results fed back to the LLM
       │
       ▼
    repeat until the LLM stops calling tools → final text answer

The orchestrator NEVER lets the LLM touch the filesystem directly.
Every proposed tool call goes through :class:`~praxis.filesystem.executor.FSExecutor`,
so the same guardrail (principal + tier + path safety + approval +
evidence) applies whether the request came from a cloud agent, a local
agent, or the user's own popover.

This is the piece that makes "the guardrail is always in the loop" true
even for offline local-LLM planning.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from praxis.evidence.vault import EvidenceSession
from praxis.filesystem.executor import FSExecutor
from praxis.filesystem.types import (
    FS_TIER,
    FSAction,
    FSActionEvent,
    FSResult,
    FSResultStatus,
)
from praxis.llm.base import (
    LLMBackendUnavailable,
    LLMMessage,
    LLMResponse,
    MessageRole,
    ToolSpec,
)
from praxis.llm.registry import LLMRegistry
from praxis.principal import Principal

logger = logging.getLogger("praxis.orchestrator")


# ---------------------------------------------------------------------------
# Tool specs — describe the FS surface to the LLM
# ---------------------------------------------------------------------------


def _fs_tool_specs() -> list[ToolSpec]:
    """Build the JSON-schema tool specs the LLM sees.

    We expose the FS tools under their dotted names so the model's
    output maps 1:1 onto :class:`FSAction`.
    """
    specs: list[ToolSpec] = []

    specs.append(ToolSpec(
        name="fs.search",
        description=(
            "Search the user's disk by filename. Returns ranked file "
            "paths. Use this first to locate files by name."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "text to search for"},
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "dirs to search (empty = home)",
                },
                "ext": {"type": "string", "description": "extension filter, e.g. pdf"},
                "limit": {"type": "integer", "description": "max results"},
            },
            "required": ["query"],
        },
    ))
    specs.append(ToolSpec(
        name="fs.read",
        description="Read a file's text contents. Refuses credential stores.",
        parameters_schema={
            "type": "object",
            "properties": {
                "paths": {"type": "array", "items": {"type": "string"}},
                "max_bytes": {"type": "integer"},
            },
            "required": ["paths"],
        },
    ))
    specs.append(ToolSpec(
        name="fs.stat",
        description="Get metadata (size, mtime, type) for a path.",
        parameters_schema={
            "type": "object",
            "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
            "required": ["paths"],
        },
    ))
    specs.append(ToolSpec(
        name="fs.list_dir",
        description="List entries in a directory.",
        parameters_schema={
            "type": "object",
            "properties": {
                "paths": {"type": "array", "items": {"type": "string"}},
                "glob": {"type": "string"},
            },
            "required": ["paths"],
        },
    ))
    specs.append(ToolSpec(
        name="fs.create_dir",
        description="Create a directory. Requires user approval for agents.",
        parameters_schema={
            "type": "object",
            "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
            "required": ["paths"],
        },
    ))
    specs.append(ToolSpec(
        name="fs.create_file",
        description="Create a new file with content. Requires approval for agents.",
        parameters_schema={
            "type": "object",
            "properties": {
                "paths": {"type": "array", "items": {"type": "string"}},
                "content": {"type": "string"},
            },
            "required": ["paths"],
        },
    ))
    specs.append(ToolSpec(
        name="fs.move",
        description="Move files to a target directory. Destructive — needs approval.",
        parameters_schema={
            "type": "object",
            "properties": {
                "paths": {"type": "array", "items": {"type": "string"}},
                "target_dir": {"type": "string"},
            },
            "required": ["paths", "target_dir"],
        },
    ))
    specs.append(ToolSpec(
        name="fs.delete",
        description=(
            "Delete files (staged to trash, recoverable 24h). Destructive "
            "— needs approval; blocked for external agents by default."
        ),
        parameters_schema={
            "type": "object",
            "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
            "required": ["paths"],
        },
    ))
    return specs


SYSTEM_PROMPT = (
    "You are Praxis, a local assistant that operates the user's computer "
    "through a set of governed filesystem tools. When the user asks you to "
    "find, read, organize, create, move, or delete files, use the tools. "
    "Call fs.search first to locate files by name. Use real absolute paths "
    "the tools returned — never invent paths. When you have completed the "
    "user's request, stop calling tools and give a short plain-language "
    "summary of what you did. If a tool is blocked by policy, tell the user "
    "plainly and do not retry the same blocked call."
)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass
class OrchestratorStep:
    """One tool call the orchestrator executed."""

    tool_name: str
    arguments: dict[str, Any]
    result: FSResult

    def summary(self) -> str:
        status = self.result.status.value
        return f"{self.tool_name}({_short_args(self.arguments)}) -> {status}"


@dataclass
class OrchestratorOutcome:
    """The full result of an ``ask`` run."""

    answer: str = ""
    steps: list[OrchestratorStep] = field(default_factory=list)
    rounds: int = 0
    llm_backend: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class Orchestrator:
    """Runs the plan → execute → feed-back loop.

    Constructed with an executor + an LLM registry.  The executor
    supplies the guardrail; the registry supplies the (cloud-or-local)
    planner.
    """

    def __init__(
        self,
        executor: FSExecutor,
        llm: LLMRegistry,
        max_rounds: int = 6,
        model: str = "",
    ) -> None:
        self._executor = executor
        self._llm = llm
        self._max_rounds = max(1, int(max_rounds))
        self._model = model
        self._tools = _fs_tool_specs()

    async def ask(
        self,
        user_text: str,
        principal: Principal,
        session: EvidenceSession | None = None,
        default_search_roots: list[str] | None = None,
    ) -> OrchestratorOutcome:
        """Answer a natural-language request through governed tools."""
        outcome = OrchestratorOutcome()

        messages: list[LLMMessage] = [
            LLMMessage(role=MessageRole.SYSTEM, content=SYSTEM_PROMPT),
        ]
        if default_search_roots:
            messages.append(LLMMessage(
                role=MessageRole.SYSTEM,
                content=(
                    "Default directories to search when the user doesn't "
                    "specify: " + ", ".join(default_search_roots)
                ),
            ))
        messages.append(LLMMessage(role=MessageRole.USER, content=user_text))

        for round_i in range(self._max_rounds):
            outcome.rounds = round_i + 1
            try:
                response: LLMResponse = await self._llm.chat(
                    messages=messages,
                    tools=self._tools,
                    model=self._model,
                )
            except LLMBackendUnavailable as e:
                outcome.error = (
                    f"No LLM backend available: {e}. Install Ollama "
                    "(https://ollama.com) and run `ollama pull llama3.2:3b`, "
                    "or configure a cloud API key."
                )
                return outcome

            outcome.llm_backend = response.model

            # No tool calls → the model has answered.
            if not response.wants_tools:
                outcome.answer = response.text.strip()
                return outcome

            # Record the assistant's tool-call turn.
            messages.append(LLMMessage(
                role=MessageRole.ASSISTANT,
                content=response.text or "(calling tools)",
            ))

            # Execute each proposed tool call through the guardrail.
            for step in response.plan.steps:
                fs_result = await self._execute_step(
                    tool_name=step.tool_name,
                    arguments=step.arguments,
                    principal=principal,
                    session=session,
                    default_search_roots=default_search_roots,
                )
                outcome.steps.append(OrchestratorStep(
                    tool_name=step.tool_name,
                    arguments=step.arguments,
                    result=fs_result,
                ))
                # Feed the result back to the model.
                messages.append(LLMMessage(
                    role=MessageRole.TOOL,
                    tool_name=step.tool_name,
                    content=_result_for_llm(fs_result),
                ))

        # Ran out of rounds — return whatever we have.
        outcome.answer = (
            outcome.answer
            or "Reached the step limit before finishing. "
            "Here is what I did:\n"
            + "\n".join(s.summary() for s in outcome.steps)
        )
        return outcome

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _execute_step(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        principal: Principal,
        session: EvidenceSession | None,
        default_search_roots: list[str] | None,
    ) -> FSResult:
        """Build an FSActionEvent from a proposed call and execute it."""
        try:
            action = FSAction(tool_name)
        except ValueError:
            # Unknown tool — synthesise a failed result the model can see.
            return FSResult(
                status=FSResultStatus.ERROR,
                action=FSAction.STAT,  # placeholder
                request_id="",
                reason=f"unknown tool {tool_name!r}",
            )

        args = dict(arguments or {})
        content = args.get("content")
        if isinstance(content, str):
            content = content.encode("utf-8")

        paths = args.get("paths") or []
        if isinstance(paths, str):
            paths = [paths]

        # Default search roots when the model omits paths on a search.
        if action == FSAction.SEARCH and not paths and default_search_roots:
            paths = list(default_search_roots)

        event = FSActionEvent(
            action=action,
            principal=principal,
            paths=list(paths),
            query=str(args.get("query", "")),
            target_dir=str(args.get("target_dir", "")),
            new_name=str(args.get("new_name", "")),
            glob=str(args.get("glob", "")),
            if_exists=str(args.get("if_exists", "error")),
            max_bytes=int(args.get("max_bytes", 0) or 0),
            content=content,
            limit=int(args.get("limit", 0) or 0),
            ext=str(args.get("ext", "")),
        )
        return await self._executor.execute(event, session=session)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _short_args(args: dict[str, Any]) -> str:
    bits = []
    for k, v in args.items():
        if k == "content":
            v = f"<{len(v)} bytes>"
        bits.append(f"{k}={v!r}")
    return ", ".join(bits)[:120]


def _result_for_llm(result: FSResult) -> str:
    """Render a tool result compactly for the model to read.

    We give the model the status + the payload, but keep it small so a
    3B local model doesn't drown.
    """
    payload: dict[str, Any] = {
        "status": result.status.value,
        "reason": result.reason,
    }
    if result.status == FSResultStatus.SUCCESS:
        res = result.result or {}
        # Search hits — just the paths + scores.
        if "hits" in res:
            payload["hits"] = [
                {"path": h.get("path"), "score": h.get("score")}
                for h in res["hits"][:10]
            ]
        elif "entries" in res:
            payload["entries"] = [e.get("name") for e in res["entries"][:30]]
        elif "bytes" in res:
            text = res["bytes"]
            payload["content"] = text[:2000]
            payload["truncated"] = res.get("truncated", False)
        else:
            payload["result"] = res
    else:
        payload["matched_rule"] = result.decision_matched_rule
    return json.dumps(payload)


__all__ = [
    "Orchestrator",
    "OrchestratorOutcome",
    "OrchestratorStep",
    "SYSTEM_PROMPT",
]
