"""
Base LLM interface used by the popover, runbook cache, and CLI.

Praxis exposes a small, protocol-shaped abstraction:

* :class:`LLMBackend` — implement ``async def chat(messages, tools)``
  returning either a plain response or a plan of tool calls.
* :class:`LLMMessage` — role + content pair (system/user/assistant/tool).
* :class:`ToolSpec` — JSON-schema-shaped tool definition.
* :class:`LLMPlan` — the model's proposed tool-call chain (or a plain
  text answer).

Backends are pluggable — Ollama for offline, direct API clients (OpenAI
+ Anthropic) for online, and a null backend for tests.  All of them
return the same shape so the daemon logic doesn't care which one is
active.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class LLMBackendUnavailable(RuntimeError):
    """The requested backend cannot serve the request right now.

    Ollama not running, no API key, wrong model — anything that means
    "try a different backend".  The daemon catches this and falls
    through to the next backend in :class:`LLMRegistry`.
    """


class MessageRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class LLMMessage:
    """A single turn in a chat conversation."""

    role: MessageRole
    content: str
    tool_name: str = ""
    """For role=TOOL, which tool this is the result of."""
    tool_call_id: str = ""
    """For role=TOOL, matches a prior tool call id from the assistant."""

    def to_openai_dict(self) -> dict[str, Any]:
        base = {"role": self.role.value, "content": self.content}
        if self.role == MessageRole.TOOL:
            if self.tool_name:
                base["name"] = self.tool_name
            if self.tool_call_id:
                base["tool_call_id"] = self.tool_call_id
        return base


@dataclass
class ToolSpec:
    """A tool the model can call."""

    name: str
    description: str
    parameters_schema: dict[str, Any] = field(default_factory=dict)
    """JSON schema describing the tool's arguments."""

    def to_openai_dict(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters_schema or {"type": "object", "properties": {}},
            },
        }


@dataclass
class LLMPlanStep:
    """One tool call the model wants us to make."""

    tool_name: str
    arguments: dict[str, Any]
    call_id: str = ""
    """Opaque id the backend uses to match tool result to call."""


@dataclass
class LLMPlan:
    """A plan of tool calls (possibly empty)."""

    steps: list[LLMPlanStep] = field(default_factory=list)
    reasoning: str = ""
    """Optional model-visible reasoning; for logs/debug only, never shown to user by default."""

    @property
    def is_empty(self) -> bool:
        return not self.steps


@dataclass
class LLMResponse:
    """The result of one ``chat()`` call.

    Either the model produced a plain text answer, or a plan of tool
    calls, or both (some models emit text plus one or more tool calls
    in the same turn).
    """

    text: str = ""
    plan: LLMPlan = field(default_factory=LLMPlan)
    model: str = ""
    tokens_prompt: int = 0
    tokens_completion: int = 0
    finish_reason: str = ""

    @property
    def wants_tools(self) -> bool:
        return bool(self.plan.steps)


class LLMBackend(Protocol):
    """The protocol every backend implements."""

    name: str
    """Short label used in status output — 'ollama', 'openai', 'anthropic', 'null'."""

    supports_tools: bool
    """True if the backend can natively emit tool calls.  When False,
    the daemon falls back to a JSON-mode prompt template."""

    async def is_available(self) -> bool:  # pragma: no cover
        """Fast check: can this backend serve a request right now?"""
        ...

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolSpec] | None = None,
        model: str = "",
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:  # pragma: no cover
        """Run one round of chat with the model.

        Implementations must raise :class:`LLMBackendUnavailable` (not
        return a partial answer) if the backend can't serve the request
        — that's how the registry knows to fall through.
        """
        ...


# ---------------------------------------------------------------------------
# Utility — extract a plan from a model's raw text output (JSON mode)
# ---------------------------------------------------------------------------


def parse_plan_from_json_text(text: str) -> LLMPlan:
    """Fallback plan extractor for models that don't support tool calls.

    Looks for a JSON object of shape::

        {"tool_calls": [{"name": "fs_search", "arguments": {"query": "passport"}}, ...]}

    or a bare list ``[{"name":...,"arguments":{...}}, ...]``.

    Returns an empty plan if nothing parses.  Any parse failure is
    silent — the daemon treats no-plan as "just show the text answer".
    """
    if not text:
        return LLMPlan()

    # Find the outermost JSON object/array.
    stripped = text.strip()
    # Try to strip a leading code fence.
    if stripped.startswith("```"):
        first_nl = stripped.find("\n")
        if first_nl != -1:
            stripped = stripped[first_nl + 1 :]
        if stripped.rstrip().endswith("```"):
            stripped = stripped.rstrip()[:-3]
        stripped = stripped.strip()

    # Try direct parse.
    obj: Any = None
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        # Look for the first {...} or [...] slice.
        for start_char, end_char in (("{", "}"), ("[", "]")):
            i = stripped.find(start_char)
            j = stripped.rfind(end_char)
            if i != -1 and j != -1 and j > i:
                candidate = stripped[i : j + 1]
                try:
                    obj = json.loads(candidate)
                    break
                except json.JSONDecodeError:
                    continue
    if obj is None:
        return LLMPlan()

    # Normalise to a list of {name, arguments} entries.
    entries: list[dict[str, Any]] = []
    if isinstance(obj, dict):
        if "tool_calls" in obj and isinstance(obj["tool_calls"], list):
            entries = [e for e in obj["tool_calls"] if isinstance(e, dict)]
        elif "name" in obj:
            entries = [obj]
    elif isinstance(obj, list):
        entries = [e for e in obj if isinstance(e, dict)]

    steps: list[LLMPlanStep] = []
    for entry in entries:
        name = entry.get("name") or entry.get("tool") or ""
        args = entry.get("arguments") or entry.get("args") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if not isinstance(args, dict):
            args = {}
        if name:
            steps.append(LLMPlanStep(tool_name=str(name), arguments=args))
    return LLMPlan(steps=steps)


__all__ = [
    "LLMBackend",
    "LLMBackendUnavailable",
    "LLMMessage",
    "LLMPlan",
    "LLMPlanStep",
    "LLMResponse",
    "MessageRole",
    "ToolSpec",
    "parse_plan_from_json_text",
]
