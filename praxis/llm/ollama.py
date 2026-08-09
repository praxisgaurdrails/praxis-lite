"""
Ollama backend — the local LLM for offline mode.

Talks HTTP to a locally-running Ollama daemon at
``http://127.0.0.1:11434``.  Uses Ollama's ``/api/chat`` endpoint which
supports the OpenAI-style tools schema natively as of Ollama 0.4+.

If Ollama isn't running or the requested model isn't pulled, we raise
:class:`~praxis.llm.base.LLMBackendUnavailable` so the registry
falls through.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from praxis.llm.base import (
    LLMBackend,
    LLMBackendUnavailable,
    LLMMessage,
    LLMPlan,
    LLMPlanStep,
    LLMResponse,
    MessageRole,
    ToolSpec,
    parse_plan_from_json_text,
)

logger = logging.getLogger("praxis.llm.ollama")


DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2:3b"
"""Default model.  ~2 GB Q4 quant, fast on M-series CPU, good enough
tool-calling for our fs.* surface.  Users can pick another via
``--model`` or the config file."""

_TOOL_CAPABLE_MODELS = frozenset({
    # Models known to support Ollama's native tools API well.
    "llama3.1", "llama3.2", "llama3.3",
    "qwen2.5", "qwen3",
    "mistral", "mistral-nemo",
    "firefunction", "command-r",
})


def _model_supports_tools(model: str) -> bool:
    """Best-effort — allow the caller to opt in by prefix match."""
    if not model:
        return False
    stem = model.split(":", 1)[0].lower()
    return any(stem.startswith(family) or stem == family for family in _TOOL_CAPABLE_MODELS)


class OllamaBackend:
    """LLMBackend for a locally-running Ollama daemon."""

    name = "ollama"
    supports_tools = True

    def __init__(
        self,
        host: str = DEFAULT_OLLAMA_HOST,
        default_model: str = DEFAULT_OLLAMA_MODEL,
        connect_timeout_seconds: float = 2.0,
        request_timeout_seconds: float = 120.0,
    ) -> None:
        self._host = host.rstrip("/")
        self._default_model = default_model
        self._connect_timeout = connect_timeout_seconds
        self._request_timeout = request_timeout_seconds

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    async def is_available(self) -> bool:
        """Fast HEAD-shaped probe against ``/api/tags``."""
        try:
            async with httpx.AsyncClient(timeout=self._connect_timeout) as c:
                r = await c.get(f"{self._host}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        """Return the list of models Ollama has pulled."""
        try:
            async with httpx.AsyncClient(timeout=self._connect_timeout) as c:
                r = await c.get(f"{self._host}/api/tags")
                r.raise_for_status()
                data = r.json()
                return [m.get("name", "") for m in data.get("models", []) if m.get("name")]
        except Exception as e:
            logger.debug("ollama list_models failed: %s", e)
            return []

    async def has_model(self, model: str) -> bool:
        models = await self.list_models()
        return any(m == model or m.startswith(f"{model}:") for m in models)

    # ------------------------------------------------------------------
    # Chat
    # ------------------------------------------------------------------

    async def chat(
        self,
        messages: list[LLMMessage],
        tools: list[ToolSpec] | None = None,
        model: str = "",
        temperature: float = 0.2,
        max_tokens: int = 1024,
    ) -> LLMResponse:
        """Run one chat round against Ollama."""
        model = model or self._default_model

        if not await self.is_available():
            raise LLMBackendUnavailable(
                "Ollama is not running at "
                f"{self._host}.  Install from https://ollama.com and "
                "run `ollama serve` (or start the app)."
            )

        if not await self.has_model(model):
            raise LLMBackendUnavailable(
                f"Ollama model {model!r} is not pulled.  Run "
                f"`ollama pull {model}` and retry."
            )

        # --- Build the request payload ---
        native_tools_ok = bool(tools) and _model_supports_tools(model)

        payload: dict[str, Any] = {
            "model": model,
            "stream": False,
            "options": {
                "temperature": float(temperature),
                "num_predict": int(max_tokens),
            },
            "messages": [_msg_to_ollama(m) for m in messages],
        }
        if tools and native_tools_ok:
            payload["tools"] = [_tool_to_ollama(t) for t in tools]
        elif tools:
            # Fallback: JSON-mode prompt.  Prepend a system message
            # instructing the model to reply with a JSON tool_calls
            # blob; parse it out with the base parser.
            payload["messages"].insert(
                0,
                {
                    "role": "system",
                    "content": _fallback_tools_prompt(tools),
                },
            )
            payload["format"] = "json"

        # --- Send ---
        try:
            async with httpx.AsyncClient(timeout=self._request_timeout) as c:
                r = await c.post(f"{self._host}/api/chat", json=payload)
                r.raise_for_status()
                body = r.json()
        except httpx.HTTPError as e:
            raise LLMBackendUnavailable(f"ollama HTTP error: {e}") from e

        return _parse_response(body, model=model, tools_native=native_tools_ok)


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------


def _msg_to_ollama(m: LLMMessage) -> dict[str, Any]:
    d: dict[str, Any] = {"role": m.role.value, "content": m.content}
    if m.role == MessageRole.TOOL and m.tool_name:
        d["name"] = m.tool_name
    return d


def _tool_to_ollama(t: ToolSpec) -> dict[str, Any]:
    """Ollama uses OpenAI-shape tools."""
    return t.to_openai_dict()


def _fallback_tools_prompt(tools: list[ToolSpec]) -> str:
    tool_descs = []
    for t in tools:
        params = t.parameters_schema or {"type": "object", "properties": {}}
        tool_descs.append(
            f"- {t.name}: {t.description.strip()}\n  args schema: {json.dumps(params)}"
        )
    return (
        "You are the planner of an agentic tool. Reply with STRICT JSON "
        "shaped {\"tool_calls\": [{\"name\": <tool>, \"arguments\": {...}}, ...]}. "
        "Do not include any text outside the JSON.  If no tool is "
        "appropriate, reply {\"tool_calls\": []}.\n\n"
        "Available tools:\n" + "\n".join(tool_descs)
    )


def _parse_response(
    body: dict[str, Any],
    model: str,
    tools_native: bool,
) -> LLMResponse:
    msg = body.get("message", {}) or {}
    text = str(msg.get("content", "") or "")

    plan = LLMPlan()
    if tools_native:
        # Native tool_calls in the message.
        for i, tc in enumerate(msg.get("tool_calls", []) or []):
            fn = (tc.get("function") or tc) or {}
            name = fn.get("name") or tc.get("name") or ""
            args = fn.get("arguments", {}) or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            if name:
                plan.steps.append(
                    LLMPlanStep(
                        tool_name=str(name),
                        arguments=args if isinstance(args, dict) else {},
                        call_id=str(tc.get("id", "") or f"tc_{i}"),
                    )
                )
    else:
        # Fallback: parse JSON out of the text.
        plan = parse_plan_from_json_text(text)
        if plan.steps:
            # Text was really a plan blob — don't show it to the user as
            # an answer.
            text = ""

    return LLMResponse(
        text=text,
        plan=plan,
        model=model,
        tokens_prompt=int(body.get("prompt_eval_count", 0) or 0),
        tokens_completion=int(body.get("eval_count", 0) or 0),
        finish_reason=str(body.get("done_reason", "") or ""),
    )


__all__ = [
    "DEFAULT_OLLAMA_HOST",
    "DEFAULT_OLLAMA_MODEL",
    "OllamaBackend",
]
