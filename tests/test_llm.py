"""Tests for the Ollama backend + LLM registry."""

from unittest.mock import AsyncMock, patch

import pytest

from praxis.llm import (
    LLMBackendUnavailable,
    LLMMessage,
    LLMPlan,
    LLMPlanStep,
    LLMRegistry,
    LLMResponse,
    OllamaBackend,
    ToolSpec,
)
from praxis.llm.base import MessageRole, parse_plan_from_json_text


# ---------------------------------------------------------------------------
# parse_plan_from_json_text
# ---------------------------------------------------------------------------


class TestParsePlan:
    def test_returns_empty_for_empty(self):
        assert parse_plan_from_json_text("").is_empty

    def test_parses_direct_tool_calls_object(self):
        p = parse_plan_from_json_text(
            '{"tool_calls": [{"name": "fs_search", '
            '"arguments": {"query": "passport"}}]}'
        )
        assert len(p.steps) == 1
        assert p.steps[0].tool_name == "fs_search"
        assert p.steps[0].arguments == {"query": "passport"}

    def test_parses_bare_list(self):
        p = parse_plan_from_json_text(
            '[{"name": "fs_read", "arguments": {"path": "~/a"}}]'
        )
        assert len(p.steps) == 1
        assert p.steps[0].tool_name == "fs_read"

    def test_strips_code_fence(self):
        p = parse_plan_from_json_text(
            '```json\n{"tool_calls": [{"name": "fs_stat", '
            '"arguments": {"path": "/tmp"}}]}\n```'
        )
        assert len(p.steps) == 1

    def test_string_arguments_parsed(self):
        p = parse_plan_from_json_text(
            '{"tool_calls": [{"name": "fs_search", '
            '"arguments": "{\\"query\\": \\"x\\"}"}]}'
        )
        assert p.steps[0].arguments == {"query": "x"}

    def test_junk_returns_empty(self):
        assert parse_plan_from_json_text("random noise not JSON").is_empty


# ---------------------------------------------------------------------------
# Ollama availability probes
# ---------------------------------------------------------------------------


class TestOllamaAvailability:
    async def test_not_running_returns_false(self):
        # Point at an obviously wrong port.
        b = OllamaBackend(host="http://127.0.0.1:1", connect_timeout_seconds=0.1)
        assert not await b.is_available()

    async def test_is_available_hits_tags(self):
        # Mock httpx to simulate Ollama responding with 200.
        import httpx

        async def _fake_get(self, url, *a, **kw):
            class R:
                status_code = 200
                def json(self_inner):
                    return {"models": [{"name": "llama3.2:3b"}]}
                def raise_for_status(self_inner):
                    pass
            return R()

        with patch.object(httpx.AsyncClient, "get", new=_fake_get):
            b = OllamaBackend()
            assert await b.is_available()
            models = await b.list_models()
            assert "llama3.2:3b" in models

    async def test_has_model_matches_prefix(self):
        import httpx

        async def _fake_get(self, url, *a, **kw):
            class R:
                status_code = 200
                def json(self_inner):
                    return {"models": [{"name": "llama3.2:3b"}]}
                def raise_for_status(self_inner):
                    pass
            return R()

        with patch.object(httpx.AsyncClient, "get", new=_fake_get):
            b = OllamaBackend()
            assert await b.has_model("llama3.2:3b")
            assert not await b.has_model("gpt-4o")


# ---------------------------------------------------------------------------
# Ollama chat with mocked responses
# ---------------------------------------------------------------------------


class TestOllamaChat:
    async def test_chat_returns_plan_from_native_tools(self):
        import httpx

        posted = {}

        class _FakeGet:
            def __init__(self, url):
                self.status_code = 200
                self._url = url
            def json(self):
                return {"models": [{"name": "llama3.2:3b"}]}
            def raise_for_status(self):
                pass

        class _FakePost:
            status_code = 200
            def json(self):
                return {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "fs_search",
                                    "arguments": {"query": "passport"},
                                }
                            }
                        ],
                    },
                    "prompt_eval_count": 100,
                    "eval_count": 20,
                    "done_reason": "stop",
                }
            def raise_for_status(self):
                pass

        async def _fake_get(self, url, *a, **kw):
            return _FakeGet(url)

        async def _fake_post(self, url, *a, **kw):
            posted["url"] = url
            posted["payload"] = kw.get("json") or (a[0] if a else None)
            return _FakePost()

        with patch.object(httpx.AsyncClient, "get", new=_fake_get), \
             patch.object(httpx.AsyncClient, "post", new=_fake_post):
            b = OllamaBackend()
            r = await b.chat(
                messages=[LLMMessage(role=MessageRole.USER, content="find my passport")],
                tools=[ToolSpec(name="fs_search", description="search files")],
            )
        assert r.wants_tools
        assert r.plan.steps[0].tool_name == "fs_search"
        assert r.plan.steps[0].arguments == {"query": "passport"}
        assert r.tokens_prompt == 100
        assert r.tokens_completion == 20
        assert "tools" in posted["payload"]

    async def test_chat_raises_when_unavailable(self):
        b = OllamaBackend(host="http://127.0.0.1:1", connect_timeout_seconds=0.1)
        with pytest.raises(LLMBackendUnavailable):
            await b.chat(
                messages=[LLMMessage(role=MessageRole.USER, content="hi")],
            )


# ---------------------------------------------------------------------------
# Registry fallthrough
# ---------------------------------------------------------------------------


class _StaticBackend:
    """Simple backend used to test the registry."""

    def __init__(
        self,
        name: str,
        available: bool = True,
        response: LLMResponse | None = None,
        raise_unavailable: bool = False,
    ):
        self.name = name
        self.supports_tools = True
        self._available = available
        self._response = response or LLMResponse(text="ok", model=name)
        self._raise_unavailable = raise_unavailable

    async def is_available(self):
        return self._available

    async def chat(self, messages, tools=None, model="", temperature=0.2, max_tokens=1024):
        if self._raise_unavailable:
            raise LLMBackendUnavailable(f"{self.name} down mid-request")
        return self._response


class TestRegistry:
    async def test_first_available_wins(self):
        r = LLMRegistry([
            _StaticBackend("cloud", available=True,
                           response=LLMResponse(text="cloud reply")),
            _StaticBackend("ollama", available=True,
                           response=LLMResponse(text="ollama reply")),
        ])
        out = await r.chat([LLMMessage(role=MessageRole.USER, content="q")])
        assert out.text == "cloud reply"

    async def test_falls_through_when_first_unavailable(self):
        r = LLMRegistry([
            _StaticBackend("cloud", available=False),
            _StaticBackend("ollama", available=True,
                           response=LLMResponse(text="fallback")),
        ])
        out = await r.chat([LLMMessage(role=MessageRole.USER, content="q")])
        assert out.text == "fallback"

    async def test_falls_through_when_first_raises(self):
        r = LLMRegistry([
            _StaticBackend("cloud", available=True, raise_unavailable=True),
            _StaticBackend("ollama", available=True,
                           response=LLMResponse(text="fallback")),
        ])
        out = await r.chat([LLMMessage(role=MessageRole.USER, content="q")])
        assert out.text == "fallback"

    async def test_all_down_raises(self):
        r = LLMRegistry([
            _StaticBackend("cloud", available=False),
            _StaticBackend("ollama", available=False),
        ])
        with pytest.raises(LLMBackendUnavailable):
            await r.chat([LLMMessage(role=MessageRole.USER, content="q")])

    async def test_empty_registry_raises(self):
        r = LLMRegistry([])
        with pytest.raises(LLMBackendUnavailable):
            await r.chat([LLMMessage(role=MessageRole.USER, content="q")])
