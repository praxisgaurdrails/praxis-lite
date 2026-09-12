"""Tests for the orchestrator (LLM plan -> guardrail -> execute loop)."""

import pytest

from praxis.approval import ApprovalCoordinator, AutoApproveNotifier, NullAuthenticator
from praxis.filesystem import (
    FSExecutor,
    FSPolicyEngine,
    StagedTrash,
    WalkerBackend,
)
from praxis.kill_switch import KillSwitch, reset_kill_switch_for_tests
from praxis.llm import LLMRegistry, LLMResponse
from praxis.llm.base import LLMPlan, LLMPlanStep, MessageRole
from praxis.orchestrator import Orchestrator
from praxis.principal import Principal


@pytest.fixture(autouse=True)
def _fresh_kill():
    reset_kill_switch_for_tests()
    yield
    reset_kill_switch_for_tests()


@pytest.fixture
def sandbox(tmp_path):
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "passport_2024.pdf").write_bytes(b"pdf")
    (tmp_path / "Downloads").mkdir()
    (tmp_path / "Downloads" / "junk.tmp").write_bytes(b"junk")
    return tmp_path


@pytest.fixture
def executor(tmp_path):
    return FSExecutor(
        policy=FSPolicyEngine(),
        approvals=ApprovalCoordinator(
            notifier=AutoApproveNotifier(),
            authenticator=NullAuthenticator(),
        ),
        trash=StagedTrash(trash_dir=tmp_path / "trash", ttl_seconds=60.0),
        kill_switch=KillSwitch(),
        search_backend=WalkerBackend(),
    )


class _ScriptedBackend:
    """A backend that replays a fixed list of responses in order."""

    name = "scripted"
    supports_tools = True

    def __init__(self, responses: list[LLMResponse]):
        self._responses = list(responses)
        self._i = 0

    async def is_available(self):
        return True

    async def chat(self, messages, tools=None, model="", temperature=0.2, max_tokens=1024):
        if self._i >= len(self._responses):
            # Default: a plain answer to end the loop.
            return LLMResponse(text="done", model=self.name)
        r = self._responses[self._i]
        self._i += 1
        return r


def _plan(*steps) -> LLMPlan:
    return LLMPlan(steps=[LLMPlanStep(tool_name=n, arguments=a) for n, a in steps])


class TestOrchestrator:
    async def test_search_then_answer(self, sandbox, executor):
        backend = _ScriptedBackend([
            LLMResponse(
                model="scripted",
                plan=_plan(("fs.search", {"query": "passport", "paths": [str(sandbox)]})),
            ),
            LLMResponse(text="Found your passport.", model="scripted"),
        ])
        orch = Orchestrator(executor=executor, llm=LLMRegistry([backend]))
        out = await orch.ask("find my passport", principal=Principal.local())
        assert out.ok
        assert out.answer == "Found your passport."
        assert len(out.steps) == 1
        assert out.steps[0].tool_name == "fs.search"
        assert out.steps[0].result.ok

    async def test_guardrail_blocks_secret_read_mid_plan(self, sandbox, executor):
        backend = _ScriptedBackend([
            LLMResponse(
                model="scripted",
                plan=_plan(("fs.read", {"paths": ["~/.ssh/id_rsa"]})),
            ),
            LLMResponse(text="I could not read that file.", model="scripted"),
        ])
        orch = Orchestrator(executor=executor, llm=LLMRegistry([backend]))
        out = await orch.ask("read my ssh key", principal=Principal.local())
        # The step ran but was blocked by the guardrail.
        assert len(out.steps) == 1
        assert not out.steps[0].result.ok
        assert out.steps[0].result.status.value == "blocked"

    async def test_agent_principal_delete_blocked(self, sandbox, executor):
        backend = _ScriptedBackend([
            LLMResponse(
                model="scripted",
                plan=_plan(("fs.delete", {"paths": [str(sandbox / "Downloads" / "junk.tmp")]})),
            ),
            LLMResponse(text="Cannot delete as an agent.", model="scripted"),
        ])
        orch = Orchestrator(executor=executor, llm=LLMRegistry([backend]))
        out = await orch.ask(
            "delete junk",
            principal=Principal.agent("openclaw"),
        )
        assert out.steps[0].result.status.value == "blocked"
        assert (sandbox / "Downloads" / "junk.tmp").exists()

    async def test_default_search_roots_injected(self, sandbox, executor):
        # Model omits paths — orchestrator must inject the default roots.
        backend = _ScriptedBackend([
            LLMResponse(
                model="scripted",
                plan=_plan(("fs.search", {"query": "passport"})),
            ),
            LLMResponse(text="found", model="scripted"),
        ])
        orch = Orchestrator(executor=executor, llm=LLMRegistry([backend]))
        out = await orch.ask(
            "find passport",
            principal=Principal.local(),
            default_search_roots=[str(sandbox)],
        )
        assert out.steps[0].result.ok
        hits = out.steps[0].result.result["hits"]
        assert any("passport" in h["path"] for h in hits)

    async def test_max_rounds_guard(self, sandbox, executor):
        # A backend that always wants a tool → must stop at max_rounds.
        class _Loop:
            name = "loop"
            supports_tools = True
            async def is_available(self): return True
            async def chat(self, messages, tools=None, model="", temperature=0.2, max_tokens=1024):
                return LLMResponse(model="loop", plan=_plan(("fs.search", {"query": "x", "paths": [str(sandbox)]})))

        orch = Orchestrator(executor=executor, llm=LLMRegistry([_Loop()]), max_rounds=3)
        out = await orch.ask("loop forever", principal=Principal.local())
        assert out.rounds == 3
        assert len(out.steps) == 3

    async def test_no_backend_available_returns_error(self, executor):
        class _Down:
            name = "down"
            supports_tools = True
            async def is_available(self): return False
            async def chat(self, *a, **k): raise AssertionError("should not be called")

        orch = Orchestrator(executor=executor, llm=LLMRegistry([_Down()]))
        out = await orch.ask("hi", principal=Principal.local())
        assert not out.ok
        assert "Ollama" in out.error or "backend" in out.error
