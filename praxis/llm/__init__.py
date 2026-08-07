"""Praxis LLM adapters — cloud + local backends the popover / runbook use."""

from praxis.llm.base import (
    LLMBackend,
    LLMBackendUnavailable,
    LLMMessage,
    LLMPlan,
    LLMPlanStep,
    LLMResponse,
    ToolSpec,
)
from praxis.llm.ollama import OllamaBackend, DEFAULT_OLLAMA_HOST, DEFAULT_OLLAMA_MODEL
from praxis.llm.registry import (
    LLMRegistry,
    default_registry,
)

__all__ = [
    "DEFAULT_OLLAMA_HOST",
    "DEFAULT_OLLAMA_MODEL",
    "LLMBackend",
    "LLMBackendUnavailable",
    "LLMMessage",
    "LLMPlan",
    "LLMPlanStep",
    "LLMResponse",
    "LLMRegistry",
    "OllamaBackend",
    "ToolSpec",
    "default_registry",
]
