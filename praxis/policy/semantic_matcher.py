"""
Semantic (NLP) intent matching — availability stub for Praxis Lite.

The full semantic matcher (sentence embeddings via fastembed/ONNX) is a
Praxis Full feature. Lite ships this dependency-free stub so the policy
engine imports cleanly and transparently falls back to its fast,
deterministic keyword/intent matching. Every function here reports
"semantic unavailable".

The ``SemanticMatch`` dataclass and ``SEMANTIC_RISK_MAP`` are pure data
(no ML dependency) and are preserved so callers keep working unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass


SEMANTIC_RISK_MAP: dict[str, str] = {
    "payment": "high",
    "delete": "high",
    "authentication": "high",
    "admin": "high",
    "financial": "high",
    "permission": "high",
    "system": "high",
    "destructive_system": "critical",
    "sensitive_field": "high",
    "data_entry": "medium",
    "posting": "medium",
    "messaging": "medium",
    "sharing": "medium",
    "modifying": "medium",
    "uploading": "medium",
    "downloading": "medium",
    "social": "low",
    "navigation": "low",
    "api_call": "high",
}


@dataclass
class SemanticMatch:
    """Result of a semantic intent classification."""

    intent: str
    score: float
    risk: str  # "low", "medium", "high", "critical"
    description: str = ""

    @property
    def confident(self) -> bool:
        """Is this match confident enough to act on?"""
        return self.score >= 0.65


def is_semantic_available() -> bool:
    """Semantic NLP matching is a Full-edition feature; always False in Lite."""
    return False


def semantic_classify(text: str, threshold: float = 0.55) -> list[SemanticMatch]:
    return []


def semantic_detect_intents(text: str, threshold: float = 0.55) -> list[tuple[str, float]]:
    return []


def semantic_risk(text: str, threshold: float = 0.55) -> str:
    return "safe"


def semantic_matches_intent(intent: str, text: str, threshold: float = 0.55) -> bool:
    return False


__all__ = [
    "SEMANTIC_RISK_MAP",
    "SemanticMatch",
    "is_semantic_available",
    "semantic_classify",
    "semantic_detect_intents",
    "semantic_risk",
    "semantic_matches_intent",
]
