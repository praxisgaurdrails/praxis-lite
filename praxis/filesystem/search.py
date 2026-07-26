"""
Praxis fuzzy-filename search — the v1 RAG.

Wraps a raw backend (Spotlight / plocate / walker) with:

* **Synonym expansion** — the query is expanded via the existing
  ``INTENT_SYNONYMS`` table plus a small filename-specific augment so
  a search for "passport" also probes "id", "travel doc", "visa".
* **Prefix + fuzzy rerank** — RapidFuzz scores every candidate.  A
  configurable weight blends fuzzy match, mtime recency, and a
  directory prior (files under `~/Documents` outrank
  ``~/Library/Caches`` at the same fuzz score).
* **De-dup, cap, and a system-dir denylist.**

The result is a list of :class:`SearchHit` objects sorted best-first.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from rapidfuzz import fuzz

from praxis.filesystem.search_backends import (
    SearchBackend,
    SearchCandidate,
    pick_default_backend,
)
from praxis.policy.intent_matcher import INTENT_SYNONYMS

logger = logging.getLogger("praxis.filesystem.search")


# ---------------------------------------------------------------------------
# Filename-specific synonym augment
# ---------------------------------------------------------------------------
#
# The browser-side ``INTENT_SYNONYMS`` covers verbs like "delete" or
# "pay" — great for UI text but weak on the noun-heavy things users
# store in files.  This table layers on top for filename search only.

_FILENAME_SYNONYMS: dict[str, list[str]] = {
    "passport": ["passport", "id", "identity", "travel", "visa"],
    "resume": ["resume", "cv", "curriculum", "vitae"],
    "invoice": ["invoice", "receipt", "bill", "statement"],
    "tax": ["tax", "1040", "w-2", "w2", "irs", "return"],
    "id": ["id", "identity", "passport", "license", "aadhaar", "pan"],
    "photo": ["photo", "img", "image", "pic", "picture"],
    "screenshot": ["screenshot", "screen", "capture", "shot"],
    "contract": ["contract", "agreement", "nda", "moa", "mou"],
    "diploma": ["diploma", "degree", "certificate", "cert"],
    "resume_": ["resume", "cv"],
}


def _expand_query(raw: str) -> list[str]:
    """Return unique lower-case query variants for a raw search term."""
    seen: dict[str, None] = {}
    q = raw.strip()
    if not q:
        return []
    seen[q.lower()] = None
    key = q.lower()

    # 1) Filename-specific synonyms
    for base, variants in _FILENAME_SYNONYMS.items():
        if base in key or any(v in key for v in variants):
            for v in variants:
                seen[v.lower()] = None

    # 2) Reuse the existing intent-synonym table where it fits
    for base, variants in INTENT_SYNONYMS.items():
        # Only expand intents whose *base* is a token in the query.
        if base in key.split() or key == base:
            for v in variants:
                seen[v.lower()] = None
    return list(seen.keys())


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SearchHit:
    path: str
    score: float
    """Blended score in [0, 100].  Higher is better."""
    fuzzy_score: float
    directory_prior: float
    recency_score: float
    matched_query: str
    """The expanded query variant that produced the best fuzzy score."""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "score": round(self.score, 2),
            "fuzzy_score": round(self.fuzzy_score, 2),
            "directory_prior": round(self.directory_prior, 2),
            "recency_score": round(self.recency_score, 2),
            "matched_query": self.matched_query,
        }


# Directory priors — additive score bumps out of 100.  Keeps the
# scoring interpretable ("this hit got +15 because it's in Documents").
_DIRECTORY_PRIORS: list[tuple[str, float]] = [
    ("~/Documents", 15.0),
    ("~/Desktop", 12.0),
    ("~/Downloads", 12.0),
    ("~/Notes", 10.0),
    ("~/Library/Caches", -20.0),
    ("~/.cache", -20.0),
    ("~/.Trash", -30.0),
    (".git", -10.0),
    ("node_modules", -25.0),
    (".venv", -25.0),
    (".praxis/trash", -50.0),
]


def _directory_prior(path: str) -> float:
    """Return a small +/- bump based on which dir the file lives in."""
    home = str(Path.home())
    p = path.replace(home, "~")
    for marker, bump in _DIRECTORY_PRIORS:
        if marker in p:
            return bump
    return 0.0


def _recency_score(mtime: float, now: float) -> float:
    """Recent files get a small bump.  Older than a year: no bump."""
    if mtime <= 0:
        return 0.0
    age_days = max(0.0, (now - mtime) / 86400.0)
    if age_days > 365:
        return 0.0
    # Exponential decay: within a week ~= full 10 bump; year ~= ~2.
    import math

    return 10.0 * math.exp(-age_days / 60.0)


def _extension_match(path: str, ext: str) -> bool:
    if not ext:
        return True
    e = ext.lower().lstrip(".")
    return path.lower().endswith("." + e)


# ---------------------------------------------------------------------------
# The public search function
# ---------------------------------------------------------------------------


def search_filenames(
    query: str,
    roots: Iterable[str] | None = None,
    ext: str = "",
    limit: int = 10,
    backend: SearchBackend | None = None,
    now: float | None = None,
) -> list[SearchHit]:
    """Run the v1 filename fuzzy search.

    Steps:

    1. Expand the query via :func:`_expand_query`.
    2. For each variant, ask the backend for raw candidates.
    3. De-dup, extension-filter, fuzzy-rerank, apply priors.
    4. Return the top ``limit`` hits.

    Backends time out after a couple of seconds — a slow filesystem
    should not stall the caller.
    """
    now = now if now is not None else time.time()
    backend = backend or pick_default_backend()
    q = query.strip()
    if not q:
        return []

    roots_list = [str(r) for r in (roots or [str(Path.home())])]
    variants = _expand_query(q) or [q.lower()]

    # Collect raw candidates from every variant.
    seen: dict[str, SearchCandidate] = {}
    for variant in variants:
        try:
            batch = backend.query(variant, roots_list, limit=limit)
        except Exception:
            logger.exception("search backend %s crashed on %r", backend.name, variant)
            batch = []
        for c in batch:
            if c.path not in seen:
                seen[c.path] = c

    # Score every candidate against the original query (not the variants).
    hits: list[SearchHit] = []
    query_lower = q.lower()
    for cand in seen.values():
        if not _extension_match(cand.path, ext):
            continue
        basename = os.path.basename(cand.path)

        # Best fuzzy score across variants using the *basename* (users
        # typing "pass" want the passport file, not the whole path).
        best_fuzzy = 0.0
        best_variant = query_lower
        for variant in variants:
            score = float(fuzz.partial_ratio(variant, basename.lower()))
            if score > best_fuzzy:
                best_fuzzy = score
                best_variant = variant

        # Also allow prefix boost — typing "pass" gets an extra 10 on
        # anything starting with "pass".
        prefix_boost = 10.0 if basename.lower().startswith(query_lower) else 0.0

        prior = _directory_prior(cand.path)
        recency = _recency_score(cand.mtime, now)

        # Weighted blend.  See docs/DESIGN.md §7 for the rationale.
        # Weights sum to > 100 by design so a great match still tops
        # out around 120 and gets clamped.
        raw_score = (
            0.65 * best_fuzzy
            + prefix_boost
            + prior
            + recency
        )
        # Clamp to [0, 100] for stable presentation.
        score = max(0.0, min(100.0, raw_score))

        hits.append(
            SearchHit(
                path=cand.path,
                score=score,
                fuzzy_score=best_fuzzy,
                directory_prior=prior,
                recency_score=recency,
                matched_query=best_variant,
            )
        )

    # Sort best-first, take top N.
    hits.sort(key=lambda h: (-h.score, -h.recency_score, h.path))
    return hits[:limit]


__all__ = [
    "SearchHit",
    "search_filenames",
]
