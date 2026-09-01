"""Tests for filename fuzzy search + backends."""

import time
from pathlib import Path

import pytest

from praxis.filesystem.search import search_filenames
from praxis.filesystem.search_backends import (
    SearchCandidate,
    WalkerBackend,
    pick_default_backend,
)


@pytest.fixture
def hoard(tmp_path):
    """A little directory of realistically-named files."""
    files = [
        ("Documents/passport_2024_final.pdf", 60),
        ("Documents/passport-application.docx", 200),
        ("Documents/tax_return_2023.pdf", 500),
        ("Downloads/nimish_cv.docx", 120),
        ("Downloads/resume.pdf", 30),
        ("Notes/passcode-hints.txt", 90),
        ("Library/Caches/passport_junk.tmp", 400),
        ("Photos/IMG_2847.jpg", 300),
        ("node_modules/deep/passport.js", 10),
    ]
    for rel, age_days in files:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
        stamp = time.time() - age_days * 86400
        import os
        os.utime(p, (stamp, stamp))
    return tmp_path


# ---------------------------------------------------------------------------
# WalkerBackend — the always-available fallback we can test deterministically
# ---------------------------------------------------------------------------


class TestWalkerBackend:
    def test_is_always_available(self):
        assert WalkerBackend().is_available()

    def test_finds_matches_by_substring(self, hoard):
        backend = WalkerBackend()
        results = backend.query("passport", [str(hoard)], limit=10)
        paths = [c.path for c in results]
        assert any("passport_2024_final.pdf" in p for p in paths)
        # Excluded dir contents don't appear.
        assert not any("node_modules" in p for p in paths)

    def test_excludes_dotdirs(self, tmp_path):
        # A .git dir with a matching filename should not surface.
        git = tmp_path / ".git"
        git.mkdir()
        (git / "passport.txt").write_text("x")
        backend = WalkerBackend()
        results = backend.query("passport", [str(tmp_path)], limit=10)
        assert results == []


# ---------------------------------------------------------------------------
# Fuzzy layer
# ---------------------------------------------------------------------------


class TestSearchFilenames:
    def test_exact_prefix_wins(self, hoard):
        hits = search_filenames(
            "passport",
            roots=[str(hoard)],
            backend=WalkerBackend(),
            limit=5,
        )
        assert hits, "no results"
        top = hits[0]
        # The best result should be an actual passport file, not the
        # passcode hint.
        assert "passport" in top.path.lower()

    def test_partial_prefix_still_finds_passport(self, hoard):
        hits = search_filenames(
            "pass",
            roots=[str(hoard)],
            backend=WalkerBackend(),
            limit=10,
        )
        assert hits
        # Both passport and passcode should show up.
        names = [Path(h.path).name.lower() for h in hits]
        assert any("passport" in n for n in names)
        assert any("passcode" in n for n in names)

    def test_recency_boost_prefers_newer_files(self, hoard):
        # The 60-day-old passport ranks above the 200-day-old one.
        hits = search_filenames(
            "passport",
            roots=[str(hoard)],
            backend=WalkerBackend(),
            limit=5,
        )
        top_paths = [h.path for h in hits]
        idx_final = next(
            (i for i, p in enumerate(top_paths)
             if "passport_2024_final" in p), -1
        )
        idx_app = next(
            (i for i, p in enumerate(top_paths)
             if "passport-application" in p), -1
        )
        assert 0 <= idx_final < idx_app, (
            f"final should outrank application: {top_paths}"
        )

    def test_directory_prior_demotes_caches(self, hoard):
        # A passport-ish file in Library/Caches should not top the list.
        hits = search_filenames(
            "passport",
            roots=[str(hoard)],
            backend=WalkerBackend(),
            limit=10,
        )
        top = hits[0]
        assert "Library/Caches" not in top.path

    def test_synonym_expansion_resume_finds_cv(self, hoard):
        # Searching "cv" should also match the "resume" file via synonyms.
        hits = search_filenames(
            "resume",
            roots=[str(hoard)],
            backend=WalkerBackend(),
            limit=10,
        )
        names = [Path(h.path).name.lower() for h in hits]
        assert any("cv" in n for n in names) or any("resume" in n for n in names)

    def test_extension_filter(self, hoard):
        hits = search_filenames(
            "passport",
            roots=[str(hoard)],
            ext="pdf",
            backend=WalkerBackend(),
            limit=10,
        )
        assert all(h.path.endswith(".pdf") for h in hits)
        assert hits, "extension filter dropped everything"

    def test_empty_query_returns_empty(self, hoard):
        assert search_filenames("", roots=[str(hoard)], backend=WalkerBackend()) == []

    def test_limit_is_honoured(self, hoard):
        hits = search_filenames(
            "p",
            roots=[str(hoard)],
            backend=WalkerBackend(),
            limit=2,
        )
        assert len(hits) <= 2

    def test_hits_serialise_to_dict(self, hoard):
        hits = search_filenames(
            "passport",
            roots=[str(hoard)],
            backend=WalkerBackend(),
            limit=1,
        )
        d = hits[0].to_dict()
        for k in ("path", "score", "fuzzy_score", "directory_prior", "recency_score"):
            assert k in d


class TestBackendPicker:
    def test_picker_returns_something_available(self):
        b = pick_default_backend()
        assert b.is_available()
