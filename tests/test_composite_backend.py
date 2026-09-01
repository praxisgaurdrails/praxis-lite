"""Tests for the composite search backend fallback."""

import pytest

from praxis.filesystem.search_backends import (
    CompositeBackend,
    SearchCandidate,
    WalkerBackend,
    pick_default_backend,
)


class _EmptyBackend:
    name = "empty"

    def is_available(self):
        return True

    def query(self, raw_query, roots, limit):
        return []


class _StaticBackend:
    name = "static"

    def __init__(self, hits):
        self._hits = hits

    def is_available(self):
        return True

    def query(self, raw_query, roots, limit):
        return self._hits


class _BoomBackend:
    name = "boom"

    def is_available(self):
        return True

    def query(self, raw_query, roots, limit):
        raise RuntimeError("backend exploded")


class TestComposite:
    def test_uses_primary_when_it_has_hits(self, tmp_path):
        primary = _StaticBackend([SearchCandidate(path="/a/b.txt")])
        fallback = _EmptyBackend()
        c = CompositeBackend(primary, fallback)
        hits = c.query("x", [str(tmp_path)], 10)
        assert len(hits) == 1
        assert hits[0].path == "/a/b.txt"

    def test_falls_back_when_primary_empty(self, tmp_path):
        (tmp_path / "passport.pdf").write_bytes(b"x")
        primary = _EmptyBackend()
        fallback = WalkerBackend()
        c = CompositeBackend(primary, fallback)
        hits = c.query("passport", [str(tmp_path)], 10)
        assert any("passport" in h.path for h in hits)

    def test_falls_back_when_primary_raises(self, tmp_path):
        (tmp_path / "resume.pdf").write_bytes(b"x")
        c = CompositeBackend(_BoomBackend(), WalkerBackend())
        hits = c.query("resume", [str(tmp_path)], 10)
        assert any("resume" in h.path for h in hits)

    def test_name_combines_both(self):
        c = CompositeBackend(_StaticBackend([]), WalkerBackend())
        assert "+" in c.name

    def test_always_available(self):
        c = CompositeBackend(_EmptyBackend(), WalkerBackend())
        assert c.is_available()


class TestPicker:
    def test_picker_returns_available_backend(self):
        b = pick_default_backend()
        assert b.is_available()
        # On any platform it should either be a composite (native+walker)
        # or a bare walker.
        assert "walker" in b.name
