"""
Praxis filename-search backends.

Backends implement :class:`SearchBackend` and return candidate paths
for a raw query.  The higher-level :mod:`praxis.filesystem.search`
layer takes the candidates, applies fuzzy rerank, synonym expansion,
and directory heuristics.

Backends shipped in v1:

* :class:`SpotlightBackend` — macOS ``mdfind``.  Fast.
* :class:`PlocateBackend` — Linux ``plocate`` / ``locate``.  Fast.
* :class:`WindowsSearchBackend` — Windows "where" tool.  Simplistic
  fallback until we bind ``System.Search.CatalogManager`` (Phase 3+).
* :class:`WalkerBackend` — cross-platform pure-Python walker.  Slower
  but always available.

The picker :func:`pick_default_backend` returns the first available
one for the current OS with the walker as a fallback.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol

logger = logging.getLogger("praxis.filesystem.search_backends")


@dataclass
class SearchCandidate:
    """A single search hit — path + minimum metadata."""

    path: str
    mtime: float = 0.0
    size: int = 0

    @classmethod
    def from_path(cls, p: str | Path) -> SearchCandidate | None:
        try:
            path = Path(p)
            st = path.stat()
            return cls(path=str(path), mtime=st.st_mtime, size=st.st_size)
        except OSError:
            return None


class SearchBackend(Protocol):
    """A source of raw filename/path candidates."""

    name: str

    def is_available(self) -> bool:  # pragma: no cover
        ...

    def query(
        self,
        raw_query: str,
        roots: Iterable[str],
        limit: int,
    ) -> list[SearchCandidate]:  # pragma: no cover
        ...


# ---------------------------------------------------------------------------
# macOS — mdfind
# ---------------------------------------------------------------------------


class SpotlightBackend:
    """macOS Spotlight via the ``mdfind`` CLI.

    We use ``kMDItemFSName`` so we get filename matches — Spotlight
    also indexes content, but for v1 we intentionally stay to
    filename search per the design.
    """

    name = "spotlight"

    def is_available(self) -> bool:
        return sys.platform == "darwin" and shutil.which("mdfind") is not None

    def query(
        self,
        raw_query: str,
        roots: Iterable[str],
        limit: int,
    ) -> list[SearchCandidate]:
        roots = list(roots) or [str(Path.home())]
        hits: list[str] = []
        # Escape the query for Spotlight — single-quote it and rely on
        # subprocess list args.
        # kMDItemFSName == LIKE means substring match; Spotlight's
        # matching is case-insensitive by default.
        expr = f'kMDItemFSName == "*{_spotlight_escape(raw_query)}*"c'
        for root in roots:
            try:
                proc = subprocess.run(
                    ["mdfind", "-onlyin", root, expr],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line:
                    hits.append(line)
                if len(hits) >= limit * 4:
                    break
            if len(hits) >= limit * 4:
                break

        # De-dup preserving order.
        seen: set[str] = set()
        candidates: list[SearchCandidate] = []
        for p in hits:
            if p in seen:
                continue
            seen.add(p)
            c = SearchCandidate.from_path(p)
            if c is not None:
                candidates.append(c)
            if len(candidates) >= limit * 4:
                break
        return candidates


def _spotlight_escape(q: str) -> str:
    """Escape characters that break the Spotlight query grammar."""
    return q.replace("\\", "\\\\").replace('"', '\\"')


# ---------------------------------------------------------------------------
# Linux — plocate / locate
# ---------------------------------------------------------------------------


class PlocateBackend:
    """Linux ``plocate`` (or the older ``locate``).

    We shell out with ``-i`` for case-insensitive matching.
    """

    name = "plocate"

    def is_available(self) -> bool:
        if not sys.platform.startswith("linux"):
            return False
        return shutil.which("plocate") is not None or shutil.which("locate") is not None

    def query(
        self,
        raw_query: str,
        roots: Iterable[str],
        limit: int,
    ) -> list[SearchCandidate]:
        binary = shutil.which("plocate") or shutil.which("locate")
        if not binary:
            return []
        roots = list(roots) or [str(Path.home())]
        try:
            proc = subprocess.run(
                [binary, "-i", raw_query],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        roots_norm = [str(Path(r).expanduser().resolve()) for r in roots]
        candidates: list[SearchCandidate] = []
        for line in proc.stdout.splitlines():
            p = line.strip()
            if not p:
                continue
            if not any(p.startswith(r) for r in roots_norm):
                continue
            c = SearchCandidate.from_path(p)
            if c is not None:
                candidates.append(c)
            if len(candidates) >= limit * 4:
                break
        return candidates


# ---------------------------------------------------------------------------
# Windows — 'where' fallback
# ---------------------------------------------------------------------------


class WindowsSearchBackend:
    """Simple Windows fallback using the ``where`` command.

    A proper implementation binds ``System.Search.CatalogManager``
    via COM — deferred to Phase 3.  In the meantime this covers
    binaries on ``PATH`` and glob searches under a specific root.
    """

    name = "windows_where"

    def is_available(self) -> bool:
        return sys.platform == "win32" and shutil.which("where") is not None

    def query(
        self,
        raw_query: str,
        roots: Iterable[str],
        limit: int,
    ) -> list[SearchCandidate]:
        roots = list(roots) or [str(Path.home())]
        candidates: list[SearchCandidate] = []
        for root in roots:
            try:
                proc = subprocess.run(
                    ["where", "/r", root, f"*{raw_query}*"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            for line in proc.stdout.splitlines():
                p = line.strip()
                if not p:
                    continue
                c = SearchCandidate.from_path(p)
                if c is not None:
                    candidates.append(c)
                if len(candidates) >= limit * 4:
                    break
        return candidates


# ---------------------------------------------------------------------------
# Cross-platform walker fallback
# ---------------------------------------------------------------------------


class WalkerBackend:
    """Pure-Python filesystem walker.

    Slow on huge trees but correct everywhere.  Used when no native
    backend is available, and in unit tests.  Applies a small
    directory denylist so we don't burn time on `.git`, `node_modules`
    and friends.
    """

    name = "walker"

    DEFAULT_EXCLUDE_DIRS = frozenset({
        ".git",
        "node_modules",
        ".venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        "Library/Caches",
        ".Trash",
        ".praxis/trash",
    })

    def __init__(
        self,
        exclude_dirs: frozenset[str] | None = None,
        max_scanned: int = 20000,
    ) -> None:
        self.exclude_dirs = exclude_dirs or self.DEFAULT_EXCLUDE_DIRS
        self.max_scanned = max_scanned

    def is_available(self) -> bool:
        return True

    def query(
        self,
        raw_query: str,
        roots: Iterable[str],
        limit: int,
    ) -> list[SearchCandidate]:
        roots = list(roots) or [str(Path.home())]
        needle = raw_query.lower()
        candidates: list[SearchCandidate] = []
        scanned = 0
        for root in roots:
            root_p = Path(root).expanduser()
            if not root_p.exists():
                continue
            for dirpath, dirnames, filenames in os.walk(root_p):
                # Prune excluded dirs.
                dirnames[:] = [
                    d for d in dirnames
                    if d not in self.exclude_dirs
                    and not d.startswith(".")
                ]
                for fname in filenames:
                    scanned += 1
                    if needle in fname.lower():
                        p = os.path.join(dirpath, fname)
                        c = SearchCandidate.from_path(p)
                        if c is not None:
                            candidates.append(c)
                    if scanned >= self.max_scanned:
                        return candidates
                    if len(candidates) >= limit * 4:
                        return candidates
        return candidates


# ---------------------------------------------------------------------------
# Picker
# ---------------------------------------------------------------------------


def pick_default_backend() -> SearchBackend:
    """Return the best backend available on this host.

    Preference: platform-native → walker.  The native backend is
    always wrapped in a :class:`CompositeBackend` so that when the OS
    index misses (e.g. Spotlight doesn't index ``/tmp`` or hasn't yet
    indexed a freshly-created file), we transparently fall back to a
    direct filesystem walk of the requested roots.
    """
    native: SearchBackend | None = None
    for backend in (
        SpotlightBackend(),
        PlocateBackend(),
        WindowsSearchBackend(),
    ):
        try:
            if backend.is_available():
                native = backend
                break
        except Exception:
            continue
    if native is None:
        return WalkerBackend()
    return CompositeBackend(primary=native, fallback=WalkerBackend())


class CompositeBackend:
    """Try a fast native backend first; fall back to the walker on a miss.

    This is what makes search robust in practice: Spotlight / plocate
    are fast and cover the whole disk, but they miss unindexed
    locations (``/tmp``, network mounts) and just-created files.  When
    the primary returns nothing, we walk the requested roots directly
    so the user still gets results.
    """

    def __init__(self, primary: SearchBackend, fallback: SearchBackend) -> None:
        self._primary = primary
        self._fallback = fallback
        self.name = f"{primary.name}+{fallback.name}"

    def is_available(self) -> bool:
        return True

    def query(
        self,
        raw_query: str,
        roots: Iterable[str],
        limit: int,
    ) -> list[SearchCandidate]:
        roots = list(roots)
        try:
            hits = self._primary.query(raw_query, roots, limit)
        except Exception:
            logger.exception("primary backend %s failed", self._primary.name)
            hits = []
        if hits:
            return hits
        # Primary missed — walk the requested roots directly.
        try:
            return self._fallback.query(raw_query, roots, limit)
        except Exception:
            logger.exception("fallback backend %s failed", self._fallback.name)
            return []


__all__ = [
    "CompositeBackend",
    "PlocateBackend",
    "SearchBackend",
    "SearchCandidate",
    "SpotlightBackend",
    "WalkerBackend",
    "WindowsSearchBackend",
    "pick_default_backend",
]
