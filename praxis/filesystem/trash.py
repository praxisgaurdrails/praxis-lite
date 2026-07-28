"""
Praxis staged trash — every T2 delete/overwrite goes through here.

Instead of removing files immediately, the executor moves them into
``~/.praxis/trash/<request_id>/`` with a small ``manifest.json`` that
records the original path, timestamp, and principal.  Retention runs
in the background and hard-deletes anything older than the configured
TTL (default 24h) or over the total-size cap (default 5 GB).

The user can also list, restore, or purge via the CLI (Phase 6).
See ``docs/DESIGN.md`` §5 ("Deletes are staged").
"""

from __future__ import annotations

import json
import logging
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from praxis.filesystem.types import normalise_path

logger = logging.getLogger("praxis.filesystem.trash")


DEFAULT_TRASH_DIR = Path.home() / ".praxis" / "trash"
DEFAULT_TTL_SECONDS = 24 * 3600
DEFAULT_TOTAL_CAP_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB


@dataclass
class TrashEntry:
    """A single staged item — one file or dir moved to the trash."""

    entry_id: str
    original_path: str
    staged_path: str
    staged_at: float
    principal: str = ""
    request_id: str = ""
    reason: str = ""
    size_bytes: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


class StagedTrash:
    """Staged-trash manager.

    Thread-unsafe on purpose — one manager per daemon, called from the
    executor's ordinary async flow.  Concurrent moves from two workers
    are fine because we use a fresh ``entry_id`` per move.

    Usage::

        trash = StagedTrash()
        entry = trash.stage(
            original_path="~/Downloads/junk.pdf",
            principal="praxis:local",
            request_id="fs_42",
            reason="fs.delete",
        )
        # ...later:
        trash.purge_expired()
    """

    def __init__(
        self,
        trash_dir: Path | str | None = None,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        total_cap_bytes: int = DEFAULT_TOTAL_CAP_BYTES,
    ) -> None:
        self._root = Path(trash_dir) if trash_dir else DEFAULT_TRASH_DIR
        self._root.mkdir(parents=True, exist_ok=True)
        try:
            self._root.chmod(0o700)
        except OSError:
            pass
        self.ttl_seconds = float(ttl_seconds)
        self.total_cap_bytes = int(total_cap_bytes)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    def list_entries(self) -> list[TrashEntry]:
        entries: list[TrashEntry] = []
        for entry_dir in sorted(self._root.iterdir()):
            if not entry_dir.is_dir():
                continue
            manifest = entry_dir / "manifest.json"
            if not manifest.exists():
                continue
            try:
                data = json.loads(manifest.read_text())
                entries.append(TrashEntry(**data))
            except Exception:
                logger.exception(
                    "corrupt trash manifest at %s — skipping", manifest
                )
        return entries

    def total_size_bytes(self) -> int:
        total = 0
        for entry_dir in self._root.iterdir():
            if entry_dir.is_dir():
                total += _dir_size(entry_dir)
        return total

    # ------------------------------------------------------------------
    # Stage / restore / purge
    # ------------------------------------------------------------------

    def stage(
        self,
        original_path: str | Path,
        principal: str = "",
        request_id: str = "",
        reason: str = "",
    ) -> TrashEntry:
        """Move a file/dir into the trash.  Returns the created entry.

        The move is done with :func:`shutil.move` so it works across
        filesystems.  If the source does not exist we raise
        :class:`FileNotFoundError` — the executor is expected to
        pre-validate.
        """
        src = normalise_path(original_path)
        if not src.exists() and not src.is_symlink():
            raise FileNotFoundError(f"cannot stage missing path: {src}")

        entry_id = f"trash_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        entry_dir = self._root / entry_id
        entry_dir.mkdir(parents=True, exist_ok=False)
        try:
            entry_dir.chmod(0o700)
        except OSError:
            pass

        # Preserve the original filename inside entry_dir so restore is
        # unambiguous.
        staged = entry_dir / src.name
        shutil.move(str(src), str(staged))

        size = _path_size(staged)
        entry = TrashEntry(
            entry_id=entry_id,
            original_path=str(src),
            staged_path=str(staged),
            staged_at=time.time(),
            principal=principal,
            request_id=request_id,
            reason=reason,
            size_bytes=size,
        )
        (entry_dir / "manifest.json").write_text(json.dumps(entry.to_dict()))
        return entry

    def restore(self, entry_id: str) -> Path:
        """Move a staged entry back to its original path.

        If the original path is now occupied by something else we bail
        out with :class:`FileExistsError` — never overwrite user data
        during a restore.  Returns the restored path.
        """
        entry = self._find_entry(entry_id)
        if entry is None:
            raise KeyError(f"no such trash entry: {entry_id}")
        original = Path(entry.original_path)
        if original.exists() or original.is_symlink():
            raise FileExistsError(
                f"cannot restore: {original} is occupied"
            )
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(entry.staged_path, str(original))
        entry_dir = self._root / entry_id
        try:
            shutil.rmtree(entry_dir)
        except OSError:
            pass
        return original

    def purge(self, entry_id: str) -> bool:
        """Hard-delete a specific trash entry.  Returns True on success."""
        entry_dir = self._root / entry_id
        if not entry_dir.exists():
            return False
        shutil.rmtree(entry_dir, ignore_errors=True)
        return not entry_dir.exists()

    def purge_expired(self, now: float | None = None) -> int:
        """Delete entries past TTL.  Returns the count purged."""
        now = now if now is not None else time.time()
        purged = 0
        for entry in self.list_entries():
            if (now - entry.staged_at) > self.ttl_seconds:
                if self.purge(entry.entry_id):
                    purged += 1
        return purged

    def enforce_size_cap(self) -> int:
        """Purge oldest entries until size <= cap.  Returns count purged."""
        if self.total_cap_bytes <= 0:
            return 0
        total = self.total_size_bytes()
        if total <= self.total_cap_bytes:
            return 0
        entries = sorted(self.list_entries(), key=lambda e: e.staged_at)
        purged = 0
        for entry in entries:
            if total <= self.total_cap_bytes:
                break
            if self.purge(entry.entry_id):
                total -= entry.size_bytes
                purged += 1
        return purged

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _find_entry(self, entry_id: str) -> TrashEntry | None:
        for e in self.list_entries():
            if e.entry_id == entry_id:
                return e
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _path_size(p: Path) -> int:
    """Size of a file or directory in bytes."""
    try:
        if p.is_file() or p.is_symlink():
            return p.stat().st_size
    except OSError:
        return 0
    return _dir_size(p)


def _dir_size(p: Path) -> int:
    total = 0
    try:
        for child in p.rglob("*"):
            try:
                if child.is_file() and not child.is_symlink():
                    total += child.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total


__all__ = [
    "DEFAULT_TOTAL_CAP_BYTES",
    "DEFAULT_TRASH_DIR",
    "DEFAULT_TTL_SECONDS",
    "StagedTrash",
    "TrashEntry",
]
