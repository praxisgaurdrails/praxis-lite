"""Tests for the staged-trash system."""

import time
from pathlib import Path

import pytest

from praxis.filesystem.trash import (
    DEFAULT_TTL_SECONDS,
    StagedTrash,
)


@pytest.fixture
def trash(tmp_path) -> StagedTrash:
    return StagedTrash(trash_dir=tmp_path / "trash", ttl_seconds=60.0)


class TestStageAndRestore:
    def test_stage_moves_file_and_writes_manifest(self, tmp_path, trash):
        f = tmp_path / "junk.pdf"
        f.write_text("hello")
        entry = trash.stage(
            original_path=f,
            principal="praxis:local",
            request_id="req_1",
            reason="fs.delete",
        )
        assert not f.exists(), "file must be moved out of original path"
        assert Path(entry.staged_path).exists()
        # Manifest is present.
        manifest = trash.root / entry.entry_id / "manifest.json"
        assert manifest.exists()

    def test_stage_missing_file_raises(self, trash):
        with pytest.raises(FileNotFoundError):
            trash.stage(original_path="/tmp/does-not-exist-praxis")

    def test_list_entries(self, tmp_path, trash):
        for name in ("a.txt", "b.txt"):
            f = tmp_path / name
            f.write_text("x")
            trash.stage(original_path=f, reason="fs.delete")
        assert len(trash.list_entries()) == 2

    def test_restore(self, tmp_path, trash):
        f = tmp_path / "keepme.txt"
        f.write_text("important")
        entry = trash.stage(original_path=f)
        assert not f.exists()
        restored = trash.restore(entry.entry_id)
        assert restored.exists()
        assert restored.read_text() == "important"

    def test_restore_refuses_if_original_reoccupied(self, tmp_path, trash):
        f = tmp_path / "keepme.txt"
        f.write_text("important")
        entry = trash.stage(original_path=f)
        # Recreate the original path with different content.
        f.write_text("something else now")
        with pytest.raises(FileExistsError):
            trash.restore(entry.entry_id)


class TestRetention:
    def test_purge_expired_removes_old_entries(self, tmp_path, trash):
        f = tmp_path / "junk.pdf"
        f.write_text("x")
        entry = trash.stage(original_path=f)
        # Simulate the entry aging out.
        far_future = time.time() + trash.ttl_seconds + 100
        purged = trash.purge_expired(now=far_future)
        assert purged == 1
        assert trash.list_entries() == []

    def test_purge_expired_leaves_fresh_entries(self, tmp_path, trash):
        f = tmp_path / "junk.pdf"
        f.write_text("x")
        entry = trash.stage(original_path=f)
        purged = trash.purge_expired(now=time.time())
        assert purged == 0
        assert len(trash.list_entries()) == 1

    def test_size_cap_purges_oldest(self, tmp_path):
        # 2 KB cap.  Two files ~1 KB each — after both staged we're
        # right at the cap; adding a third forces the oldest out.
        trash = StagedTrash(
            trash_dir=tmp_path / "trash",
            ttl_seconds=DEFAULT_TTL_SECONDS,
            total_cap_bytes=2000,
        )
        contents = "x" * 1000
        entries = []
        for i in range(3):
            f = tmp_path / f"junk_{i}.txt"
            f.write_text(contents)
            entries.append(trash.stage(original_path=f, request_id=f"r{i}"))
            time.sleep(0.01)  # ensure staged_at ordering
        purged = trash.enforce_size_cap()
        # We should have purged at least one to get under 2 KB.
        assert purged >= 1
        remaining = trash.list_entries()
        # The oldest should have gone first.
        remaining_ids = {e.entry_id for e in remaining}
        assert entries[0].entry_id not in remaining_ids
