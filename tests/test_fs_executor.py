"""End-to-end tests for the FS policy engine + executor."""

import shutil
import tempfile
from pathlib import Path

import pytest

from praxis.approval import ApprovalCoordinator, AutoApproveNotifier, AutoDenyNotifier, NullAuthenticator
from praxis.evidence.vault import EvidenceVault
from praxis.filesystem import (
    FSAction,
    FSActionEvent,
    FSExecutor,
    FSPolicyEngine,
    FSResultStatus,
    StagedTrash,
    WalkerBackend,
)
from praxis.kill_switch import KillSwitch, reset_kill_switch_for_tests
from praxis.policy.engine import Decision
from praxis.principal import Principal
from praxis.tiers import RiskTier


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_kill_switch():
    reset_kill_switch_for_tests()
    yield
    reset_kill_switch_for_tests()


@pytest.fixture
def sandbox(tmp_path):
    """A directory of real files we're allowed to touch."""
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "passport_2024.pdf").write_bytes(b"pretend pdf")
    (tmp_path / "Documents" / "resume.pdf").write_bytes(b"pretend cv")
    (tmp_path / "Downloads").mkdir()
    (tmp_path / "Downloads" / "junk.tmp").write_bytes(b"trash")
    return tmp_path


@pytest.fixture
def executor(tmp_path):
    trash = StagedTrash(trash_dir=tmp_path / "trash", ttl_seconds=60.0)
    coord = ApprovalCoordinator(
        notifier=AutoApproveNotifier(),
        authenticator=NullAuthenticator(),
    )
    ks = KillSwitch()
    return FSExecutor(
        policy=FSPolicyEngine(),
        approvals=coord,
        trash=trash,
        kill_switch=ks,
        search_backend=WalkerBackend(),
    )


def _event(action, principal, **kw):
    kw.setdefault("cool_off_seconds", 0.0) if False else None
    return FSActionEvent(action=action, principal=principal, **kw)


# ---------------------------------------------------------------------------
# T0 — read
# ---------------------------------------------------------------------------


class TestT0Read:
    async def test_search_returns_hits(self, sandbox, executor):
        e = _event(
            FSAction.SEARCH,
            Principal.local(),
            query="passport",
            paths=[str(sandbox)],
            limit=5,
        )
        r = await executor.execute(e)
        assert r.ok, r.reason
        hits = r.result["hits"]
        assert any("passport" in h["path"] for h in hits)

    async def test_read_returns_content(self, sandbox, executor):
        target = sandbox / "Documents" / "passport_2024.pdf"
        e = _event(FSAction.READ, Principal.local(), paths=[str(target)])
        r = await executor.execute(e)
        assert r.ok
        assert r.result["path"] == str(target)
        assert "pretend pdf" in r.result["bytes"]

    async def test_read_caps_large_files(self, sandbox, executor):
        big = sandbox / "Documents" / "big.bin"
        big.write_bytes(b"A" * 100)
        e = _event(
            FSAction.READ,
            Principal.local(),
            paths=[str(big)],
            max_bytes=10,
        )
        r = await executor.execute(e)
        assert r.ok
        assert r.result["truncated"] is True
        assert len(r.result["bytes"]) <= 10

    async def test_stat_returns_metadata(self, sandbox, executor):
        target = sandbox / "Documents" / "passport_2024.pdf"
        e = _event(FSAction.STAT, Principal.local(), paths=[str(target)])
        r = await executor.execute(e)
        assert r.ok
        assert r.result["is_file"] is True
        assert r.result["size"] > 0

    async def test_list_dir(self, sandbox, executor):
        e = _event(
            FSAction.LIST_DIR,
            Principal.local(),
            paths=[str(sandbox / "Documents")],
        )
        r = await executor.execute(e)
        assert r.ok
        names = [entry["name"] for entry in r.result["entries"]]
        assert "passport_2024.pdf" in names

    async def test_read_refuses_ssh_keys(self, sandbox, executor):
        e = _event(
            FSAction.READ,
            Principal.local(),
            paths=["~/.ssh/id_rsa"],
        )
        r = await executor.execute(e)
        assert r.status == FSResultStatus.BLOCKED
        assert "credential" in r.reason.lower() or "keychain" in r.reason.lower() or "ssh" in r.decision_matched_rule.lower() or "fs_path" in r.decision_matched_rule


# ---------------------------------------------------------------------------
# T1 — benign write
# ---------------------------------------------------------------------------


class TestT1Write:
    async def test_create_dir(self, sandbox, executor):
        target = sandbox / "new_dir" / "deep"
        e = _event(FSAction.CREATE_DIR, Principal.local(), paths=[str(target)])
        r = await executor.execute(e)
        assert r.ok
        assert target.exists() and target.is_dir()

    async def test_create_file_new(self, sandbox, executor):
        target = sandbox / "brand_new.txt"
        e = _event(
            FSAction.CREATE_FILE,
            Principal.local(),
            paths=[str(target)],
            content=b"hello",
        )
        r = await executor.execute(e)
        assert r.ok
        assert target.read_bytes() == b"hello"

    async def test_create_file_refuses_existing(self, sandbox, executor):
        existing = sandbox / "Documents" / "passport_2024.pdf"
        e = _event(
            FSAction.CREATE_FILE,
            Principal.local(),
            paths=[str(existing)],
            content=b"nope",
        )
        r = await executor.execute(e)
        assert r.status == FSResultStatus.ERROR
        assert "exist" in r.reason.lower()

    async def test_write_append(self, sandbox, executor):
        target = sandbox / "Documents" / "log.txt"
        target.write_bytes(b"line1\n")
        e = _event(
            FSAction.WRITE,
            Principal.local(),
            paths=[str(target)],
            content=b"line2\n",
            if_exists="append",
        )
        r = await executor.execute(e)
        assert r.ok
        assert target.read_bytes() == b"line1\nline2\n"

    async def test_write_refuses_secrets(self, executor):
        e = _event(
            FSAction.WRITE,
            Principal.local(),
            paths=["~/.aws/credentials"],
            content=b"x",
        )
        r = await executor.execute(e)
        assert r.status == FSResultStatus.BLOCKED


# ---------------------------------------------------------------------------
# T2 — destructive
# ---------------------------------------------------------------------------


class TestT2Delete:
    async def test_delete_from_local_stages_to_trash(self, sandbox, executor):
        target = sandbox / "Downloads" / "junk.tmp"
        e = _event(FSAction.DELETE, Principal.local(), paths=[str(target)])
        r = await executor.execute(e)
        assert r.ok, r.reason
        assert not target.exists(), "file must be gone from original path"
        assert r.trashed_paths, "trash entry must be recorded"

    async def test_delete_from_local_needs_approval(self, sandbox, tmp_path):
        # Same executor but with a denying notifier.
        coord = ApprovalCoordinator(
            notifier=AutoDenyNotifier(), authenticator=NullAuthenticator()
        )
        executor = FSExecutor(
            policy=FSPolicyEngine(),
            approvals=coord,
            trash=StagedTrash(trash_dir=tmp_path / "trash"),
            kill_switch=KillSwitch(),
            search_backend=WalkerBackend(),
        )
        target = sandbox / "Downloads" / "junk.tmp"
        e = _event(FSAction.DELETE, Principal.local(), paths=[str(target)])
        r = await executor.execute(e)
        assert r.status == FSResultStatus.APPROVAL_DENIED
        assert target.exists(), "denial must not delete"

    async def test_delete_from_agent_blocked(self, sandbox, executor):
        target = sandbox / "Downloads" / "junk.tmp"
        e = _event(
            FSAction.DELETE,
            Principal.agent("claude-desktop"),
            paths=[str(target)],
        )
        r = await executor.execute(e)
        assert r.status == FSResultStatus.BLOCKED
        assert target.exists()

    async def test_delete_home_root_refused(self, sandbox, executor):
        e = _event(FSAction.DELETE, Principal.local(), paths=["~"])
        r = await executor.execute(e)
        assert r.status == FSResultStatus.BLOCKED

    async def test_move_ok(self, sandbox, executor):
        src = sandbox / "Documents" / "resume.pdf"
        dst_dir = sandbox / "Archive"
        e = _event(
            FSAction.MOVE,
            Principal.local(),
            paths=[str(src)],
            target_dir=str(dst_dir),
        )
        r = await executor.execute(e)
        assert r.ok, r.reason
        assert not src.exists()
        assert (dst_dir / "resume.pdf").exists()

    async def test_rename(self, sandbox, executor):
        target = sandbox / "Documents" / "resume.pdf"
        e = _event(
            FSAction.RENAME,
            Principal.local(),
            paths=[str(target)],
            new_name="resume_final.pdf",
        )
        r = await executor.execute(e)
        assert r.ok
        assert (sandbox / "Documents" / "resume_final.pdf").exists()

    async def test_rename_rejects_path_in_new_name(self, sandbox, executor):
        target = sandbox / "Documents" / "resume.pdf"
        e = _event(
            FSAction.RENAME,
            Principal.local(),
            paths=[str(target)],
            new_name="../evil.pdf",
        )
        r = await executor.execute(e)
        assert r.status == FSResultStatus.ERROR
        assert "basename" in r.reason.lower()

    async def test_overwrite_backs_up_before_writing(self, sandbox, executor):
        target = sandbox / "Documents" / "passport_2024.pdf"
        original = target.read_bytes()
        e = _event(
            FSAction.OVERWRITE,
            Principal.local(),
            paths=[str(target)],
            content=b"new content",
        )
        r = await executor.execute(e)
        assert r.ok
        assert target.read_bytes() == b"new content"
        assert r.trashed_paths, "original must be backed up"
        assert Path(r.trashed_paths[0]).read_bytes() == original


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


class TestKillSwitchIntegration:
    async def test_fired_kill_switch_refuses_ops(self, sandbox, executor):
        executor._kill.fire(reason="test")
        e = _event(FSAction.STAT, Principal.local(),
                   paths=[str(sandbox / "Documents" / "resume.pdf")])
        r = await executor.execute(e)
        assert r.status == FSResultStatus.KILLED


# ---------------------------------------------------------------------------
# Evidence recording integration
# ---------------------------------------------------------------------------


class TestEvidenceRecording:
    async def test_fs_op_appears_in_evidence_chain(self, sandbox, tmp_path, executor):
        vault = EvidenceVault(tmp_path / "evidence")
        session = await vault.start_session(agent_id="fs-test")

        e = _event(
            FSAction.STAT,
            Principal.local(),
            paths=[str(sandbox / "Documents" / "resume.pdf")],
        )
        await executor.execute(e, session=session)

        e2 = _event(
            FSAction.DELETE,
            Principal.agent("claude-desktop"),
            paths=[str(sandbox / "Downloads" / "junk.tmp")],
        )
        await executor.execute(e2, session=session)

        summary = await session.end()
        assert summary.chain_valid
        assert summary.total_actions == 2

        records = await vault.get_session_records(session.session_id)
        # First record: T0 stat by local, allowed.
        assert records[0].action_type == "filesystem"
        assert records[0].selector == "fs.stat"
        assert records[0].tier == "t0"
        assert records[0].principal == "praxis:local"
        assert records[0].decision == "allow"
        # Second: T2 delete by agent, blocked.
        assert records[1].selector == "fs.delete"
        assert records[1].tier == "t2"
        assert records[1].principal == "agent:claude-desktop"
        assert records[1].decision == "block"
