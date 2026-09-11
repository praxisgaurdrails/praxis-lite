"""Tests for the runbook cache, capture, and replay."""

import pytest

from praxis.approval import ApprovalCoordinator, AutoApproveNotifier, NullAuthenticator
from praxis.filesystem import (
    FSAction,
    FSActionEvent,
    FSExecutor,
    FSPolicyEngine,
    FSResult,
    FSResultStatus,
    StagedTrash,
    WalkerBackend,
)
from praxis.filesystem.types import FSResultStatus  # noqa: F401 (re-export check)
from praxis.kill_switch import KillSwitch, reset_kill_switch_for_tests
from praxis.principal import Principal
from praxis.runbook import (
    ReplayOutcome,
    Runbook,
    RunbookCache,
    RunbookCapture,
    RunbookReplayer,
    RunbookStep,
)
from praxis.runbook.cache import _jaccard, _tokenize
from praxis.runbook.replay import ReplayStatus


@pytest.fixture(autouse=True)
def _fresh_kill():
    reset_kill_switch_for_tests()
    yield
    reset_kill_switch_for_tests()


@pytest.fixture
def cache(tmp_path):
    return RunbookCache(path=tmp_path / "runbooks.db")


@pytest.fixture
def sandbox(tmp_path):
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "resume.pdf").write_bytes(b"cv")
    (tmp_path / "Downloads").mkdir()
    (tmp_path / "Downloads" / "junk.tmp").write_bytes(b"j")
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


# ---------------------------------------------------------------------------
# Tokenisation / similarity
# ---------------------------------------------------------------------------


class TestTokenisation:
    def test_stopwords_dropped(self):
        toks = _tokenize("clean up the downloads please")
        assert "clean" in toks
        assert "downloads" in toks
        assert "the" not in toks
        assert "please" not in toks

    def test_jaccard_identical(self):
        # Only stopwords differ → identical token sets
        a = _tokenize("clean downloads please")
        b = _tokenize("the clean downloads")
        assert _jaccard(a, b) == pytest.approx(1.0)

    def test_jaccard_disjoint(self):
        a = _tokenize("random noise sample")
        b = _tokenize("passport visa document")
        assert _jaccard(a, b) == 0.0


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


class TestCacheCRUD:
    def test_add_generates_id(self, cache):
        rb = cache.add(Runbook(
            runbook_id="",
            trigger_phrase="clean up downloads",
            steps=[RunbookStep("fs.delete", {"paths": ["/tmp/x"]})],
        ))
        assert rb.runbook_id.startswith("rb_")

    def test_get_returns_stored(self, cache):
        rb = cache.add(Runbook(
            runbook_id="rb_1",
            trigger_phrase="foo",
            steps=[RunbookStep("fs.stat", {"paths": ["/tmp/x"]})],
        ))
        got = cache.get(rb.runbook_id)
        assert got is not None
        assert got.trigger_phrase == "foo"
        assert len(got.steps) == 1

    def test_delete_removes(self, cache):
        rb = cache.add(Runbook(runbook_id="rb_del", trigger_phrase="x"))
        assert cache.delete(rb.runbook_id)
        assert cache.get(rb.runbook_id) is None

    def test_count(self, cache):
        for i in range(3):
            cache.add(Runbook(runbook_id=f"rb_{i}", trigger_phrase="x"))
        assert cache.count() == 3

    def test_record_replay_updates_stats(self, cache):
        rb = cache.add(Runbook(
            runbook_id="rb_replay",
            trigger_phrase="clean downloads",
        ))
        cache.record_replay(rb.runbook_id, success=True)
        cache.record_replay(rb.runbook_id, success=False)
        got = cache.get(rb.runbook_id)
        assert got.replay_count == 2
        assert got.verified_success is False


# ---------------------------------------------------------------------------
# Match
# ---------------------------------------------------------------------------


class TestMatch:
    def test_high_overlap_matches(self, cache):
        cache.add(Runbook(
            runbook_id="rb_a",
            trigger_phrase="clean up my downloads",
            steps=[RunbookStep("fs.delete", {"paths": ["/x"]})],
        ))
        matches = cache.match("clean the downloads please")
        assert len(matches) == 1
        assert matches[0].score >= 0.4

    def test_no_overlap_no_match(self, cache):
        cache.add(Runbook(
            runbook_id="rb_a",
            trigger_phrase="clean up my downloads",
        ))
        matches = cache.match("send an email")
        assert matches == []

    def test_ranks_higher_score_first(self, cache):
        cache.add(Runbook(runbook_id="a", trigger_phrase="clean downloads"))
        cache.add(Runbook(runbook_id="b", trigger_phrase="clean downloads folder"))
        cache.add(Runbook(runbook_id="c", trigger_phrase="delete tmp files"))
        matches = cache.match("clean downloads folder now", top_k=3)
        ordered = [m.runbook.runbook_id for m in matches]
        assert ordered[0] in ("a", "b")


# ---------------------------------------------------------------------------
# Capture buffer
# ---------------------------------------------------------------------------


class TestCaptureBuffer:
    def test_captures_success_chain(self, cache):
        cap = RunbookCapture(cache=cache)
        buf = cap.buffer
        p = Principal.agent("claude-desktop")
        buf.set_trigger(p, "clean downloads")

        # Simulate two successful ops.
        for _ in range(2):
            e = FSActionEvent(
                action=FSAction.DELETE,
                principal=p,
                paths=["/tmp/x"],
            )
            r = FSResult(
                status=FSResultStatus.SUCCESS,
                action=FSAction.DELETE,
                request_id="r",
            )
            buf.observe(e, r)

        rb = buf.close_chain(p)
        assert rb is not None
        assert len(rb.steps) == 2
        # Persisted.
        assert cache.count() == 1

    def test_search_ops_are_ignored(self, cache):
        cap = RunbookCapture(cache=cache)
        buf = cap.buffer
        p = Principal.agent("claude-desktop")
        buf.set_trigger(p, "find things")

        e = FSActionEvent(action=FSAction.SEARCH, principal=p, query="x")
        r = FSResult(status=FSResultStatus.SUCCESS, action=FSAction.SEARCH, request_id="r")
        buf.observe(e, r)

        assert buf.close_chain(p) is None  # search alone is not enough

    def test_failed_ops_dropped(self, cache):
        cap = RunbookCapture(cache=cache)
        buf = cap.buffer
        p = Principal.agent("claude-desktop")
        buf.set_trigger(p, "delete things")

        e = FSActionEvent(action=FSAction.DELETE, principal=p, paths=["/x"])
        r = FSResult(status=FSResultStatus.BLOCKED, action=FSAction.DELETE, request_id="r")
        buf.observe(e, r)

        assert buf.close_chain(p) is None

    def test_content_bytes_never_captured(self, cache):
        """A runbook must not embed raw content bytes — data-leak risk."""
        cap = RunbookCapture(cache=cache)
        buf = cap.buffer
        p = Principal.agent("claude-desktop")
        buf.set_trigger(p, "write secret file")

        secret = b"THIS-IS-A-SECRET" * 10
        e = FSActionEvent(
            action=FSAction.WRITE,
            principal=p,
            paths=["/tmp/x"],
            content=secret,
        )
        r = FSResult(status=FSResultStatus.SUCCESS, action=FSAction.WRITE, request_id="r")
        buf.observe(e, r)
        rb = buf.close_chain(p)
        assert rb is not None
        step = rb.steps[0]
        # Content itself must be absent — only content_size may leak.
        for v in step.arguments.values():
            assert secret not in (str(v).encode() if not isinstance(v, bytes) else v)
        assert "content" not in step.arguments


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


class TestReplay:
    async def test_replay_re_runs_success_chain(self, cache, sandbox, executor):
        # Build a runbook by hand — search + move.
        target = sandbox / "Documents" / "resume.pdf"
        dest = sandbox / "Archive"

        rb = cache.add(Runbook(
            runbook_id="rb_move",
            trigger_phrase="move resume to archive",
            steps=[
                RunbookStep(
                    "fs.move",
                    {"paths": [str(target)], "target_dir": str(dest)},
                ),
            ],
        ))
        replayer = RunbookReplayer(executor)
        out = await replayer.replay(rb, principal=Principal.local())
        assert out.ok, out.reason
        assert (dest / "resume.pdf").exists()

    async def test_replay_aborts_on_policy_block(self, cache, sandbox, executor):
        # Runbook says "delete ~/.ssh/id_rsa" — will be blocked by path safety.
        rb = cache.add(Runbook(
            runbook_id="rb_bad",
            trigger_phrase="delete secrets",
            steps=[
                RunbookStep("fs.read", {"paths": ["~/.ssh/id_rsa"]}),
            ],
        ))
        replayer = RunbookReplayer(executor)
        out = await replayer.replay(rb, principal=Principal.local())
        assert not out.ok
        assert out.status == ReplayStatus.BLOCKED
        assert "fs_path" in out.reason or "credential" in out.reason.lower()
