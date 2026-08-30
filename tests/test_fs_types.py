"""Tests for FSAction / FSActionEvent / FS tier assignment."""

import pytest

from praxis.filesystem.types import (
    FS_TIER,
    FSAction,
    FSActionEvent,
    FSResultStatus,
    normalise_path,
    tier_for,
)
from praxis.policy.engine import ActionType
from praxis.principal import Principal
from praxis.tiers import RiskTier


class TestFSActionTiers:
    def test_all_actions_have_a_tier(self):
        # Every enum value must appear in the tier table.
        for action in FSAction:
            assert action in FS_TIER, f"missing tier for {action}"

    @pytest.mark.parametrize(
        "action,expected",
        [
            (FSAction.SEARCH, RiskTier.T0),
            (FSAction.READ, RiskTier.T0),
            (FSAction.STAT, RiskTier.T0),
            (FSAction.LIST_DIR, RiskTier.T0),
            (FSAction.CREATE_DIR, RiskTier.T1),
            (FSAction.CREATE_FILE, RiskTier.T1),
            (FSAction.WRITE, RiskTier.T1),
            (FSAction.DELETE, RiskTier.T2),
            (FSAction.MOVE, RiskTier.T2),
            (FSAction.RENAME, RiskTier.T2),
            (FSAction.OVERWRITE, RiskTier.T2),
        ],
    )
    def test_tier_assignment(self, action, expected):
        assert tier_for(action) == expected


class TestFSActionEvent:
    def _base(self, **kw):
        return FSActionEvent(
            action=kw.pop("action", FSAction.STAT),
            principal=kw.pop("principal", Principal.local()),
            **kw,
        )

    def test_resolved_tier_defaults_from_action(self):
        e = self._base(action=FSAction.DELETE, paths=["~/a.txt"])
        assert e.resolved_tier == RiskTier.T2

    def test_resolved_tier_honours_explicit_override(self):
        e = self._base(action=FSAction.STAT, tier=RiskTier.T2)
        assert e.resolved_tier == RiskTier.T2

    def test_primary_path_prefers_paths_then_target(self):
        assert self._base(paths=["~/a"]).primary_path == "~/a"
        assert (
            self._base(action=FSAction.MOVE, target_dir="~/dst").primary_path
            == "~/dst"
        )
        assert self._base(action=FSAction.SEARCH).primary_path == ""

    def test_fingerprint_stable_across_reconstruction(self):
        a = self._base(action=FSAction.DELETE, paths=["~/x"])
        b = self._base(action=FSAction.DELETE, paths=["~/x"])
        assert a.fingerprint == b.fingerprint
        # Different path → different fingerprint.
        c = self._base(action=FSAction.DELETE, paths=["~/y"])
        assert a.fingerprint != c.fingerprint

    def test_blast_radius_covers_every_action(self):
        # No action must produce an empty blast radius — the notifier
        # relies on this text.
        for action in FSAction:
            e = self._base(
                action=action,
                paths=["~/a"],
                query="q",
                target_dir="~/dst",
                new_name="x",
                content=b"hello",
            )
            assert e.blast_radius(), f"blast empty for {action}"

    def test_approval_summary_includes_principal(self):
        e = self._base(
            action=FSAction.DELETE,
            paths=["~/a", "~/b"],
            principal=Principal.agent("claude-desktop"),
        )
        s = e.approval_summary()
        assert "agent:claude-desktop" in s
        assert "delete" in s.lower()

    def test_to_action_event_produces_recording_view(self):
        e = self._base(
            action=FSAction.DELETE,
            paths=["~/a", "~/b"],
            principal=Principal.agent("claude-desktop"),
        )
        ae = e.to_action_event()
        assert ae.action_type == ActionType.FILESYSTEM
        assert ae.selector == "fs.delete"
        # Principal propagated.
        assert str(ae.resolved_principal) == "agent:claude-desktop"
        assert ae.resolved_tier == RiskTier.T2
        # Blast radius made it into element_text (for evidence display).
        assert "delete" in ae.element_text.lower()

    def test_to_action_event_never_leaks_content_bytes(self):
        big = b"x" * 10_000
        e = self._base(
            action=FSAction.WRITE,
            paths=["~/a"],
            content=big,
        )
        ae = e.to_action_event()
        # Neither the value nor the text should contain the raw bytes.
        assert b"x" * 100 not in ae.value.encode()
        assert b"x" * 100 not in ae.element_text.encode()


class TestNormalisePath:
    def test_expands_tilde(self):
        p = normalise_path("~/foo")
        assert "~" not in str(p)
        assert str(p).startswith(str(__import__("pathlib").Path.home()))

    def test_defeats_dot_dot_traversal(self):
        p = normalise_path("~/foo/../bar")
        assert "/../" not in str(p)
        assert str(p).endswith("bar")


class TestFSResultStatus:
    def test_success_flag(self):
        from praxis.filesystem.types import FSResult

        ok = FSResult(status=FSResultStatus.SUCCESS, action=FSAction.STAT, request_id="r")
        bad = FSResult(status=FSResultStatus.BLOCKED, action=FSAction.STAT, request_id="r")
        assert ok.ok
        assert not bad.ok
