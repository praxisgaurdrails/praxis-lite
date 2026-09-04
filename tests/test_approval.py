"""Tests for the Praxis approval coordinator + kill switch."""

import asyncio

import pytest

from praxis.approval import (
    ApprovalCoordinator,
    ApprovalRequest,
    ApprovalStatus,
    AutoApproveNotifier,
    AutoDenyNotifier,
    NullAuthenticator,
)
from praxis.kill_switch import (
    KillSwitch,
    get_kill_switch,
    reset_kill_switch_for_tests,
)
from praxis.principal import Principal
from praxis.tiers import RiskTier


def _req(**overrides) -> ApprovalRequest:
    """Build a plausible T2 approval request for tests."""
    base = dict(
        request_id="req_test",
        tool_name="fs.delete",
        tier=RiskTier.T2,
        principal=Principal.local(),
        summary="Delete 3 files under ~/Downloads",
        details={"paths": ["a.pdf", "b.pdf", "c.pdf"]},
        blast_radius="~200 KB, 3 files",
        timeout_seconds=1.0,
        cool_off_seconds=0.0,
    )
    base.update(overrides)
    return ApprovalRequest(**base)


# ---------------------------------------------------------------------------
# Approval coordinator
# ---------------------------------------------------------------------------


class TestApprovalCoordinatorHappyPath:
    async def test_approve_success_no_cool_off(self):
        coord = ApprovalCoordinator(
            notifier=AutoApproveNotifier(),
            authenticator=NullAuthenticator(),
        )
        outcome = await coord.request(_req())
        assert outcome.status == ApprovalStatus.APPROVED
        assert outcome.authenticator == "noop"

    async def test_deny_at_notifier(self):
        coord = ApprovalCoordinator(
            notifier=AutoDenyNotifier(),
            authenticator=NullAuthenticator(),
        )
        outcome = await coord.request(_req())
        assert outcome.status == ApprovalStatus.DENIED

    async def test_auth_failure(self):
        class DenyAuth:
            name = "deny"

            async def authenticate(self, req):
                return False

        coord = ApprovalCoordinator(
            notifier=AutoApproveNotifier(),
            authenticator=DenyAuth(),
        )
        outcome = await coord.request(_req())
        assert outcome.status == ApprovalStatus.AUTH_FAILED
        assert outcome.authenticator == "deny"


class TestApprovalTimeout:
    async def test_notifier_hang_causes_timeout(self):
        class SlowNotifier:
            async def prompt(self, req):
                await asyncio.sleep(10)
                return ApprovalStatus.APPROVED

        coord = ApprovalCoordinator(
            notifier=SlowNotifier(),
            authenticator=NullAuthenticator(),
        )
        outcome = await coord.request(_req(timeout_seconds=0.1))
        assert outcome.status == ApprovalStatus.TIMED_OUT

    async def test_authenticator_exception_maps_to_auth_failed(self):
        class Boom:
            name = "boom"

            async def authenticate(self, req):
                raise RuntimeError("hardware key unplugged")

        coord = ApprovalCoordinator(
            notifier=AutoApproveNotifier(), authenticator=Boom()
        )
        outcome = await coord.request(_req())
        assert outcome.status == ApprovalStatus.AUTH_FAILED
        assert "hardware key" in outcome.reason


class TestApprovalCoolOff:
    async def test_cool_off_elapses_and_approves(self):
        coord = ApprovalCoordinator(
            notifier=AutoApproveNotifier(),
            authenticator=NullAuthenticator(),
        )
        outcome = await coord.request(_req(cool_off_seconds=0.3))
        assert outcome.status == ApprovalStatus.APPROVED

    async def test_cool_off_cancelled_returns_cancelled(self):
        coord = ApprovalCoordinator(
            notifier=AutoApproveNotifier(),
            authenticator=NullAuthenticator(),
        )
        req = _req(request_id="req_cancel_me", cool_off_seconds=1.0)

        async def canceller():
            await asyncio.sleep(0.1)
            coord.cancel(req.request_id)

        cancel_task = asyncio.create_task(canceller())
        outcome = await coord.request(req)
        await cancel_task
        assert outcome.status == ApprovalStatus.CANCELLED
        assert "aborted" in outcome.reason.lower()

    async def test_cool_off_callback_can_abort(self):
        aborts_at_third_tick = {"count": 0}

        async def cb(req):
            aborts_at_third_tick["count"] += 1
            return aborts_at_third_tick["count"] < 3

        coord = ApprovalCoordinator(
            notifier=AutoApproveNotifier(),
            authenticator=NullAuthenticator(),
            cool_off_cb=cb,
        )
        outcome = await coord.request(_req(cool_off_seconds=1.0))
        assert outcome.status == ApprovalStatus.CANCELLED
        assert "callback" in outcome.reason.lower()


class TestApprovalIntrospection:
    async def test_pending_tracks_request_during_prompt(self):
        seen: list = []

        class ObservingNotifier:
            def __init__(self, coord):
                self.coord = coord

            async def prompt(self, req):
                seen.append(list(self.coord.pending()))
                return ApprovalStatus.APPROVED

        coord = ApprovalCoordinator(
            notifier=None, authenticator=NullAuthenticator()
        )
        coord._notifier = ObservingNotifier(coord)  # noqa: SLF001
        await coord.request(_req())
        assert len(seen) == 1
        assert len(seen[0]) == 1
        assert seen[0][0].tool_name == "fs.delete"
        # After completion nothing is pending.
        assert coord.pending() == []


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


class TestKillSwitch:
    def setup_method(self):
        reset_kill_switch_for_tests()

    def teardown_method(self):
        reset_kill_switch_for_tests()

    def test_singleton(self):
        a = get_kill_switch()
        b = get_kill_switch()
        assert a is b

    def test_fire_is_idempotent(self):
        ks = KillSwitch()
        e1 = ks.fire(reason="test-a")
        e2 = ks.fire(reason="test-b")
        assert ks.is_fired
        assert e1 is e2  # second fire returns the first event
        assert e1.reason == "test-a"
        assert len(ks.history) == 1

    def test_fire_triggers_hooks(self):
        ks = KillSwitch()
        calls = []
        ks.register(lambda: calls.append("hook1"))
        ks.register(lambda: calls.append("hook2"))
        ks.fire(reason="test")
        assert calls == ["hook1", "hook2"]
        assert ks.last_event.hooks_run == 2
        assert ks.last_event.hooks_failed == 0

    def test_bad_hook_does_not_stop_others(self):
        ks = KillSwitch()
        calls = []

        def boom():
            raise RuntimeError("nope")

        ks.register(lambda: calls.append("before"))
        ks.register(boom)
        ks.register(lambda: calls.append("after"))
        ks.fire(reason="test")
        assert calls == ["before", "after"]
        assert ks.last_event.hooks_run == 2
        assert ks.last_event.hooks_failed == 1

    def test_fire_revokes_tokens(self):
        ks = KillSwitch()
        state = {"revoked": 0}

        def revoke_all():
            state["revoked"] += 7
            return 7

        ks.bind_token_store(revoke_all)
        ks.fire(reason="panic")
        assert state["revoked"] == 7
        assert ks.last_event.tokens_revoked == 7

    def test_fire_cancels_approvals(self):
        ks = KillSwitch()

        def cancel_all():
            return 4

        ks.bind_approval_coordinator(cancel_all)
        ks.fire(reason="panic")
        assert ks.last_event.approvals_cancelled == 4

    def test_reset(self):
        ks = KillSwitch()
        ks.fire(reason="test")
        assert ks.is_fired
        ks.reset(reason="all clear")
        assert not ks.is_fired
        # History retains both events.
        assert len(ks.history) == 2
        assert "reset" in ks.history[-1].reason
