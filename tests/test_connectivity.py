"""Tests for the connectivity monitor."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from praxis.connectivity import (
    ConnectivityMonitor,
    ConnectivityState,
    ProbeResult,
    ProbeTarget,
)


# ---------------------------------------------------------------------------
# Classification tests — synthetic probe results
# ---------------------------------------------------------------------------


class TestClassification:
    def _mon(self, targets=None):
        return ConnectivityMonitor(
            targets=targets or ConnectivityMonitor.__init__.__defaults__[0]
            if False else (
                ProbeTarget("anthropic", "api.anthropic.com", is_ai_vendor=True),
                ProbeTarget("openai", "api.openai.com", is_ai_vendor=True),
                ProbeTarget("internet", "1.1.1.1", is_ai_vendor=False),
            ),
        )

    def test_all_reachable_is_online(self):
        m = self._mon()
        results = [
            ProbeResult("anthropic", True, 20.0),
            ProbeResult("openai", True, 25.0),
            ProbeResult("internet", True, 8.0),
        ]
        assert m._classify(results) == ConnectivityState.ONLINE

    def test_only_internet_is_degraded(self):
        m = self._mon()
        results = [
            ProbeResult("anthropic", False, 2000, "timeout"),
            ProbeResult("openai", False, 2000, "timeout"),
            ProbeResult("internet", True, 8.0),
        ]
        assert m._classify(results) == ConnectivityState.DEGRADED

    def test_all_down_is_offline(self):
        m = self._mon()
        results = [
            ProbeResult("anthropic", False, 2000, "timeout"),
            ProbeResult("openai", False, 2000, "timeout"),
            ProbeResult("internet", False, 2000, "timeout"),
        ]
        assert m._classify(results) == ConnectivityState.OFFLINE

    def test_partial_ai_vendor_still_online(self):
        m = self._mon()
        # Anthropic up, OpenAI down, internet up → online (one vendor is enough)
        results = [
            ProbeResult("anthropic", True, 20.0),
            ProbeResult("openai", False, 2000, "timeout"),
            ProbeResult("internet", True, 8.0),
        ]
        assert m._classify(results) == ConnectivityState.ONLINE


# ---------------------------------------------------------------------------
# Debounce
# ---------------------------------------------------------------------------


class TestDebounce:
    async def test_first_probe_fires_change_immediately(self):
        # From UNKNOWN → the first observed state fires without debounce.
        m = ConnectivityMonitor(debounce_matches=2)
        fired = []
        m.on_state_change(lambda old, new: fired.append((old.value, new.value)))
        # Manually push a state as if a probe had happened.
        await m._transition(ConnectivityState.ONLINE)
        assert m.state == ConnectivityState.ONLINE
        assert fired == [("unknown", "online")]

    async def test_transition_requires_debounce(self):
        m = ConnectivityMonitor(debounce_matches=2)
        # Establish ONLINE first.
        await m._transition(ConnectivityState.ONLINE)
        fired = []
        m.on_state_change(lambda old, new: fired.append((old.value, new.value)))
        # Single OFFLINE observation must not fire.
        await m._transition(ConnectivityState.OFFLINE)
        assert m.state == ConnectivityState.ONLINE
        assert fired == []
        # Second consecutive OFFLINE observation crosses debounce.
        await m._transition(ConnectivityState.OFFLINE)
        assert m.state == ConnectivityState.OFFLINE
        assert fired == [("online", "offline")]

    async def test_flap_resets_pending(self):
        m = ConnectivityMonitor(debounce_matches=2)
        await m._transition(ConnectivityState.ONLINE)
        # OFFLINE seen once, then ONLINE seen again — no transition.
        await m._transition(ConnectivityState.OFFLINE)
        await m._transition(ConnectivityState.ONLINE)
        assert m.state == ConnectivityState.ONLINE


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------


class TestCallbacks:
    async def test_async_callback_awaited(self):
        m = ConnectivityMonitor(debounce_matches=1)
        seen = []

        async def cb(old, new):
            await asyncio.sleep(0)
            seen.append((old.value, new.value))

        m.on_state_change(cb)
        await m._transition(ConnectivityState.ONLINE)
        assert seen == [("unknown", "online")]

    async def test_bad_callback_swallowed(self):
        m = ConnectivityMonitor(debounce_matches=1)

        def bad_cb(old, new):
            raise RuntimeError("nope")

        good_cb_calls = []
        m.on_state_change(bad_cb)
        m.on_state_change(lambda old, new: good_cb_calls.append((old, new)))
        await m._transition(ConnectivityState.ONLINE)
        assert len(good_cb_calls) == 1


# ---------------------------------------------------------------------------
# Probe execution — mocked
# ---------------------------------------------------------------------------


class TestProbing:
    async def test_probe_reports_reachable_on_connect(self):
        m = ConnectivityMonitor(
            targets=(ProbeTarget("test", "example.com", is_ai_vendor=False),),
            debounce_matches=1,
        )

        class _FakeReader:
            pass

        class _FakeWriter:
            def close(self): pass

            async def wait_closed(self): pass

        async def _fake_open(**kwargs):
            return _FakeReader(), _FakeWriter()

        with patch("praxis.connectivity.asyncio.open_connection", side_effect=_fake_open):
            result = await m._probe_target(m._targets[0])
        assert result.reachable

    async def test_probe_reports_unreachable_on_timeout(self):
        m = ConnectivityMonitor(
            targets=(ProbeTarget("test", "unreachable.example.invalid", is_ai_vendor=False),),
            per_probe_timeout=0.05,
            debounce_matches=1,
        )
        result = await m._probe_target(m._targets[0])
        assert not result.reachable


# ---------------------------------------------------------------------------
# Snapshot serialisation
# ---------------------------------------------------------------------------


class TestSnapshot:
    async def test_snapshot_is_jsonable(self):
        import json

        m = ConnectivityMonitor(debounce_matches=1)
        m._last_probes = [
            ProbeResult("anthropic", True, 20.0),
            ProbeResult("openai", False, 2000, "timeout"),
            ProbeResult("internet", True, 8.5),
        ]
        m._state = ConnectivityState.DEGRADED
        m._last_checked = 12345.0
        s = m.snapshot()
        # Must round-trip through JSON.
        _ = json.dumps(s)
        assert s["state"] == "degraded"
        assert len(s["probes"]) == 3
