"""Behavioural detector tests.

`TestPollingIsNotThrash` is the class that decides whether this detector is
usable. Repetition alone is normal — agents poll. If the detector cannot tell
polling from a loop it fires on healthy workloads, gets muted, and protects
nobody.
"""

from __future__ import annotations

import pytest

from kams.detect.base import FindingKind, Severity
from kams.detect.behavioural import BehaviouralDetector, Thresholds


class FakeClock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def det(clock):
    return BehaviouralDetector(clock=clock)


def findings_of(records, detector_name):
    return [f for f in records if f.detector == detector_name]


class TestThrash:
    def test_identical_call_and_result_is_thrash(self, det, clock):
        """The agent is learning nothing — same question, same answer, again."""
        out = []
        for _ in range(5):
            out += det.record("mcp", "read_file", arguments={"p": "/a"}, result={"content": "x"}, duration=0.1)
            clock.advance(1)
        thrash = findings_of(out, "behavioural.thrash")
        assert len(thrash) == 1
        assert thrash[0].kind is FindingKind.BEHAVIOURAL_THRASH
        assert thrash[0].evidence["repeats"] >= 4

    def test_below_threshold_stays_quiet(self, det, clock):
        out = []
        for _ in range(3):
            out += det.record("mcp", "read_file", arguments={"p": "/a"}, result={"content": "x"}, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.thrash") == []

    def test_reported_once_per_window(self, det, clock):
        """A loop must not emit a finding per iteration — that is its own noise."""
        out = []
        for _ in range(12):
            out += det.record("mcp", "read_file", arguments={"p": "/a"}, result={"content": "x"}, duration=0.1)
            clock.advance(1)
        assert len(findings_of(out, "behavioural.thrash")) == 1

    def test_argument_key_order_does_not_hide_a_loop(self, det, clock):
        """Canonicalisation matters: reordered keys are the same call."""
        out = []
        for i in range(5):
            args = {"a": 1, "b": 2} if i % 2 else {"b": 2, "a": 1}
            out += det.record("mcp", "t", arguments=args, result={"r": 1}, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.thrash")

    def test_window_expiry_resets(self, det, clock):
        out = []
        for _ in range(3):
            out += det.record("mcp", "t", arguments={"p": 1}, result={"r": 1}, duration=0.1)
            clock.advance(1)
        clock.advance(300)  # well past the window
        for _ in range(3):
            out += det.record("mcp", "t", arguments={"p": 1}, result={"r": 1}, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.thrash") == []


class TestPollingIsNotThrash:
    """The discriminator that makes this detector usable."""

    def test_changing_results_are_polling(self, det, clock):
        """Same call, different answer each time — a status poll, not a loop."""
        out = []
        for i in range(10):
            out += det.record("ci-mcp", "build_status",
                              arguments={"id": "b1"}, result={"progress": i}, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.thrash") == []

    def test_result_settling_then_repeating_does_fire(self, det, clock):
        """Once the answer stops changing, continuing to ask is a loop."""
        out = []
        for i in range(3):
            out += det.record("ci-mcp", "build_status",
                              arguments={"id": "b1"}, result={"progress": i}, duration=0.1)
            clock.advance(1)
        for _ in range(5):
            out += det.record("ci-mcp", "build_status",
                              arguments={"id": "b1"}, result={"progress": "done"}, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.thrash")

    def test_varied_arguments_are_not_thrash(self, det, clock):
        out = []
        for i in range(10):
            out += det.record("mcp", "read_file", arguments={"p": f"/f{i}"}, result={"c": "x"}, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.thrash") == []

    def test_interleaved_tools_are_not_thrash(self, det, clock):
        out = []
        for i in range(12):
            tool = ["read", "write", "list"][i % 3]
            out += det.record("mcp", tool, arguments={"p": "/a"}, result={"c": i}, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.thrash") == []


class TestRetryStorm:
    def test_consecutive_failures_flagged(self, det, clock):
        out = []
        for _ in range(4):
            out += det.record("flaky", "fetch", arguments={"u": "x"}, is_error=True, duration=0.1)
            clock.advance(1)
        storm = findings_of(out, "behavioural.retry_storm")
        assert len(storm) == 1
        assert storm[0].severity is Severity.HIGH

    def test_a_success_breaks_the_streak(self, det, clock):
        out = []
        for i in range(8):
            err = i != 3  # one success partway through
            out += det.record("flaky", "fetch", arguments={"u": "x"},
                              result=None if err else {"ok": i}, is_error=err, duration=0.1)
            clock.advance(1)
        # Streak restarts after the success, so only the later run qualifies.
        assert len(findings_of(out, "behavioural.retry_storm")) == 1

    def test_errors_on_different_tools_do_not_combine(self, det, clock):
        out = []
        for i in range(6):
            out += det.record("mcp", f"tool{i % 3}", arguments={}, is_error=True, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.retry_storm") == []


class TestErrorRate:
    def test_high_rate_flagged(self, det, clock):
        out = []
        for i in range(8):
            out += det.record("flaky", f"t{i}", arguments={}, is_error=(i % 2 == 0),
                              result={"r": i}, duration=0.1)
            clock.advance(1)
        rate = findings_of(out, "behavioural.error_rate")
        assert rate
        assert rate[0].evidence["rate"] >= 0.5

    def test_small_samples_do_not_trigger(self, det, clock):
        """One failure in two calls is not a 50% error rate in any useful sense."""
        out = det.record("mcp", "t", arguments={}, is_error=True, duration=0.1)
        clock.advance(1)
        out += det.record("mcp", "t", arguments={}, result={"ok": 1}, duration=0.1)
        assert findings_of(out, "behavioural.error_rate") == []

    def test_healthy_server_quiet(self, det, clock):
        out = []
        for i in range(20):
            out += det.record("good", "t", arguments={"i": i}, result={"r": i}, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.error_rate") == []


class TestLatency:
    def test_spike_against_own_baseline(self, det, clock):
        out = []
        for i in range(6):
            out += det.record("mcp", "query", arguments={"i": i}, result={"r": i}, duration=2.0)
            clock.advance(1)
        out += det.record("mcp", "query", arguments={"n": 1}, result={"r": 9}, duration=20.0)
        lat = findings_of(out, "behavioural.latency_degradation")
        assert lat
        assert lat[0].evidence["median_seconds"] == 2.0

    def test_consistently_slow_tool_is_not_flagged(self, det, clock):
        """A tool that always takes 30s is not slow — it is that tool."""
        out = []
        for i in range(12):
            out += det.record("mcp", "slow_export", arguments={"i": i}, result={"r": i}, duration=30.0)
            clock.advance(1)
        assert findings_of(out, "behavioural.latency_degradation") == []

    def test_fast_tool_does_not_alert_on_a_trivial_absolute_jump(self, det, clock):
        """2ms -> 8ms is 4x but means nothing; the absolute floor suppresses it."""
        out = []
        for i in range(8):
            out += det.record("mcp", "ping", arguments={"i": i}, result={"r": i}, duration=0.002)
            clock.advance(1)
        out += det.record("mcp", "ping", arguments={"n": 1}, result={"r": 1}, duration=0.008)
        assert findings_of(out, "behavioural.latency_degradation") == []

    def test_no_baseline_means_no_alert(self, det):
        out = det.record("mcp", "first", arguments={}, result={"r": 1}, duration=99.0)
        assert findings_of(out, "behavioural.latency_degradation") == []


class TestIsolation:
    def test_servers_are_tracked_separately(self, det, clock):
        out = []
        for _ in range(5):
            out += det.record("a", "t", arguments={"p": 1}, result={"r": 1}, duration=0.1)
            out += det.record("b", "t", arguments={"p": 2}, result={"r": 2}, duration=0.1)
            clock.advance(1)
        thrash = findings_of(out, "behavioural.thrash")
        assert {f.server for f in thrash} == {"a", "b"}

    def test_custom_thresholds_respected(self, clock):
        det = BehaviouralDetector(Thresholds(thrash_repeats=2), clock=clock)
        out = []
        for _ in range(2):
            out += det.record("mcp", "t", arguments={"p": 1}, result={"r": 1}, duration=0.1)
            clock.advance(1)
        assert findings_of(out, "behavioural.thrash")
