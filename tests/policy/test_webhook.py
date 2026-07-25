"""Alert-webhook and shared-state tests.

The webhook is the fleet-scale half of the control loop, and it is exposed to
payloads Kams does not control. So the tests lean on the awkward cases: missing
labels, resolved notifications, varying schemas — the things that decide whether
this quarantines the right server or the wrong one.
"""

from __future__ import annotations

import json

import pytest

from kams.daemon.state import SharedState, StoredRestriction
from kams.daemon.webhook import extract_rule, extract_server, is_firing
from kams.policy.engine import PolicyEngine
from kams.policy.model import Policy


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


# --- payload parsing ---------------------------------------------------------


class TestExtractServer:
    def test_from_alert_labels(self):
        assert extract_server({"alerts": [{"labels": {"server": "notes-mcp"}}]}) == "notes-mcp"

    def test_from_common_labels(self):
        assert extract_server({"commonLabels": {"server": "github-mcp"}}) == "github-mcp"

    def test_from_dotted_semconv_label(self):
        assert extract_server({"alerts": [{"labels": {"mcp.server.name": "fs-mcp"}}]}) == "fs-mcp"

    def test_missing_returns_none(self):
        """Refuse to guess. Quarantining the wrong server is worse than none."""
        assert extract_server({"alerts": [{"labels": {"severity": "critical"}}]}) is None
        assert extract_server({}) is None


class TestIsFiring:
    def test_firing(self):
        assert is_firing({"status": "firing"}) is True

    def test_resolved(self):
        assert is_firing({"status": "resolved"}) is False

    def test_nested_status(self):
        assert is_firing({"alerts": [{"status": "resolved"}]}) is False

    def test_absent_status_treated_as_firing(self):
        """A missed containment is worse than an over-eager TTL-bounded one."""
        assert is_firing({"ruleName": "x"}) is True


class TestExtractRule:
    def test_prefixes_with_signoz(self):
        """Provenance matters: an operator must be able to tell which path
        installed a restriction."""
        assert extract_rule({"ruleName": "drift"}) == "signoz:drift"

    def test_falls_back(self):
        assert extract_rule({}) == "signoz:alert"


# --- shared state ------------------------------------------------------------


@pytest.fixture
def state(tmp_path):
    return SharedState(tmp_path / "kams-state.json", clock=FakeClock())


def restriction(server="notes-mcp", ttl=3600.0, now=1000.0, **kw) -> StoredRestriction:
    base = dict(
        action="quarantine_server", server=server, tool=None, rule="r",
        reason="because", created_at=now, expires_at=now + ttl if ttl else None,
        origin="signoz",
    )
    base.update(kw)
    return StoredRestriction(**base)


class TestSharedState:
    def test_roundtrip(self, state):
        state.add(restriction())
        assert [r.server for r in state.active(force=True)] == ["notes-mcp"]

    def test_visible_to_a_second_reader(self, tmp_path):
        """The whole point: separate processes must see the same decision."""
        clock = FakeClock()
        writer = SharedState(tmp_path / "s.json", clock=clock)
        writer.add(restriction())
        reader = SharedState(tmp_path / "s.json", clock=clock)
        assert [r.server for r in reader.active(force=True)] == ["notes-mcp"]

    def test_expiry(self, tmp_path):
        clock = FakeClock()
        s = SharedState(tmp_path / "s.json", clock=clock)
        s.add(restriction(ttl=60))
        assert len(s.active(force=True)) == 1
        clock.advance(61)
        assert s.active(force=True) == []

    def test_lift(self, state):
        state.add(restriction())
        assert state.lift("notes-mcp") == 1
        assert state.active(force=True) == []

    def test_lift_unknown_is_noop(self, state):
        state.add(restriction())
        assert state.lift("other") == 0

    def test_same_target_replaces_rather_than_accumulates(self, state):
        state.add(restriction(rule="first"))
        state.add(restriction(rule="second"))
        active = state.active(force=True)
        assert len(active) == 1
        assert active[0].rule == "second"

    def test_corrupt_file_fails_open(self, tmp_path):
        """Principle 1: unreadable state means no restrictions, not no service."""
        path = tmp_path / "s.json"
        path.write_text("{not json")
        assert SharedState(path).active(force=True) == []

    def test_missing_file_fails_open(self, tmp_path):
        assert SharedState(tmp_path / "absent.json").active(force=True) == []

    def test_write_is_atomic_shaped(self, state, tmp_path):
        """Readers must never see a partial document."""
        state.add(restriction())
        payload = json.loads((tmp_path / "kams-state.json").read_text())
        assert payload["version"] == 1
        assert len(payload["restrictions"]) == 1


# --- engine honouring shared state -------------------------------------------


class TestEngineWithSharedState:
    def test_shim_honours_a_daemon_installed_quarantine(self, tmp_path):
        """The SigNoz path and the reflex path converge on one engine.

        Nothing was detected locally here — the block comes purely from state
        another process wrote.
        """
        clock = FakeClock()
        shared = SharedState(tmp_path / "s.json", clock=clock)
        shared.add(restriction(server="notes-mcp"))

        engine = PolicyEngine(Policy.permissive(), clock=clock,
                              shared=SharedState(tmp_path / "s.json", clock=clock))
        verdict = engine.check("notes-mcp", "save_note")
        assert verdict.allowed is False
        assert "signoz" not in verdict.message  # rule name is what surfaces
        assert "quarantined" in verdict.message

    def test_other_servers_unaffected(self, tmp_path):
        clock = FakeClock()
        SharedState(tmp_path / "s.json", clock=clock).add(restriction(server="notes-mcp"))
        engine = PolicyEngine(Policy.permissive(), clock=clock,
                              shared=SharedState(tmp_path / "s.json", clock=clock))
        assert engine.check("docs-mcp", "search").allowed is True

    def test_expired_shared_restriction_stops_blocking(self, tmp_path):
        clock = FakeClock()
        SharedState(tmp_path / "s.json", clock=clock).add(restriction(ttl=60))
        engine = PolicyEngine(Policy.permissive(), clock=clock,
                              shared=SharedState(tmp_path / "s.json", clock=clock))
        assert engine.check("notes-mcp", "x").allowed is False
        clock.advance(61)
        assert engine.check("notes-mcp", "x").allowed is True

    def test_engine_without_shared_state_still_works(self):
        """kamsd is optional. A shim must run standalone."""
        engine = PolicyEngine(Policy.permissive())
        assert engine.check("anything", "tool").allowed is True
