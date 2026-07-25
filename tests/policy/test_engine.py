"""Policy engine tests.

The clock is injected, so TTL expiry is tested by advancing a variable rather
than sleeping. That is the practical payoff of keeping this module pure.
"""

from __future__ import annotations

import pytest
import yaml

from kams.detect.base import Finding, FindingKind, Severity
from kams.policy.engine import PolicyEngine
from kams.policy.model import Action, Policy, parse_duration, parse_rate


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def finding(**kw) -> Finding:
    base = dict(
        kind=FindingKind.INTEGRITY_DRIFT,
        severity=Severity.CRITICAL,
        detector="integrity.definition_drift",
        server="notes-mcp",
        summary="test finding",
        tool="save_note",
        confidence=0.9,
    )
    base.update(kw)
    return Finding(**base)


POLICY = Policy.parse(yaml.safe_load("""
version: 1
defaults: {action: allow, fail_mode: open}
rules:
  - name: quarantine-critical
    match: {kind: INTEGRITY_DRIFT, severity: [CRITICAL], min_confidence: 0.6}
    action: quarantine_server
    ttl: 1h
    reason: pinned definition poisoned
  - name: block-result-injection
    match: {detector: integrity.result_injection, min_severity: HIGH}
    action: block_tool
    ttl: 15m
  - name: warn-lesser-drift
    match: {kind: INTEGRITY_DRIFT}
    action: warn
  - name: block-credentials
    match: {kind: EGRESS_SENSITIVE, classes: [aws_key, private_key]}
    unless: {server: [vault-mcp]}
    action: block_tool
"""))


class TestDuration:
    @pytest.mark.parametrize("text,expected", [
        ("30s", 30), ("15m", 900), ("1h", 3600), ("7d", 604800), ("45", 45), (90, 90),
    ])
    def test_parses(self, text, expected):
        assert parse_duration(text) == expected

    def test_rejects_nonsense(self):
        with pytest.raises(ValueError):
            parse_duration("soon")


class TestRate:
    @pytest.mark.parametrize("text,expected", [
        ("4/min", (4, 60.0)),
        ("2/second", (2, 1.0)),
        ("10/hour", (10, 3600.0)),
    ])
    def test_parses(self, text, expected):
        assert parse_rate(text) == expected

    def test_rejects_missing_rate_on_rate_limit_rule(self):
        with pytest.raises(ValueError, match="bad rate"):
            Policy.parse({"rules": [{"name": "r", "action": "rate_limit"}]})


class TestMatching:
    def test_first_match_wins_in_file_order(self):
        engine = PolicyEngine(POLICY)
        # Matches both quarantine-critical and warn-lesser-drift; the earlier
        # rule must win, because file order IS evaluation order.
        d = engine.evaluate([finding()])
        assert len(d) == 1
        assert d[0].rule == "quarantine-critical"
        assert d[0].action is Action.QUARANTINE_SERVER

    def test_lower_severity_falls_through_to_warn(self):
        d = PolicyEngine(POLICY).evaluate([finding(severity=Severity.MEDIUM)])
        assert d[0].rule == "warn-lesser-drift"
        assert d[0].action is Action.WARN

    def test_confidence_gate_excludes(self):
        """A low-confidence heuristic should not trigger containment."""
        d = PolicyEngine(POLICY).evaluate([finding(confidence=0.2)])
        assert d[0].rule == "warn-lesser-drift"

    def test_unless_exempts_allowlisted_server(self):
        engine = PolicyEngine(POLICY)
        f = finding(kind=FindingKind.EGRESS_SENSITIVE, server="vault-mcp",
                    evidence={"classes": ["aws_key"]})
        assert engine.evaluate([f]) == []

    def test_unless_does_not_exempt_others(self):
        f = finding(kind=FindingKind.EGRESS_SENSITIVE, server="random-mcp",
                    evidence={"classes": ["aws_key"]})
        assert PolicyEngine(POLICY).evaluate([f])[0].action is Action.BLOCK_TOOL

    def test_class_matching_needs_an_intersection(self):
        f = finding(kind=FindingKind.EGRESS_SENSITIVE, server="x", evidence={"classes": ["email"]})
        assert PolicyEngine(POLICY).evaluate([f]) == []

    def test_unmatched_finding_is_observed_not_enforced(self):
        """Silence from policy is not silence from telemetry."""
        engine = PolicyEngine(Policy.permissive())
        assert engine.evaluate([finding()]) == []
        assert engine.check("notes-mcp", "save_note").allowed is True


class TestEnforcement:
    def test_quarantine_blocks_every_tool_on_the_server(self):
        engine = PolicyEngine(POLICY)
        engine.apply(engine.evaluate([finding()]))
        assert engine.check("notes-mcp", "save_note").allowed is False
        # Quarantine is server-wide, not scoped to the offending tool.
        assert engine.check("notes-mcp", "list_notes").allowed is False

    def test_quarantine_does_not_leak_to_other_servers(self):
        engine = PolicyEngine(POLICY)
        engine.apply(engine.evaluate([finding()]))
        assert engine.check("docs-mcp", "search").allowed is True

    def test_block_tool_is_scoped_to_that_tool(self):
        engine = PolicyEngine(POLICY)
        f = finding(detector="integrity.result_injection", severity=Severity.HIGH,
                    kind=FindingKind.INTEGRITY_INJECTION, tool="fetch")
        engine.apply(engine.evaluate([f]))
        assert engine.check("notes-mcp", "fetch").allowed is False
        assert engine.check("notes-mcp", "list_notes").allowed is True

    def test_warn_installs_nothing(self):
        engine = PolicyEngine(POLICY)
        engine.apply(engine.evaluate([finding(severity=Severity.MEDIUM)]))
        assert engine.restrictions == []
        assert engine.check("notes-mcp", "save_note").allowed is True

    def test_block_message_names_the_rule(self):
        """An operator reading the error should not have to grep the source."""
        engine = PolicyEngine(POLICY)
        engine.apply(engine.evaluate([finding()]))
        msg = engine.check("notes-mcp", "save_note").message
        assert "quarantine-critical" in msg
        assert "pinned definition poisoned" in msg

    def test_rate_limit_allows_budget_then_blocks_and_recovers(self):
        clock = FakeClock()
        policy = Policy.parse({
            "rules": [{
                "name": "slow-retries",
                "match": {"detector": "behavioural.retry_storm"},
                "action": "rate_limit",
                "rate": "2/min",
                "ttl": "10m",
            }]
        })
        engine = PolicyEngine(policy, clock=clock)
        retry = finding(
            kind=FindingKind.BEHAVIOURAL_THRASH,
            detector="behavioural.retry_storm",
        )
        engine.apply(engine.evaluate([retry]))

        assert engine.check("notes-mcp", "save_note").allowed is True
        assert engine.check("notes-mcp", "save_note").allowed is True
        assert engine.check("notes-mcp", "save_note").allowed is False
        clock.advance(61)
        assert engine.check("notes-mcp", "save_note").allowed is True


class TestTTL:
    def test_restriction_expires(self):
        clock = FakeClock()
        engine = PolicyEngine(POLICY, clock=clock)
        engine.apply(engine.evaluate([finding()]))
        assert engine.check("notes-mcp", "save_note").allowed is False

        clock.advance(3599)
        assert engine.check("notes-mcp", "save_note").allowed is False
        clock.advance(2)
        assert engine.check("notes-mcp", "save_note").allowed is True

    def test_lift_removes_early(self):
        engine = PolicyEngine(POLICY, clock=FakeClock())
        engine.apply(engine.evaluate([finding()]))
        assert engine.lift("notes-mcp") == 1
        assert engine.check("notes-mcp", "save_note").allowed is True


class TestWebhookPath:
    """The SigNoz path lands on the same state as the reflex path."""

    def test_direct_quarantine(self):
        engine = PolicyEngine(POLICY, clock=FakeClock())
        engine.quarantine("flaky-mcp", rule="signoz:error-rate", reason="20% errors over 5m", ttl=600)
        v = engine.check("flaky-mcp", "anything")
        assert v.allowed is False
        assert "signoz:error-rate" in v.message

    def test_webhook_quarantine_also_expires(self):
        clock = FakeClock()
        engine = PolicyEngine(POLICY, clock=clock)
        engine.quarantine("flaky-mcp", rule="r", reason="x", ttl=60)
        clock.advance(61)
        assert engine.check("flaky-mcp", "anything").allowed is True


class TestResilience:
    def test_bad_rule_does_not_break_evaluation(self):
        """A rule that throws is skipped, never fatal (principle 1)."""
        class Exploding:
            name = "bad"
            action = Action.BLOCK_TOOL
            def applies_to(self, _):
                raise RuntimeError("boom")

        policy = Policy.permissive()
        policy.rules = [Exploding(), *POLICY.rules]
        engine = PolicyEngine(policy)
        assert engine.evaluate([finding()])[0].rule == "quarantine-critical"

    def test_rule_without_name_is_rejected_at_parse(self):
        with pytest.raises(ValueError, match="name"):
            Policy.parse({"rules": [{"action": "block_tool"}]})

    def test_unknown_action_is_rejected_at_parse(self):
        with pytest.raises(ValueError, match="unknown action"):
            Policy.parse({"rules": [{"name": "r", "action": "detonate"}]})


class TestShippedPolicy:
    def test_repo_policy_parses(self):
        """The policy.yaml we ship must actually load."""
        policy = Policy.load("policy.yaml")
        assert policy.rules
        assert policy.fail_open is True
        assert all(r.name for r in policy.rules)

    def test_shipped_policy_quarantines_a_pinned_rug_pull(self):
        engine = PolicyEngine(Policy.load("policy.yaml"))
        engine.apply(engine.evaluate([finding()]))
        assert engine.check("notes-mcp", "save_note").allowed is False
