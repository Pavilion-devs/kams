"""Context-cost attribution tests.

The interesting property is not the estimate — it is that an estimate is never
published as though it were measured, and that ground truth makes subsequent
estimates less wrong.
"""

from __future__ import annotations

from kams.detect.base import FindingKind, Severity
from kams.detect.cost import ContextCostEstimator


class TestEstimation:
    def test_estimate_is_flagged_as_estimated(self):
        """The discriminator is the whole point of the semconv proposal."""
        est = ContextCostEstimator()
        a = est.estimate("notes-mcp", "read_file", 3600)
        assert a.estimated is True
        assert a.tokens > 0

    def test_larger_result_costs_more(self):
        est = ContextCostEstimator()
        small = est.estimate("s", "t", 1_000)
        large = est.estimate("s", "t", 100_000)
        assert large.tokens > small.tokens * 10

    def test_tiny_result_still_costs_at_least_one(self):
        assert ContextCostEstimator().estimate("s", "t", 1).tokens >= 1


class TestReconciliation:
    def test_measured_delta_replaces_estimates(self):
        est = ContextCostEstimator()
        for _ in range(2):
            est.record("conv-1", est.estimate("notes-mcp", "read_file", 4000))

        actual = est.reconcile("conv-1", measured_input_tokens=3000)
        assert len(actual) == 2
        assert all(a.estimated is False for a in actual)
        assert sum(a.tokens for a in actual) <= 3000

    def test_split_is_proportional_to_estimate(self):
        est = ContextCostEstimator()
        est.record("c", est.estimate("s", "small", 1000))
        est.record("c", est.estimate("s", "big", 9000))
        actual = {a.tool: a.tokens for a in est.reconcile("c", 10_000)}
        # ~1:9, so the larger result carries the bulk of the measured cost.
        assert actual["big"] > actual["small"] * 5

    def test_calibration_improves_the_next_estimate(self):
        """Ground truth should make future estimates less wrong."""
        est = ContextCostEstimator()
        before = est.estimate("slow-mcp", "t", 10_000).tokens
        est.record("c", est.estimate("slow-mcp", "t", 10_000))
        # Measured cost is far above the estimate -- this server's output
        # tokenizes much denser than the default assumption.
        est.reconcile("c", measured_input_tokens=before * 3)
        after = est.estimate("slow-mcp", "t", 10_000).tokens
        assert after > before

    def test_calibration_is_per_server(self):
        est = ContextCostEstimator()
        base = est.estimate("other-mcp", "t", 10_000).tokens
        est.record("c", est.estimate("dense-mcp", "t", 10_000))
        est.reconcile("c", measured_input_tokens=base * 3)
        assert est.estimate("other-mcp", "t", 10_000).tokens == base
        assert est.calibration("other-mcp") is None

    def test_calibration_is_clamped_against_a_bad_match(self):
        """A reconciliation matched to the wrong turn must not wreck the factor."""
        est = ContextCostEstimator()
        est.record("c", est.estimate("s", "t", 1000))
        est.reconcile("c", measured_input_tokens=10_000_000)
        assert est.calibration("s").factor <= 4.0

    def test_reconcile_with_nothing_pending_is_safe(self):
        assert ContextCostEstimator().reconcile("unknown", 500) == []

    def test_reconcile_ignores_nonpositive_measurement(self):
        est = ContextCostEstimator()
        est.record("c", est.estimate("s", "t", 1000))
        assert est.reconcile("c", 0) == []


class TestSpikeDetection:
    def test_large_result_raises_a_finding(self):
        est = ContextCostEstimator(spike_threshold=1000)
        findings = est.check_spike(est.estimate("chatty-mcp", "dump", 500_000))
        assert findings
        assert findings[0].kind is FindingKind.COST_SPIKE
        assert findings[0].severity is Severity.HIGH

    def test_ordinary_result_does_not(self):
        est = ContextCostEstimator(spike_threshold=20_000)
        assert est.check_spike(est.estimate("s", "t", 2_000)) == []

    def test_estimated_findings_carry_lower_confidence(self):
        """Policy can gate on confidence, so an estimate must say so."""
        est = ContextCostEstimator(spike_threshold=100)
        f = est.check_spike(est.estimate("s", "t", 100_000))[0]
        assert f.confidence < 0.9
        assert f.evidence["estimated"] is True
