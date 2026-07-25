"""Attributing context-window cost to the MCP server that caused it.

Tool results are inserted into the model's context, so every MCP server imposes
a token cost on every subsequent inference in that conversation. Nothing today
attributes that cost back to the dependency responsible, which is why
`mcp.context.cost.tokens` is part of the semconv proposal.

Honesty about measurement is the whole design here. An interceptor cannot see
the model's tokenizer, so per-call figures are estimates. Rather than quietly
publishing an estimate as though it were measured, every emission carries
`mcp.context.cost.estimated`, and the estimator **calibrates itself** when
ground truth arrives:

  * The shim estimates each result as it passes.
  * An instrumented agent reports the real `usage.inputTokens` delta for a turn.
  * `reconcile()` distributes that measured delta across the results that
    entered context, and carries a per-server correction factor forward.

So per-call figures start as an estimate and get progressively less wrong, while
turn-level figures are ground truth. A cost metric that silently mixed the two
would not be one anyone should trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kams.detect.base import Finding, FindingKind, Severity

DETECTOR = "cost.context_spike"

# Bytes per token before calibration. Roughly right for JSON-ish English text;
# deliberately a starting point, not a claim.
DEFAULT_BYTES_PER_TOKEN = 3.6

# Correction factors outside this range indicate the reconciliation was matched
# against the wrong turn rather than a genuinely unusual encoding.
MIN_FACTOR, MAX_FACTOR = 0.25, 4.0


@dataclass
class Attribution:
    server: str
    tool: str
    tokens: int
    estimated: bool


@dataclass
class ServerCalibration:
    factor: float = 1.0
    samples: int = 0

    def update(self, observed_ratio: float) -> None:
        """Exponential moving average, so one odd turn cannot swing the factor."""
        clamped = max(MIN_FACTOR, min(MAX_FACTOR, observed_ratio))
        weight = 0.3 if self.samples else 1.0
        self.factor = (1 - weight) * self.factor + weight * clamped
        self.samples += 1


class ContextCostEstimator:
    def __init__(self, *, bytes_per_token: float = DEFAULT_BYTES_PER_TOKEN,
                 spike_threshold: int = 20_000) -> None:
        self.bytes_per_token = bytes_per_token
        self.spike_threshold = spike_threshold
        self._calibration: dict[str, ServerCalibration] = {}
        # Results seen since the last reconcile, per conversation.
        self._pending: dict[str, list[Attribution]] = {}

    # ---- estimation ----------------------------------------------------------

    def estimate(self, server: str, tool: str, result_bytes: int) -> Attribution:
        cal = self._calibration.get(server)
        factor = cal.factor if cal else 1.0
        tokens = max(1, int((result_bytes / self.bytes_per_token) * factor))
        return Attribution(server=server, tool=tool, tokens=tokens, estimated=True)

    def record(self, conversation_id: str, attribution: Attribution) -> None:
        self._pending.setdefault(conversation_id, []).append(attribution)

    # ---- reconciliation ------------------------------------------------------

    def reconcile(self, conversation_id: str, measured_input_tokens: int) -> list[Attribution]:
        """Distribute a measured token delta across the results that caused it.

        Proportional to estimate: a result estimated at twice another's size gets
        twice the measured tokens. Crude, but it is the only defensible split
        without per-result tokenization, and it converges the correction factor.
        """
        pending = self._pending.pop(conversation_id, [])
        if not pending or measured_input_tokens <= 0:
            return []

        total_estimate = sum(a.tokens for a in pending) or 1
        out: list[Attribution] = []
        for a in pending:
            share = a.tokens / total_estimate
            actual = max(1, int(measured_input_tokens * share))
            out.append(Attribution(server=a.server, tool=a.tool, tokens=actual, estimated=False))

        # Calibrate per server on the aggregate ratio for this turn.
        by_server: dict[str, tuple[int, int]] = {}
        for est, act in zip(pending, out):
            e, a = by_server.get(est.server, (0, 0))
            by_server[est.server] = (e + est.tokens, a + act.tokens)
        for server, (est_total, act_total) in by_server.items():
            if est_total > 0:
                self._calibration.setdefault(server, ServerCalibration()).update(act_total / est_total)

        return out

    def calibration(self, server: str) -> ServerCalibration | None:
        return self._calibration.get(server)

    # ---- findings ------------------------------------------------------------

    def check_spike(self, attribution: Attribution) -> list[Finding]:
        if attribution.tokens < self.spike_threshold:
            return []
        severity = Severity.HIGH if attribution.tokens >= self.spike_threshold * 2 else Severity.MEDIUM
        return [
            Finding(
                kind=FindingKind.COST_SPIKE,
                severity=severity,
                detector=DETECTOR,
                server=attribution.server,
                tool=attribution.tool,
                summary=(
                    f"'{attribution.tool}' returned roughly {attribution.tokens:,} tokens of "
                    f"context — a single result consuming a disproportionate share of the window"
                ),
                evidence={
                    "tokens": attribution.tokens,
                    "estimated": attribution.estimated,
                    "threshold": self.spike_threshold,
                },
                confidence=0.7 if attribution.estimated else 0.95,
            )
        ]
