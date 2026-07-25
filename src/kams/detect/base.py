"""Finding model shared by every detector.

The uniformity here is what lets the policy engine stay dumb: it matches on
kind/severity/detector without knowing anything about how a finding was
produced. Adding a detector never means touching policy code.

Redaction rule, and the distinction matters:

  * Tool descriptions and schemas are server-advertised *metadata*, not user
    secrets. Quoting a matched phrase is safe and is the whole value of the
    finding -- a human needs to see what the injected text actually said.
  * Call arguments and results carry user data. Those detectors emit class,
    count, and salted digest only, never the value (principle 4).

So redaction is a property of the detector, not of the Finding type. The test
suite enforces the egress side against known-secret fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered so policy can express `severity >= HIGH` naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[value.strip().upper()]


class FindingKind(str, Enum):
    # A pinned tool definition changed.
    INTEGRITY_DRIFT = "INTEGRITY_DRIFT"
    # Text from the server looks like it is addressing the model.
    INTEGRITY_INJECTION = "INTEGRITY_INJECTION"
    # Sensitive data classes crossing into a third-party server.
    EGRESS_SENSITIVE = "EGRESS_SENSITIVE"
    # A server's results are consuming disproportionate context.
    COST_SPIKE = "COST_SPIKE"
    # Loops, retry storms, error-rate breaches.
    BEHAVIOURAL_THRASH = "BEHAVIOURAL_THRASH"
    # A detector itself failed. Recorded, never fatal.
    DETECTOR_ERROR = "DETECTOR_ERROR"


@dataclass(frozen=True)
class Finding:
    kind: FindingKind
    severity: Severity
    detector: str
    server: str
    summary: str
    tool: str | None = None
    # Structured and already safe to log -- see the module docstring.
    evidence: dict[str, Any] = field(default_factory=dict)
    # Heuristics are not certainties. Policy may gate on this.
    confidence: float = 1.0

    def to_attributes(self) -> dict[str, Any]:
        """Flatten onto a span. Nested evidence is left to the log record."""
        from kams.telemetry import semconv as sc

        attrs: dict[str, Any] = {
            sc.KAMS_FINDING_KIND: self.kind.value,
            sc.KAMS_FINDING_SEVERITY: self.severity.name,
            sc.KAMS_FINDING_DETECTOR: self.detector,
            sc.KAMS_FINDING_CONFIDENCE: round(self.confidence, 3),
            sc.KAMS_FINDING_SUMMARY: self.summary[:400],
        }
        if self.tool:
            attrs[sc.GEN_AI_TOOL_NAME] = self.tool
        return attrs


def noisy_or(scored: list[tuple[float, float]]) -> float:
    """Combine independent evidence: 1 - product of (1 - weight*score).

    Chosen over a weighted sum deliberately. Signals here are largely
    independent -- invisible unicode says nothing about whether the text also
    contains an exfiltration URL -- and a single strong signal should be able to
    carry a verdict on its own. A sum would dilute one damning signal among
    several quiet ones, and would need clamping to stay in range.
    """
    remaining = 1.0
    for weight, score in scored:
        if score <= 0:
            continue
        remaining *= 1.0 - max(0.0, min(1.0, weight * score))
    return 1.0 - remaining
