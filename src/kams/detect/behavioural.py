"""Reliability and behaviour: thrash, retry storms, error rates, latency drift.

The other three detectors ask *what* crossed the boundary. This one asks whether
the interaction itself is healthy — which is a different question and needs
history rather than a single message.

The design problem worth stating: **repetition is not the same as being stuck.**
An agent polling a build status calls the same tool with the same arguments a
dozen times, and that is correct behaviour. An agent in a loop does the same
thing. Flagging on repetition alone produces an alert that fires constantly on
healthy workloads and gets muted.

The discriminator is the *result*. Identical call plus identical result means the
agent learned nothing and is going round in circles. Identical call plus a
changing result is polling, and polling is fine. That single check is what makes
this detector usable rather than noisy.

Pure: sliding windows over an injected clock, no I/O, no ambient time.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kams.detect.base import Finding, FindingKind, Severity

DETECTOR_THRASH = "behavioural.thrash"
DETECTOR_RETRY_STORM = "behavioural.retry_storm"
DETECTOR_ERROR_RATE = "behavioural.error_rate"
DETECTOR_LATENCY = "behavioural.latency_degradation"

Clock = Callable[[], float]


def digest(obj: Any) -> str:
    """Stable digest of a call's arguments or result.

    Canonicalised so key ordering does not make two identical calls look
    different — which would defeat thrash detection entirely.
    """
    try:
        data = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        data = repr(obj)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


@dataclass
class CallRecord:
    tool: str
    args_digest: str
    result_digest: str | None
    is_error: bool
    duration: float
    at: float


@dataclass
class Thresholds:
    window: float = 120.0
    # Repeats of an identical (tool, args, result) triple before it is thrash.
    thrash_repeats: int = 4
    # Consecutive errors from one tool before it is a storm.
    storm_errors: int = 4
    # Error ratio over the window, only assessed once there are enough calls
    # for the ratio to mean anything.
    error_rate: float = 0.5
    error_rate_min_calls: int = 6
    # Latency multiple over the tool's own established median.
    latency_multiple: float = 4.0
    latency_min_samples: int = 5
    # Absolute floor, so a tool that normally takes 2ms does not alert at 8ms.
    latency_floor: float = 1.0


class BehaviouralDetector:
    def __init__(self, thresholds: Thresholds | None = None, *, clock: Clock = time.monotonic) -> None:
        self.t = thresholds or Thresholds()
        self._clock = clock
        self._calls: dict[str, deque[CallRecord]] = {}
        self._latency: dict[tuple[str, str], deque[float]] = {}
        # Suppress repeat findings for the same condition inside one window --
        # a loop would otherwise emit a finding per iteration, which is itself
        # a form of noise.
        self._reported: dict[tuple[str, str, str], float] = {}

    # ---- ingest --------------------------------------------------------------

    def record(
        self,
        server: str,
        tool: str,
        *,
        arguments: Any,
        result: Any = None,
        is_error: bool = False,
        duration: float = 0.0,
    ) -> list[Finding]:
        now = self._clock()
        window = self._calls.setdefault(server, deque())
        window.append(
            CallRecord(
                tool=tool,
                args_digest=digest(arguments),
                # An error has no meaningful result to compare, so leave it
                # None rather than letting all errors look identical.
                result_digest=None if is_error else digest(result),
                is_error=is_error,
                duration=duration,
                at=now,
            )
        )
        self._evict(window, now)

        lat = self._latency.setdefault((server, tool), deque(maxlen=50))

        findings: list[Finding] = []
        findings += self._check_thrash(server, window, now)
        findings += self._check_storm(server, tool, window, now)
        findings += self._check_error_rate(server, window, now)
        findings += self._check_latency(server, tool, lat, duration, now)

        # Record latency after checking, so a call is never compared to itself.
        if not is_error and duration > 0:
            lat.append(duration)

        return findings

    def _evict(self, window: deque[CallRecord], now: float) -> None:
        cutoff = now - self.t.window
        while window and window[0].at < cutoff:
            window.popleft()

    def _once(self, key: tuple[str, str, str], now: float) -> bool:
        """True if this condition has not been reported inside the window."""
        last = self._reported.get(key)
        if last is not None and (now - last) < self.t.window:
            return False
        self._reported[key] = now
        return True

    # ---- detectors -----------------------------------------------------------

    def _check_thrash(self, server: str, window: deque[CallRecord], now: float) -> list[Finding]:
        latest = window[-1]
        if latest.is_error or latest.result_digest is None:
            return []

        # Identical call AND identical result: the agent is learning nothing.
        identical = [
            c for c in window
            if c.tool == latest.tool
            and c.args_digest == latest.args_digest
            and c.result_digest == latest.result_digest
        ]
        if len(identical) < self.t.thrash_repeats:
            return []
        if not self._once((server, latest.tool, "thrash"), now):
            return []

        span = identical[-1].at - identical[0].at
        return [
            Finding(
                kind=FindingKind.BEHAVIOURAL_THRASH,
                severity=Severity.MEDIUM if len(identical) < self.t.thrash_repeats * 2 else Severity.HIGH,
                detector=DETECTOR_THRASH,
                server=server,
                tool=latest.tool,
                summary=(
                    f"'{latest.tool}' called {len(identical)} times with identical arguments and "
                    f"identical results in {span:.0f}s — the agent is not making progress"
                ),
                evidence={
                    "repeats": len(identical),
                    "window_seconds": round(span, 1),
                    "args_digest": latest.args_digest,
                    "result_digest": latest.result_digest,
                },
                confidence=0.85,
            )
        ]

    def _check_storm(self, server: str, tool: str, window: deque[CallRecord], now: float) -> list[Finding]:
        consecutive = 0
        for call in reversed(window):
            if call.tool != tool:
                continue
            if call.is_error:
                consecutive += 1
            else:
                break
        if consecutive < self.t.storm_errors:
            return []
        if not self._once((server, tool, "storm"), now):
            return []
        return [
            Finding(
                kind=FindingKind.BEHAVIOURAL_THRASH,
                severity=Severity.HIGH,
                detector=DETECTOR_RETRY_STORM,
                server=server,
                tool=tool,
                summary=f"'{tool}' failed {consecutive} times consecutively — retrying against a broken dependency",
                evidence={"consecutive_errors": consecutive},
                confidence=0.9,
            )
        ]

    def _check_error_rate(self, server: str, window: deque[CallRecord], now: float) -> list[Finding]:
        total = len(window)
        if total < self.t.error_rate_min_calls:
            # A 1-of-2 failure is not a 50% error rate in any useful sense.
            return []
        errors = sum(1 for c in window if c.is_error)
        rate = errors / total
        if rate < self.t.error_rate:
            return []
        if not self._once((server, "*", "error_rate"), now):
            return []
        return [
            Finding(
                kind=FindingKind.BEHAVIOURAL_THRASH,
                severity=Severity.HIGH if rate >= 0.8 else Severity.MEDIUM,
                detector=DETECTOR_ERROR_RATE,
                server=server,
                summary=f"'{server}' failed {errors}/{total} calls ({rate:.0%}) in the last {self.t.window:.0f}s",
                evidence={"errors": errors, "total": total, "rate": round(rate, 3)},
                confidence=0.95,
            )
        ]

    def _check_latency(
        self, server: str, tool: str, samples: deque[float], duration: float, now: float
    ) -> list[Finding]:
        if duration <= 0 or len(samples) < self.t.latency_min_samples:
            return []
        median = statistics.median(samples)
        # Compared against the tool's OWN history, not a global threshold: a
        # tool that always takes 30s is not slow, it is that tool.
        if median <= 0 or duration < max(self.t.latency_floor, median * self.t.latency_multiple):
            return []
        if not self._once((server, tool, "latency"), now):
            return []
        return [
            Finding(
                kind=FindingKind.BEHAVIOURAL_THRASH,
                severity=Severity.MEDIUM,
                detector=DETECTOR_LATENCY,
                server=server,
                tool=tool,
                summary=(
                    f"'{tool}' took {duration:.1f}s against a median of {median:.1f}s "
                    f"over its last {len(samples)} calls"
                ),
                evidence={
                    "duration_seconds": round(duration, 3),
                    "median_seconds": round(median, 3),
                    "samples": len(samples),
                },
                confidence=0.7,
            )
        ]
