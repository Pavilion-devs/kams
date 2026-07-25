"""Background enrichment worker.

Findings arrive from shims over HTTP, get judged, and are emitted to SigNoz as
spans linked to the trace that produced them.

Why a queue rather than judging inline in the shim: the shim is in the request
path and a model call takes seconds. Even fire-and-forget from a short-lived
process is unreliable — the shim exits when the agent disconnects and takes any
pending work with it. `kamsd` outlives every connection, which is exactly what
enrichment needs.

The queue is bounded and drops oldest-first when full. Under a flood of findings
the useful response is to keep enriching recent ones and lose old ones, not to
grow memory or block the HTTP handler that is feeding it.
"""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from typing import Any

from opentelemetry.trace import Link, NonRecordingSpan, SpanContext, SpanKind, TraceFlags

from kams.daemon.judge import Judge, Verdict
from kams.telemetry import semconv as sc
from kams.telemetry import tracing

log = logging.getLogger("kams.enrich")

MAX_QUEUE = 256


@dataclass
class EnrichmentJob:
    server: str
    tool: str | None
    detector: str
    severity: str
    summary: str
    evidence: dict[str, Any]
    trace_id: str | None = None
    span_id: str | None = None


def _link_to(trace_id: str | None, span_id: str | None) -> list[Link]:
    """Link back to the span that produced the finding.

    A link rather than a parent: enrichment happens minutes later in a different
    process, so making it a child would distort the original trace's duration.
    """
    if not trace_id or not span_id:
        return []
    try:
        ctx = SpanContext(
            trace_id=int(trace_id, 16),
            span_id=int(span_id, 16),
            is_remote=True,
            trace_flags=TraceFlags(TraceFlags.SAMPLED),
        )
        if not ctx.is_valid:
            return []
        return [Link(ctx)]
    except (ValueError, TypeError):
        return []


class Enricher:
    def __init__(self, judge: Judge | None = None, *, max_queue: int = MAX_QUEUE) -> None:
        self.judge = judge or Judge()
        self._queue: queue.Queue[EnrichmentJob] = queue.Queue(maxsize=max_queue)
        self._tracer = tracing.tracer("kamsd.enrich")
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.processed = 0
        self.dropped = 0

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="kams-enrich")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def submit(self, job: EnrichmentJob) -> bool:
        """Never blocks. Drops oldest when saturated."""
        try:
            self._queue.put_nowait(job)
            return True
        except queue.Full:
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(job)
                self.dropped += 1
                return True
            except (queue.Empty, queue.Full):
                self.dropped += 1
                return False

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._process(job)
            except Exception as exc:  # noqa: BLE001 - a bad job must not kill the worker
                log.warning("enrichment failed: %r", exc)
            finally:
                self.processed += 1

    def _process(self, job: EnrichmentJob) -> None:
        verdict = self.judge.assess(job.evidence)
        self._emit(job, verdict)

    def _emit(self, job: EnrichmentJob, verdict: Verdict | None) -> None:
        attributes: dict[str, Any] = {
            sc.KAMS_FINDING_DETECTOR: job.detector,
            sc.KAMS_FINDING_SEVERITY: job.severity,
            sc.KAMS_SERVER_NAME: job.server,
            "kams.judge.available": verdict is not None,
            **({sc.GEN_AI_TOOL_NAME: job.tool} if job.tool else {}),
            **(verdict.to_attributes() if verdict else {}),
        }
        with self._tracer.start_as_current_span(
            "kams.enrich",
            kind=SpanKind.INTERNAL,
            links=_link_to(job.trace_id, job.span_id),
            attributes=attributes,
        ):
            pass

        if verdict:
            log.info(
                "judge: %s on %s/%s — %s",
                verdict.assessment, job.server, job.tool or "-", verdict.explanation[:160],
            )


__all__ = ["Enricher", "EnrichmentJob", "NonRecordingSpan"]
