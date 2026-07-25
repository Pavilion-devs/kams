"""OTel tracer/meter setup and W3C context handling for the shim.

Principle 1 governs this whole module: telemetry must never break the workload.
Every export path is best-effort, the exporter never blocks the relay, and a
SigNoz outage degrades to "no telemetry" rather than "no agent".
"""

from __future__ import annotations

import logging
import os

from opentelemetry import metrics, trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import Counter, Histogram, MeterProvider, UpDownCounter
from opentelemetry.sdk.metrics.export import AggregationTemporality
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

log = logging.getLogger("kams.telemetry")

_PROPAGATOR = TraceContextTextMapPropagator()
_INITIALISED = False

DEFAULT_ENDPOINT = "http://localhost:4317"


def setup(service_name: str, *, endpoint: str | None = None, extra_resource: dict | None = None) -> None:
    """Wire up OTLP export. Safe to call more than once.

    `service.name` separates the planes in SigNoz -- `kams-shim` is per-connection
    data-plane throughput, `kamsd` is control-plane activity. Mixing them into one
    service would make both dashboards useless.
    """
    global _INITIALISED
    if _INITIALISED:
        return

    endpoint = endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", DEFAULT_ENDPOINT)

    attrs = {"service.name": service_name, "service.namespace": "kams"}
    if extra_resource:
        attrs.update(extra_resource)
    resource = Resource.create(attrs)

    try:
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=endpoint, insecure=True),
                # Keep the queue shallow and the delay short: a shim is often
                # short-lived, and spans still sitting in a large buffer at exit
                # are spans that never arrive.
                max_queue_size=2048,
                schedule_delay_millis=1000,
            )
        )
        trace.set_tracer_provider(provider)

        # Delta, not cumulative. A shim is short-lived: it exports once or
        # twice and exits. Cumulative counters from a fresh process restart at
        # zero every run, so rate() and increase() see no usable delta and the
        # panels render empty even though the data arrived. Delta temporality
        # makes each export self-contained, which is what SigNoz wants anyway.
        reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(
                endpoint=endpoint,
                insecure=True,
                preferred_temporality={
                    Counter: AggregationTemporality.DELTA,
                    UpDownCounter: AggregationTemporality.DELTA,
                    Histogram: AggregationTemporality.DELTA,
                },
            ),
            export_interval_millis=5000,
        )
        metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))
        _INITIALISED = True
    except Exception as exc:  # noqa: BLE001 - telemetry must never break the workload
        log.warning("telemetry setup failed, continuing without it: %r", exc)


def tracer(name: str = "kams"):
    return trace.get_tracer(name)


def meter(name: str = "kams"):
    return metrics.get_meter(name)


def shutdown() -> None:
    """Flush pending spans on exit. Bounded -- we never hang the agent's teardown."""
    try:
        provider = trace.get_tracer_provider()
        if hasattr(provider, "shutdown"):
            provider.shutdown()
    except Exception as exc:  # noqa: BLE001
        log.debug("tracer shutdown: %r", exc)
    try:
        provider = metrics.get_meter_provider()
        if hasattr(provider, "shutdown"):
            provider.shutdown()
    except Exception as exc:  # noqa: BLE001
        log.debug("meter shutdown: %r", exc)


# --- W3C context over MCP `_meta` --------------------------------------------


def context_from_traceparent(traceparent: str | None, tracestate: str | None = None) -> Context | None:
    """Rebuild parent context from a traceparent carried in `params._meta`.

    Returns None when absent or malformed, which the caller records as an
    orphaned span rather than silently rooting it (architecture.md §5).
    """
    if not traceparent:
        return None
    carrier = {"traceparent": traceparent}
    if tracestate:
        carrier["tracestate"] = tracestate
    try:
        ctx = _PROPAGATOR.extract(carrier)
    except Exception:  # noqa: BLE001
        return None
    span_ctx = trace.get_current_span(ctx).get_span_context()
    return ctx if span_ctx.is_valid else None


def traceparent_from_current() -> tuple[str | None, str | None]:
    """Serialise the active span for injection into an outbound `_meta`."""
    carrier: dict[str, str] = {}
    _PROPAGATOR.inject(carrier)
    return carrier.get("traceparent"), carrier.get("tracestate")
