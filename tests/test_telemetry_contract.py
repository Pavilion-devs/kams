from __future__ import annotations

from kams.detect.base import Finding, FindingKind, Severity
from kams.protocol import mcp
from kams.shim.interceptor import Interceptor
from kams.telemetry import semconv as sc


class _Instrument:
    def __init__(self) -> None:
        self.records = []

    def add(self, value, attributes=None):
        self.records.append((value, attributes or {}))

    def record(self, value, attributes=None):
        self.records.append((value, attributes or {}))


class _Meter:
    def __init__(self) -> None:
        self.instruments = {}

    def create_counter(self, name, **_kwargs):
        return self.instruments.setdefault(name, _Instrument())

    def create_histogram(self, name, **_kwargs):
        return self.instruments.setdefault(name, _Instrument())


class _SpanContext:
    is_valid = False
    trace_id = 0
    span_id = 0


class _Span:
    def add_event(self, *_args, **_kwargs):
        return None

    def get_span_context(self):
        return _SpanContext()


def _finding(kind, detector, *, server="notes-mcp"):
    return Finding(
        kind=kind,
        severity=Severity.CRITICAL,
        detector=detector,
        server=server,
        tool="save_note",
        summary="test",
        evidence={"baseline_state": "pinned"},
    )


def test_non_drift_findings_never_increment_integrity_drift(monkeypatch):
    meter = _Meter()
    monkeypatch.setattr("kams.shim.interceptor.tracing.meter", lambda _name: meter)
    monkeypatch.setattr("kams.shim.interceptor.tracing.tracer", lambda _name: object())
    interceptor = Interceptor("notes-mcp")

    interceptor._emit(_Span(), [
        _finding(FindingKind.EGRESS_SENSITIVE, "egress.classifier"),
        _finding(FindingKind.COST_SPIKE, "cost.context_spike"),
        _finding(FindingKind.INTEGRITY_INJECTION, "integrity.description_injection"),
    ])

    assert len(meter.instruments[sc.METRIC_FINDINGS].records) == 3
    assert meter.instruments[sc.METRIC_INTEGRITY_DRIFT].records == []


def test_only_definition_drift_increments_drift_metric(monkeypatch):
    meter = _Meter()
    monkeypatch.setattr("kams.shim.interceptor.tracing.meter", lambda _name: meter)
    monkeypatch.setattr("kams.shim.interceptor.tracing.tracer", lambda _name: object())
    interceptor = Interceptor("notes-mcp")

    interceptor._emit(_Span(), [
        _finding(FindingKind.INTEGRITY_DRIFT, "integrity.definition_drift"),
    ])

    labels = meter.instruments[sc.METRIC_INTEGRITY_DRIFT].records[0][1]
    assert labels["detector"] == "integrity.definition_drift"
    assert labels["baseline_state"] == "pinned"


def test_sep414_meta_preserves_baggage_and_unrelated_keys():
    params = {"_meta": {"tenant": "acme", "baggage": "region=west"}}
    injected = mcp.inject_trace_context(
        params,
        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
        baggage="region=west",
    )
    assert injected["_meta"]["tenant"] == "acme"
    assert injected["_meta"]["baggage"] == "region=west"
    assert injected["_meta"]["traceparent"].startswith("00-")


def test_published_mcp_span_names_have_no_custom_prefix():
    assert sc.span_name_for("tools/list") == "tools/list"
    assert sc.span_name_for("tools/call", "save_note") == "tools/call save_note"
