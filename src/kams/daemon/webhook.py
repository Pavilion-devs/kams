"""Receive SigNoz alert webhooks and turn them into enforcement.

This is the second half of the dual control loop (architecture.md §4), and the
half that justifies routing enforcement through an observability backend at all.

The shim sees one connection, right now. SigNoz sees every agent, every server,
over time. Conditions like "this server's error rate across the fleet exceeded
20% over five minutes" are **not expressible in the shim** -- it does not have
the data. So the reflex path handles what one connection can determine alone,
and this path handles what only the aggregate knows.

Both write to the same SharedState, so enforcement behaves identically no matter
which path decided it.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from kams.daemon.state import SharedState, StoredRestriction
from kams.telemetry import semconv as sc
from kams.telemetry import tracing

log = logging.getLogger("kams.webhook")

DEFAULT_PORT = 8787

# Quarantine length for an alert-driven containment. Bounded on purpose: a
# fleet-scale signal can be transient, and an unbounded block from a flapping
# alert is its own outage.
DEFAULT_TTL = 3600.0
_CONTROL_COUNTER = None


def _emit_quarantine(server: str, rule: str, reason: str, ttl: float) -> None:
    """Emit the SigNoz→Kams control action as a trace, metric, and OTLP log."""
    global _CONTROL_COUNTER
    tracer = tracing.tracer("kams.daemon.webhook")
    if _CONTROL_COUNTER is None:
        _CONTROL_COUNTER = tracing.meter("kams.daemon.webhook").create_counter(
            sc.METRIC_ENFORCEMENT,
            description="Policy enforcement actions taken",
        )
    with tracer.start_as_current_span(
        "kams.enforce quarantine_server",
        attributes={
            sc.KAMS_ENFORCE_ACTION: "quarantine_server",
            sc.KAMS_RULE_NAME: rule,
            sc.KAMS_SERVER_NAME: server,
            sc.KAMS_ENFORCE_ORIGIN: "signoz",
            sc.KAMS_ENFORCE_TTL: int(ttl),
        },
    ):
        _CONTROL_COUNTER.add(
            1,
            {
                "server": server,
                "action": "quarantine_server",
                "rule": rule,
                "origin": "signoz",
            },
        )
        log.warning(
            "quarantined %s via %s (ttl %ds): %s",
            server,
            rule,
            int(ttl),
            reason,
            extra={
                "kams.server.name": server,
                "kams.rule.name": rule,
                "kams.enforce.action": "quarantine_server",
                "kams.enforce.origin": "signoz",
            },
        )


def extract_server(payload: dict[str, Any]) -> str | None:
    """Find which MCP server an alert is about.

    SigNoz webhook payloads vary by alert shape, so look in the places the
    label can appear rather than assuming one schema. Returning None is fine --
    we refuse to guess, because quarantining the wrong server is worse than
    quarantining nothing.
    """
    candidates: list[dict] = []
    for key in ("alerts", "groupedAlerts"):
        items = payload.get(key)
        if isinstance(items, list):
            candidates.extend(i for i in items if isinstance(i, dict))
    candidates.append(payload)

    for item in candidates:
        for field in ("labels", "commonLabels", "annotations"):
            block = item.get(field)
            if isinstance(block, dict):
                for label in ("server", "mcp.server.name", "mcp_server_name"):
                    value = block.get(label)
                    if isinstance(value, str) and value:
                        return value
    return None


def extract_rule(payload: dict[str, Any]) -> str:
    for key in ("ruleName", "alertname", "name"):
        v = payload.get(key)
        if isinstance(v, str) and v:
            return f"signoz:{v}"
    labels = payload.get("commonLabels")
    if isinstance(labels, dict) and isinstance(labels.get("alertname"), str):
        return f"signoz:{labels['alertname']}"
    return "signoz:alert"


def is_firing(payload: dict[str, Any]) -> bool:
    """Resolved notifications must not install a quarantine."""
    status = payload.get("status")
    if isinstance(status, str):
        return status.lower() == "firing"
    alerts = payload.get("alerts")
    if isinstance(alerts, list) and alerts:
        first = alerts[0]
        if isinstance(first, dict) and isinstance(first.get("status"), str):
            return first["status"].lower() == "firing"
    # No status field: treat as firing. A missed containment is worse than an
    # over-eager, TTL-bounded one.
    return True


class _Handler(BaseHTTPRequestHandler):
    state: SharedState
    ttl: float
    enricher: Any = None

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.rstrip("/").endswith("/findings"):
            self._handle_finding()
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
            if not isinstance(payload, dict):
                payload = {}
        except json.JSONDecodeError:
            self._reply(400, {"error": "invalid json"})
            return

        if not is_firing(payload):
            server = extract_server(payload)
            lifted = self.state.lift(server) if server else 0
            log.info("alert resolved for %s, lifted %d restriction(s)", server, lifted)
            self._reply(200, {"status": "resolved", "server": server, "lifted": lifted})
            return

        server = extract_server(payload)
        if not server:
            # Refuse to guess. Quarantining the wrong server is worse than
            # quarantining nothing. Log the payload so the label path can be
            # fixed rather than guessed at -- alert schemas vary by version.
            log.warning(
                "alert carried no identifiable server label; ignoring. payload=%s",
                json.dumps(payload)[:1200],
            )
            self._reply(202, {"status": "ignored", "reason": "no server label"})
            return

        rule = extract_rule(payload)
        now = time.time()
        reason = _reason(payload)
        self.state.add(
            StoredRestriction(
                action="quarantine_server",
                server=server,
                tool=None,
                rule=rule,
                reason=reason,
                created_at=now,
                expires_at=now + self.ttl,
                origin="signoz",
            )
        )
        _emit_quarantine(server, rule, reason, self.ttl)
        self._reply(200, {"status": "quarantined", "server": server, "rule": rule})

    def _handle_finding(self) -> None:
        """Accept a finding from a shim for asynchronous enrichment.

        Always 202: the shim must not care whether enrichment succeeded, and
        must never wait on it.
        """
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        if self.enricher is None:
            self._reply(202, {"status": "ignored", "reason": "enrichment disabled"})
            return
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._reply(400, {"error": "invalid json"})
            return

        from kams.daemon.enrich import EnrichmentJob

        self.enricher.submit(
            EnrichmentJob(
                server=str(payload.get("server", "unknown")),
                tool=payload.get("tool"),
                detector=str(payload.get("detector", "unknown")),
                severity=str(payload.get("severity", "INFO")),
                summary=str(payload.get("summary", "")),
                evidence=payload.get("evidence") or {},
                trace_id=payload.get("trace_id"),
                span_id=payload.get("span_id"),
            )
        )
        self._reply(202, {"status": "queued"})

    def do_GET(self) -> None:  # noqa: N802
        self._reply(200, {
            "status": "ok",
            "restrictions": [
                {"server": r.server, "action": r.action, "rule": r.rule, "origin": r.origin}
                for r in self.state.active()
            ],
        })

    def _reply(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        log.debug("webhook %s", fmt % args)


def _reason(payload: dict[str, Any]) -> str:
    for key in ("description", "summary", "message"):
        v = payload.get(key)
        if isinstance(v, str) and v:
            return re.sub(r"\s+", " ", v)[:300]
    for item in payload.get("alerts") or []:
        if isinstance(item, dict):
            ann = item.get("annotations")
            if isinstance(ann, dict):
                for key in ("description", "summary"):
                    v = ann.get(key)
                    if isinstance(v, str) and v:
                        return re.sub(r"\s+", " ", v)[:300]
    return "SigNoz alert fired"


def serve(state: SharedState, *, port: int = DEFAULT_PORT, ttl: float = DEFAULT_TTL,
          enricher: Any = None) -> ThreadingHTTPServer:
    handler = type("KamsWebhookHandler", (_Handler,), {"state": state, "ttl": ttl, "enricher": enricher})
    server = ThreadingHTTPServer(("0.0.0.0", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True, name="kams-webhook").start()
    log.info("webhook listening on :%d", port)
    return server
