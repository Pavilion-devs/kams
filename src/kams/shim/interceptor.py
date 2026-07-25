"""The shim's observation layer: turn relayed JSON-RPC into spans and metrics.

A span covers a request/response *pair*, so it must stay open across the gap.
That means holding started spans in a pending map keyed by JSON-RPC id and
ending them when the matching response arrives.

Two consequences worth stating, because both are easy to get wrong:

  * Responses can arrive out of order. Correlation is by id, never by arrival.
  * A response may never arrive (server dies, agent gives up). Unpaired spans
    are closed at shutdown and marked, rather than leaking or vanishing.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode

from kams.protocol import mcp
from kams.protocol.jsonrpc import Message, MessageKind
from kams.telemetry import semconv as sc
from kams.telemetry import tracing
from kams.transport.stdio import HookResult

log = logging.getLogger("kams.shim")


@dataclass
class _Pending:
    span: Any
    method: str
    tool: str | None
    started: float
    request_bytes: int
    session_id: str
    arguments: Any = None
    # Detector output attached on the request side, applied when the span closes.
    extra: dict[str, Any] = field(default_factory=dict)


class Interceptor:
    """Observes a single agent<->server connection.

    Detection is injected rather than built in: `detectors` is a list of
    callables that take an event and return findings. That keeps this class
    about plumbing and keeps the brain in `kams.detect`, where it is pure and
    testable without a transport.
    """

    def __init__(
        self,
        server_name: str,
        *,
        session_id: str | None = None,
        integrity: Any | None = None,
        policy: Any | None = None,
        egress: Any | None = None,
        cost: Any | None = None,
        behavioural: Any | None = None,
        forwarder: Any | None = None,
        transport: str = "stdio",
    ) -> None:
        self.server_name = server_name
        self.session_id = session_id or uuid.uuid4().hex[:16]
        self.integrity = integrity
        self.policy = policy
        self.egress = egress
        self.cost = cost
        self.behavioural = behavioural
        self.forwarder = forwarder
        # Set by whichever adapter constructed us. Hardcoding this meant
        # HTTP traffic was reported as stdio, which is worse than omitting
        # the attribute entirely.
        self.transport = transport
        self.protocol_version: str | None = None
        self._tracer = tracing.tracer("kams.shim")
        self._pending: dict[tuple[str, str | int | None], _Pending] = {}

        m = tracing.meter("kams.shim")
        self._h_duration = m.create_histogram(
            sc.METRIC_OPERATION_DURATION, unit="s", description="MCP operation duration"
        )
        self._c_calls = m.create_counter(sc.METRIC_TOOL_CALLS, description="MCP tool calls")
        self._c_errors = m.create_counter(sc.METRIC_TOOL_ERRORS, description="MCP tool errors")
        self._c_drift = m.create_counter(
            sc.METRIC_INTEGRITY_DRIFT, description="Pinned MCP tool-definition drift findings"
        )
        self._c_findings = m.create_counter(
            sc.METRIC_FINDINGS, description="All Kams detector findings"
        )
        self._c_enforce = m.create_counter(
            sc.METRIC_ENFORCEMENT, description="Policy enforcement actions taken"
        )
        self._c_egress = m.create_counter(
            sc.METRIC_EGRESS_CLASSIFIED, description="Sensitive values crossing into a third-party server"
        )
        self._h_cost = m.create_histogram(
            sc.METRIC_CONTEXT_COST, unit="{token}",
            description="Model-context tokens consumed by MCP results, by server",
        )

    @staticmethod
    def _message_key(msg: Message) -> tuple[str, str | int | None]:
        return str(msg.context.get("kams.correlation", "")), msg.id

    def _session_for(self, msg: Message) -> str:
        return str(msg.context.get("mcp.session.id") or self.session_id)

    def _emit_enforcement(
        self,
        restriction,
        method: str,
        tool: str | None,
        *,
        parent_span=None,
        session_id: str | None = None,
    ) -> None:
        """A standalone span for the containment itself.

        Separate from the blocked call's span so enforcement is visible in
        SigNoz as an event in its own right — "what did Kams do, and under which
        rule" is a different question from "what did the agent try".
        """
        try:
            parent_context = (
                trace.set_span_in_context(parent_span) if parent_span is not None else None
            )
            with self._tracer.start_as_current_span(
                f"kams.enforce {restriction.action.value}",
                context=parent_context,
                kind=SpanKind.INTERNAL,
                attributes={
                    sc.KAMS_ENFORCE_ACTION: restriction.action.value,
                    sc.KAMS_RULE_NAME: restriction.rule,
                    sc.KAMS_SERVER_NAME: restriction.server,
                    sc.MCP_METHOD_NAME: method,
                    sc.MCP_SESSION_ID: session_id or self.session_id,
                    sc.KAMS_ENFORCE_ORIGIN: getattr(restriction, "origin", "reflex"),
                    **({sc.GEN_AI_TOOL_NAME: tool} if tool else {}),
                    **({sc.KAMS_ENFORCE_TTL: int(restriction.expires_at - restriction.created_at)}
                       if restriction.expires_at else {}),
                },
            ) as span:
                span.set_status(Status(StatusCode.ERROR, restriction.reason[:200] or "blocked by policy"))
            self._c_enforce.add(
                1,
                {
                    "server": restriction.server,
                    "action": restriction.action.value,
                    "rule": restriction.rule,
                    "origin": getattr(restriction, "origin", "reflex"),
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("failed to emit enforcement span: %r", exc)

    def _decide(
        self,
        span,
        findings: list,
        *,
        method: str,
        tool: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Run findings through policy and install any standing restrictions."""
        if self.policy is None or not findings:
            return
        try:
            with trace.use_span(span, end_on_exit=False):
                decisions = self.policy.evaluate(findings)
                for restriction in self.policy.apply(decisions):
                    span.add_event(
                        "kams.enforcement",
                        attributes={
                            sc.KAMS_ENFORCE_ACTION: restriction.action.value,
                            sc.KAMS_RULE_NAME: restriction.rule,
                            sc.KAMS_SERVER_NAME: restriction.server,
                        },
                    )
                    self._emit_enforcement(
                        restriction,
                        method,
                        tool,
                        parent_span=span,
                        session_id=session_id,
                    )
        except Exception as exc:  # noqa: BLE001 - policy must never break the relay
            log.warning("policy evaluation failed, allowing: %r", exc)

    def _emit(self, span, findings: list) -> None:
        """Attach findings to the span as events and count them.

        Events rather than attributes: a single `tools/list` can produce several
        findings, and attributes cannot repeat a key. Detector failure is caught
        here so a bad regex can never take down the relay (principle 1).
        """
        for f in findings:
            try:
                span.add_event(f"kams.finding.{f.kind.value.lower()}", attributes=f.to_attributes())
                labels = {
                    "server": f.server,
                    "kind": f.kind.value,
                    "severity": f.severity.name,
                    "detector": f.detector,
                    "baseline_state": str(f.evidence.get("baseline_state", "n/a")),
                    **({"tool": f.tool} if f.tool else {}),
                }
                self._c_findings.add(1, labels)
                if (
                    f.kind.value == "INTEGRITY_DRIFT"
                    and f.detector == "integrity.definition_drift"
                ):
                    self._c_drift.add(1, labels)
                if f.kind.value == "EGRESS_SENSITIVE":
                    for cls in f.evidence.get("classes") or []:
                        self._c_egress.add(1, {"server": f.server, "class": cls,
                                               **({"tool": f.tool} if f.tool else {})})
                # Hand integrity findings to kamsd for LLM enrichment. Fire
                # and forget: the judge must never be in the request path.
                if self.forwarder is not None and f.kind.value.startswith("INTEGRITY"):
                    ctx = span.get_span_context()
                    self.forwarder.submit(
                        f,
                        trace_id=format(ctx.trace_id, "032x") if ctx.is_valid else None,
                        span_id=format(ctx.span_id, "016x") if ctx.is_valid else None,
                    )
                with trace.use_span(span, end_on_exit=False):
                    log.warning(
                        "[%s] %s: %s",
                        f.severity.name,
                        f.detector,
                        f.summary,
                        extra={
                            "kams.finding.kind": f.kind.value,
                            "kams.finding.severity": f.severity.name,
                            "kams.finding.detector": f.detector,
                            "kams.server.name": f.server,
                            "gen_ai.tool.name": f.tool or "",
                        },
                    )
            except Exception as exc:  # noqa: BLE001
                log.debug("failed to emit finding: %r", exc)

    # ---- client -> server ---------------------------------------------------

    async def on_client_message(self, msg: Message) -> HookResult:
        if msg.kind is not MessageKind.REQUEST:
            # Notifications and anything unclassifiable pass through untouched.
            return HookResult.forward()

        method = msg.method or "unknown"
        params = msg.params
        tool = mcp.tool_call_name(params) if method == mcp.TOOLS_CALL else None
        session_id = self._session_for(msg)

        traceparent, tracestate, baggage = mcp.extract_trace_context(params)
        parent_ctx = tracing.context_from_traceparent(traceparent, tracestate, baggage)

        protocol_version = self.protocol_version
        if method == mcp.INITIALIZE:
            requested = params.get("protocolVersion")
            if isinstance(requested, str):
                protocol_version = requested

        span = self._tracer.start_span(
            sc.span_name_for(method, tool),
            context=parent_ctx,
            kind=SpanKind.CLIENT,
            attributes={
                sc.MCP_METHOD_NAME: method,
                sc.KAMS_SERVER_NAME: self.server_name,
                sc.MCP_SESSION_ID: session_id,
                sc.NETWORK_TRANSPORT: "pipe" if self.transport == "stdio" else "tcp",
                sc.JSONRPC_REQUEST_ID: str(msg.id),
                sc.MCP_REQUEST_SIZE: len(msg.raw),
                sc.KAMS_TRACE_PROPAGATED: parent_ctx is not None,
                sc.KAMS_TRACE_ORPHANED: parent_ctx is None,
                **({sc.MCP_PROTOCOL_VERSION: protocol_version} if protocol_version else {}),
                **({sc.GEN_AI_TOOL_NAME: tool} if tool else {}),
                **(
                    {sc.GEN_AI_OPERATION_NAME: sc.OP_EXECUTE_TOOL}
                    if method == mcp.TOOLS_CALL
                    else {}
                ),
            },
        )

        # Check before forwarding, but inside the request span so containment is
        # represented as a connected child operation.
        if self.policy is not None and method == mcp.TOOLS_CALL:
            verdict = self.policy.check(self.server_name, tool)
            if not verdict.allowed:
                span.set_status(Status(StatusCode.ERROR, verdict.message[:200]))
                self._emit_enforcement(
                    verdict.restriction,
                    method,
                    tool,
                    parent_span=span,
                    session_id=session_id,
                )
                span.end()
                return HookResult.block(
                    verdict.message,
                    data={
                        "kams": {
                            "action": verdict.restriction.action.value,
                            "rule": verdict.restriction.rule,
                            "server": self.server_name,
                        }
                    },
                )

        key = self._message_key(msg)
        self._pending[key] = _Pending(
            span=span,
            method=method,
            tool=tool,
            started=time.perf_counter(),
            request_bytes=len(msg.raw),
            session_id=session_id,
            # Kept so the behavioural detector can pair the call with its
            # result -- identical call plus identical result is the loop
            # signature, and it cannot be seen from either half alone.
            arguments=mcp.tool_call_arguments(params) if method == mcp.TOOLS_CALL else None,
        )

        # Egress runs on the way out, while the data can still be stopped.
        # Findings may install a redact or block restriction, so it happens
        # before the message is forwarded.
        redacted_args: dict[str, Any] | None = None
        if self.egress is not None and method == mcp.TOOLS_CALL and tool:
            arguments = mcp.tool_call_arguments(params)
            if arguments:
                findings = self.egress.on_tool_call(self.server_name, tool, arguments)
                if findings:
                    self._emit(span, findings)
                    self._decide(
                        span,
                        findings,
                        method=method,
                        tool=tool,
                        session_id=session_id,
                    )
                    # Re-check: a finding may have just blocked this very call.
                    if self.policy is not None:
                        verdict = self.policy.check(self.server_name, tool)
                        if not verdict.allowed:
                            span.set_status(Status(StatusCode.ERROR, "blocked on egress"))
                            self._pending.pop(key, None)
                            self._emit_enforcement(
                                verdict.restriction,
                                method,
                                tool,
                                parent_span=span,
                                session_id=session_id,
                            )
                            span.end()
                            return HookResult.block(verdict.message)
                        redacted_args = self._maybe_redact(span, arguments, tool)

        # SEP-414 propagates Kams' CLIENT span to the upstream through
        # params._meta. Existing baggage and unrelated _meta keys survive.
        outbound_context = trace.set_span_in_context(span, parent_ctx)
        out_tp, out_ts, out_baggage = tracing.traceparent_from_current(outbound_context)
        needs_rewrite = out_tp is not None or redacted_args is not None
        if needs_rewrite:
            new_params = (
                mcp.inject_trace_context(params, out_tp, out_ts, out_baggage)
                if out_tp
                else dict(params)
            )
            if redacted_args is not None:
                new_params = dict(new_params)
                new_params["arguments"] = redacted_args
            if new_params is not params:
                payload = dict(msg.payload or {})
                payload["params"] = new_params
                msg.rewrite(payload)

        return HookResult.forward()

    def _maybe_redact(self, span, arguments: dict[str, Any], tool: str) -> dict[str, Any] | None:
        """Apply a standing redact_args restriction, if one is in force."""
        if self.policy is None or self.egress is None:
            return None
        try:
            from kams.detect.egress import redact
            from kams.policy.model import Action

            for r in self.policy.restrictions:
                if r.action is Action.REDACT_ARGS and r.server == self.server_name:
                    cleaned, count = redact(arguments, self.egress)
                    if count:
                        span.add_event(
                            "kams.redacted",
                            attributes={sc.KAMS_EGRESS_COUNT: count, sc.KAMS_RULE_NAME: r.rule},
                        )
                        log.warning("redacted %d value(s) in %s arguments [%s]", count, tool, r.rule)
                        return cleaned
                    return None
        except Exception as exc:  # noqa: BLE001 - redaction must never break the call
            log.warning("redaction failed, forwarding unmodified: %r", exc)
        return None

    # ---- server -> client ---------------------------------------------------

    async def on_server_message(self, msg: Message) -> HookResult:
        if msg.kind not in (MessageKind.RESPONSE, MessageKind.ERROR):
            return HookResult.forward()

        pending = self._pending.pop(self._message_key(msg), None)
        if pending is None:
            # A response we never saw the request for. Real (agent sent it
            # before we attached) and not worth synthesising a span for.
            return HookResult.forward()

        elapsed = time.perf_counter() - pending.started
        span = pending.span
        labels = {"server": self.server_name, "method": pending.method}
        if pending.tool:
            labels["tool"] = pending.tool

        try:
            span.set_attribute(sc.MCP_RESPONSE_SIZE, len(msg.raw))

            if err := msg.error:
                code = err.get("code")
                span.set_attribute(sc.RPC_RESPONSE_STATUS_CODE, code if isinstance(code, int) else -1)
                span.set_attribute(sc.ERROR_TYPE, str(code) if code is not None else "jsonrpc.error")
                span.set_status(Status(StatusCode.ERROR, str(err.get("message", "error"))[:200]))
                self._c_errors.add(1, labels)
            else:
                # OTel represents a successful client span with UNSET status.
                if pending.method == mcp.INITIALIZE and isinstance(msg.result, dict):
                    version = msg.result.get("protocolVersion")
                    if isinstance(version, str):
                        self.protocol_version = version
                        span.set_attribute(sc.MCP_PROTOCOL_VERSION, version)

                elif pending.method == mcp.TOOLS_LIST:
                    tools = mcp.extract_tools(msg.result)
                    span.set_attribute(sc.MCP_TOOL_COUNT, len(tools))
                    if self.integrity is not None:
                        baseline = self.integrity.store.get(self.server_name)
                        findings = self.integrity.on_tools_list(self.server_name, tools)
                        self._emit(span, findings)
                        self._decide(
                            span,
                            findings,
                            method=pending.method,
                            tool=pending.tool,
                            session_id=pending.session_id,
                        )
                        # Persist now, not at shutdown. A long-running proxy
                        # would otherwise hold a learned baseline in memory
                        # indefinitely and lose it on a crash.
                        self._persist_baseline()
                        span.set_attribute(
                            sc.KAMS_BASELINE_STATE,
                            baseline.state if baseline else "first_sighting",
                        )

                elif pending.method == mcp.TOOLS_CALL and pending.tool:
                    # Context cost: what this result will consume of the model's
                    # window, attributed to the server that produced it.
                    if self.cost is not None:
                        attribution = self.cost.estimate(self.server_name, pending.tool, len(msg.raw))
                        self.cost.record(pending.session_id, attribution)
                        span.set_attribute(sc.MCP_CONTEXT_COST_TOKENS, attribution.tokens)
                        # Never publish an estimate as though it were measured.
                        span.set_attribute(sc.MCP_CONTEXT_COST_ESTIMATED, attribution.estimated)
                        self._h_cost.record(
                            attribution.tokens,
                            {**labels, "estimated": str(attribution.estimated).lower()},
                        )
                        spike = self.cost.check_spike(attribution)
                        if spike:
                            self._emit(span, spike)
                            self._decide(
                                span,
                                spike,
                                method=pending.method,
                                tool=pending.tool,
                                session_id=pending.session_id,
                            )

                if pending.method == mcp.TOOLS_CALL and self.integrity is not None and pending.tool:
                    # Descriptions are not the only injection surface -- any
                    # server output reaches the model's context.
                    texts = mcp.extract_result_text(msg.result)
                    if texts:
                        findings = self.integrity.on_result_text(self.server_name, pending.tool, texts)
                        self._emit(span, findings)
                        self._decide(
                            span,
                            findings,
                            method=pending.method,
                            tool=pending.tool,
                            session_id=pending.session_id,
                        )

            if pending.method == mcp.TOOLS_CALL:
                self._c_calls.add(1, labels)

            for k, v in pending.extra.items():
                span.set_attribute(k, v)

            self._h_duration.record(elapsed, labels)

            if self.behavioural is not None and pending.method == mcp.TOOLS_CALL and pending.tool:
                behaviour = self.behavioural.record(
                    self.server_name,
                    pending.tool,
                    arguments=pending.arguments,
                    result=msg.result,
                    is_error=msg.error is not None,
                    duration=elapsed,
                )
                if behaviour:
                    self._emit(span, behaviour)
                    self._decide(
                        span,
                        behaviour,
                        method=pending.method,
                        tool=pending.tool,
                        session_id=pending.session_id,
                    )
        finally:
            span.end()

        return HookResult.forward()

    # ---- lifecycle ----------------------------------------------------------

    def _persist_baseline(self) -> None:
        store = getattr(self.integrity, "store", None)
        if store is None:
            return
        try:
            store.save()
        except OSError as exc:
            log.debug("could not persist baseline: %r", exc)

    def close(self) -> None:
        if self.forwarder is not None:
            self.forwarder.stop()

        """Close spans whose responses never arrived.

        Leaving them open means they are never exported and the calls vanish
        from the trace -- the opposite of what an observability tool should do
        when something goes wrong.
        """
        for mid, pending in list(self._pending.items()):
            pending.span.set_status(Status(StatusCode.ERROR, "no response received"))
            pending.span.set_attribute("kams.response.missing", True)
            pending.span.end()
            log.debug("closed unpaired span for request id=%s", mid)
        self._pending.clear()
