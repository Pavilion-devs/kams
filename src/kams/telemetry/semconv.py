"""Semantic convention constants.

Three tiers, and the distinction matters for the upstream contribution:

  GEN_AI_*  Settled. OpenTelemetry GenAI semantic conventions, as of the
            2026-07 state of open-telemetry/semantic-conventions-genai.
            We conform; we do not invent here.

  MCP_*     Unsettled. The GenAI semconv repo carries MCP model YAML but the
            docs are not yet published. These follow the conventions' naming
            grammar and are our PROPOSAL, shipped as semconv/mcp.yaml.

  KAMS_*    Ours. Kams-specific and namespaced as such, so nothing here can be
            mistaken for a standard attribute.

Keeping the tiers visibly separate is the honest thing to do and is what makes
the upstream PR reviewable: a reader can see exactly which claims we are making
about the standard and which are our own.
"""

from __future__ import annotations

from typing import Final

# --- GenAI: settled ----------------------------------------------------------

GEN_AI_OPERATION_NAME: Final = "gen_ai.operation.name"
GEN_AI_PROVIDER_NAME: Final = "gen_ai.provider.name"
GEN_AI_AGENT_NAME: Final = "gen_ai.agent.name"
GEN_AI_AGENT_ID: Final = "gen_ai.agent.id"
GEN_AI_CONVERSATION_ID: Final = "gen_ai.conversation.id"
GEN_AI_REQUEST_MODEL: Final = "gen_ai.request.model"
GEN_AI_RESPONSE_MODEL: Final = "gen_ai.response.model"
GEN_AI_RESPONSE_FINISH_REASONS: Final = "gen_ai.response.finish_reasons"
GEN_AI_USAGE_INPUT_TOKENS: Final = "gen_ai.usage.input_tokens"
GEN_AI_USAGE_OUTPUT_TOKENS: Final = "gen_ai.usage.output_tokens"
GEN_AI_TOOL_NAME: Final = "gen_ai.tool.name"
GEN_AI_TOOL_CALL_ID: Final = "gen_ai.tool.call.id"
GEN_AI_TOOL_TYPE: Final = "gen_ai.tool.type"

# Span-name prefixes defined by the conventions.
OP_INVOKE_AGENT: Final = "invoke_agent"
OP_EXECUTE_TOOL: Final = "execute_tool"
OP_CHAT: Final = "chat"

PROVIDER_AWS_BEDROCK: Final = "aws.bedrock"

# --- MCP: our proposal -------------------------------------------------------

MCP_METHOD_NAME: Final = "mcp.method.name"
MCP_SERVER_NAME: Final = "mcp.server.name"
MCP_TRANSPORT: Final = "mcp.transport"
MCP_SESSION_ID: Final = "mcp.session.id"
MCP_REQUEST_ID: Final = "mcp.request.id"
MCP_TOOL_NAME: Final = "mcp.tool.name"
MCP_TOOL_COUNT: Final = "mcp.tool.count"

# Payload sizing. Bytes are cheap and exact; token cost is the expensive,
# reconciled figure (architecture.md §3.4).
MCP_REQUEST_SIZE: Final = "mcp.request.size_bytes"
MCP_RESPONSE_SIZE: Final = "mcp.response.size_bytes"
MCP_CONTEXT_COST_TOKENS: Final = "mcp.context.cost.tokens"
MCP_CONTEXT_COST_ESTIMATED: Final = "mcp.context.cost.estimated"

MCP_ERROR_CODE: Final = "mcp.error.code"

# --- Kams: ours --------------------------------------------------------------

KAMS_FINDING_KIND: Final = "kams.finding.kind"
KAMS_FINDING_SEVERITY: Final = "kams.finding.severity"
KAMS_FINDING_DETECTOR: Final = "kams.finding.detector"
KAMS_FINDING_CONFIDENCE: Final = "kams.finding.confidence"
KAMS_FINDING_SUMMARY: Final = "kams.finding.summary"

KAMS_RULE_NAME: Final = "kams.rule.name"
KAMS_ENFORCE_ACTION: Final = "kams.enforce.action"
KAMS_ENFORCE_TTL: Final = "kams.enforce.ttl_seconds"

KAMS_INTEGRITY_CHANGE: Final = "kams.integrity.change"
KAMS_INTEGRITY_SCORE: Final = "kams.integrity.score"
KAMS_INTEGRITY_SIGNALS: Final = "kams.integrity.signals"
KAMS_BASELINE_STATE: Final = "kams.baseline.state"

KAMS_EGRESS_CLASSES: Final = "kams.egress.classes"
KAMS_EGRESS_COUNT: Final = "kams.egress.count"

# Marks a span whose parent context was unavailable because the agent does not
# propagate trace context over MCP. The gap is recorded rather than hidden --
# a silently-rooted span looks identical to a correctly-rooted one.
KAMS_TRACE_ORPHANED: Final = "kams.trace.orphaned"

# --- metrics -----------------------------------------------------------------

METRIC_OPERATION_DURATION: Final = "mcp.client.operation.duration"
METRIC_TOOL_CALLS: Final = "mcp.tool.call.count"
METRIC_TOOL_ERRORS: Final = "mcp.tool.error.count"
METRIC_CONTEXT_COST: Final = "mcp.context.cost.tokens"
METRIC_INTEGRITY_DRIFT: Final = "mcp.integrity.drift.count"
METRIC_EGRESS_CLASSIFIED: Final = "mcp.egress.classified.count"
METRIC_ENFORCEMENT: Final = "kams.enforcement.count"


def span_name_for(method: str, tool: str | None = None) -> str:
    """Span naming follows the conventions' `{operation} {target}` grammar."""
    if tool:
        return f"mcp.{method} {tool}"
    return f"mcp.{method}"
