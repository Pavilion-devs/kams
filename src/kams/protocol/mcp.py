"""MCP-specific protocol knowledge: methods, tool shapes, and `_meta` handling.

Scope note: this module knows the *shape* of MCP messages. It does not judge
them. Judgement lives in `kams.detect`, which is pure and testable without a
transport. Keeping that line sharp is what lets the brain be exercised without
Docker, SigNoz, or a live server.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Any

# --- methods we attach specific meaning to -----------------------------------
# Anything not listed here is relayed verbatim with a generic span (principle 5).

INITIALIZE = "initialize"
TOOLS_LIST = "tools/list"
TOOLS_CALL = "tools/call"
RESOURCES_LIST = "resources/list"
RESOURCES_READ = "resources/read"
PROMPTS_LIST = "prompts/list"
PROMPTS_GET = "prompts/get"

INSPECTED_METHODS = frozenset(
    {INITIALIZE, TOOLS_LIST, TOOLS_CALL, RESOURCES_LIST, RESOURCES_READ, PROMPTS_LIST, PROMPTS_GET}
)

# W3C trace context key inside `params._meta`.
#
# MCP has no defined mechanism for propagating trace context -- there are no
# headers in stdio. The spec reserves `_meta` for out-of-band metadata, so we
# use it. This is a PROPOSAL, shipped alongside the semconv contribution rather
# than an existing standard, and is documented as such in architecture.md §5.
META_KEY = "_meta"
TRACEPARENT = "traceparent"
TRACESTATE = "tracestate"


# --- tool definitions --------------------------------------------------------


@dataclass(frozen=True)
class ToolDef:
    """A single tool as advertised by a server, in canonical form.

    `digest` covers exactly the triple that reaches the model's context or
    constrains its calls: name, description, and input schema. Server-side
    churn that cannot influence the model (ordering, formatting) is normalised
    away so the integrity detector does not cry wolf.
    """

    name: str
    description: str
    input_schema: dict[str, Any]

    @property
    def digest(self) -> str:
        return _digest(
            {
                "name": self.name,
                "description": _normalise_text(self.description),
                "inputSchema": _canonical(self.input_schema),
            }
        )

    @property
    def description_digest(self) -> str:
        """Isolated so drift classification can tell a description change --
        the actual poisoning vector -- from a schema change."""
        return _digest(_normalise_text(self.description))

    @property
    def schema_digest(self) -> str:
        return _digest(_canonical(self.input_schema))


def extract_tools(result: Any) -> list[ToolDef]:
    """Pull tool definitions out of a `tools/list` result.

    Tolerant by design: a malformed or unexpected shape yields no tools rather
    than an exception. A server that returns garbage is a finding for the
    behavioural detector, not a crash in the relay.
    """
    if not isinstance(result, dict):
        return []
    raw_tools = result.get("tools")
    if not isinstance(raw_tools, list):
        return []

    out: list[ToolDef] = []
    for t in raw_tools:
        if not isinstance(t, dict):
            continue
        name = t.get("name")
        if not isinstance(name, str):
            continue
        desc = t.get("description")
        schema = t.get("inputSchema")
        out.append(
            ToolDef(
                name=name,
                description=desc if isinstance(desc, str) else "",
                input_schema=schema if isinstance(schema, dict) else {},
            )
        )
    return out


def tool_call_name(params: dict[str, Any]) -> str | None:
    n = params.get("name")
    return n if isinstance(n, str) else None


def tool_call_arguments(params: dict[str, Any]) -> dict[str, Any]:
    a = params.get("arguments")
    return a if isinstance(a, dict) else {}


def extract_result_text(result: Any) -> list[str]:
    """Collect text blocks from a `tools/call` result.

    Needed because injection is not confined to tool descriptions: CyberArk's
    "Poison everywhere" research shows any server output can carry an injected
    payload. The integrity detector scans these the same way it scans
    descriptions.
    """
    if not isinstance(result, dict):
        return []
    content = result.get("content")
    if not isinstance(content, list):
        return []

    texts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            t = block.get("text")
            if isinstance(t, str):
                texts.append(t)
    return texts


# --- trace context in _meta ---------------------------------------------------


def inject_trace_context(params: dict[str, Any], traceparent: str, tracestate: str | None = None) -> dict[str, Any]:
    """Return a copy of `params` carrying W3C trace context in `_meta`.

    Copies rather than mutates: the caller owns whether the message becomes
    dirty, and an accidental in-place edit would silently break byte-fidelity.
    """
    new = dict(params)
    meta = dict(new.get(META_KEY) or {})
    meta[TRACEPARENT] = traceparent
    if tracestate:
        meta[TRACESTATE] = tracestate
    new[META_KEY] = meta
    return new


def extract_trace_context(params: dict[str, Any]) -> tuple[str | None, str | None]:
    meta = params.get(META_KEY)
    if not isinstance(meta, dict):
        return None, None
    tp = meta.get(TRACEPARENT)
    ts = meta.get(TRACESTATE)
    return (tp if isinstance(tp, str) else None, ts if isinstance(ts, str) else None)


def strip_trace_context(params: dict[str, Any]) -> dict[str, Any]:
    """Remove our keys before forwarding upstream.

    Instrumentation must not change what the server receives. If `_meta` becomes
    empty as a result, drop it entirely rather than forwarding `"_meta": {}`,
    which a strict server could reject and which is observably different from
    what the agent sent.
    """
    meta = params.get(META_KEY)
    if not isinstance(meta, dict):
        return params
    if TRACEPARENT not in meta and TRACESTATE not in meta:
        return params

    new = dict(params)
    cleaned = {k: v for k, v in meta.items() if k not in (TRACEPARENT, TRACESTATE)}
    if cleaned:
        new[META_KEY] = cleaned
    else:
        new.pop(META_KEY, None)
    return new


# --- canonicalisation ---------------------------------------------------------


def _normalise_text(s: str) -> str:
    """Normalise text for digesting.

    NFC only -- deliberately NOT stripping invisible characters. Zero-width and
    bidi codepoints are a real poisoning vector, so they must survive into the
    digest and be caught by the detector. Normalising them away here would hide
    exactly the attack we exist to find.
    """
    return unicodedata.normalize("NFC", s).strip()


def _canonical(obj: Any) -> Any:
    """Recursively sort mapping keys so formatting churn does not alter digests."""
    if isinstance(obj, dict):
        return {k: _canonical(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [_canonical(v) for v in obj]
    return obj


def _digest(obj: Any) -> str:
    data = obj if isinstance(obj, str) else json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]
