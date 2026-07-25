"""A deterministic MCP-ish server for transparency testing.

Deliberately exercises the wire shapes most likely to break a naive proxy:

  * non-ASCII text and emoji (unicode escaping differences)
  * keys in non-alphabetical order (re-serialisation reordering)
  * significant interior whitespace in strings
  * a large result payload (stream buffer limits)
  * an error response
  * a notification (no id)
  * a method the proxy has never heard of
  * a line that is valid JSON but not a JSON-RPC object

If Kams round-trips any of these through json.loads/json.dumps instead of
forwarding original bytes, the golden test catches it.
"""

from __future__ import annotations

import json
import sys

# Key order here is intentionally NOT alphabetical -- a proxy that re-serialises
# will silently sort these and fail the byte comparison.
TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from disk.  Returns its contents.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute path"}},
            "required": ["path"],
        },
    },
    {
        "name": "søk",  # non-ASCII tool name
        "description": "Søk i dokumenter — search documents ✨",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
    },
]


def respond(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def handle(payload):
    method = payload.get("method")
    mid = payload.get("id")

    if method == "initialize":
        return respond(
            mid,
            {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "mock-mcp", "version": "0.1.0"},
                "capabilities": {"tools": {}},
            },
        )

    if method == "tools/list":
        return respond(mid, {"tools": TOOLS})

    if method == "tools/call":
        params = payload.get("params") or {}
        name = params.get("name")
        if name == "big":
            # Comfortably past the default 64 KiB StreamReader limit.
            return respond(mid, {"content": [{"type": "text", "text": "x" * 200_000}]})
        if name == "boom":
            return {
                "jsonrpc": "2.0",
                "id": mid,
                "error": {"code": -32001, "message": "tool exploded", "data": {"detail": "on purpose"}},
            }
        return respond(mid, {"content": [{"type": "text", "text": f"called {name}"}]})

    if method == "notifications/initialized":
        return None  # notification: no response

    if mid is None:
        return None

    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown method {method}"}}


def main() -> None:
    for line in sys.stdin.buffer:
        stripped = line.rstrip(b"\r\n")
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue  # valid JSON, not JSON-RPC -- server ignores it

        out = handle(payload)
        if out is None:
            continue
        sys.stdout.buffer.write(json.dumps(out, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n")
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
