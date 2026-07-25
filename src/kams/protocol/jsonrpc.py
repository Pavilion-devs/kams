"""JSON-RPC 2.0 framing for MCP's line-delimited stdio transport.

Transparency is the load-bearing property of this module. The relay must be
byte-faithful: an agent must not be able to tell Kams is in the path.

That is why every message carries its ORIGINAL bytes alongside the parsed view.
We forward `raw` unless a detector has explicitly rewritten the message. If we
re-serialised every message we would silently change key order, unicode
escaping, and whitespace -- differences that are invisible in a diff of the
parsed objects but very visible to anything hashing or signing the wire format.

Parsing is therefore for OBSERVATION only. Forwarding uses the original bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MessageKind(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"
    # Anything we cannot classify. Relayed verbatim, never inspected.
    UNKNOWN = "unknown"


@dataclass
class Message:
    """A single JSON-RPC message on the wire.

    Attributes:
        raw: the exact bytes read from the transport, minus the line terminator.
            This is what gets forwarded unless `dirty` is True.
        payload: parsed view, or None if the line was not valid JSON.
        kind: classification used to decide which detectors apply.
        dirty: set by `rewrite()`. Only then do we re-serialise.
    """

    raw: bytes
    payload: dict[str, Any] | None
    kind: MessageKind
    dirty: bool = field(default=False, repr=False)

    # ---- classification helpers -------------------------------------------------

    @property
    def method(self) -> str | None:
        if self.payload is None:
            return None
        m = self.payload.get("method")
        return m if isinstance(m, str) else None

    @property
    def id(self) -> str | int | None:
        if self.payload is None:
            return None
        mid = self.payload.get("id")
        return mid if isinstance(mid, (str, int)) else None

    @property
    def params(self) -> dict[str, Any]:
        if self.payload is None:
            return {}
        p = self.payload.get("params")
        return p if isinstance(p, dict) else {}

    @property
    def result(self) -> Any:
        return None if self.payload is None else self.payload.get("result")

    @property
    def error(self) -> dict[str, Any] | None:
        if self.payload is None:
            return None
        e = self.payload.get("error")
        return e if isinstance(e, dict) else None

    # ---- mutation ---------------------------------------------------------------

    def rewrite(self, payload: dict[str, Any]) -> None:
        """Replace the payload and mark the message for re-serialisation.

        The ONLY way a message stops being byte-faithful. Detectors that merely
        observe must never call this -- the golden transparency tests assert
        that an unmodified session produces identical bytes end to end.
        """
        self.payload = payload
        self.dirty = True

    def to_bytes(self) -> bytes:
        """Bytes to forward. Original unless explicitly rewritten."""
        if not self.dirty or self.payload is None:
            return self.raw
        # separators: no spaces, matching what MCP implementations emit.
        return json.dumps(self.payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def classify(payload: dict[str, Any] | None) -> MessageKind:
    if payload is None:
        return MessageKind.UNKNOWN
    has_method = isinstance(payload.get("method"), str)
    has_id = "id" in payload
    if has_method and has_id:
        return MessageKind.REQUEST
    if has_method and not has_id:
        return MessageKind.NOTIFICATION
    if "error" in payload:
        return MessageKind.ERROR
    if "result" in payload:
        return MessageKind.RESPONSE
    return MessageKind.UNKNOWN


def parse(line: bytes) -> Message:
    """Parse one wire line. Never raises -- malformed input becomes UNKNOWN.

    A proxy that crashes on input it does not understand is a proxy that breaks
    the workload it was meant to observe (principle 1).
    """
    try:
        payload = json.loads(line)
        if not isinstance(payload, dict):
            # Valid JSON but not a JSON-RPC object (e.g. a batch array).
            # Out of scope for inspection; relayed untouched.
            return Message(raw=line, payload=None, kind=MessageKind.UNKNOWN)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return Message(raw=line, payload=None, kind=MessageKind.UNKNOWN)
    return Message(raw=line, payload=payload, kind=classify(payload))
