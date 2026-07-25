"""Streamable-HTTP transport: the reverse-proxy adapter.

Same detector pipeline as stdio, different I/O. The agent points at Kams instead
of the upstream MCP server; Kams forwards and observes.

Three things make HTTP harder than stdio, and each shapes the code below:

1. **Responses can be SSE.** A `tools/call` may come back as `application/json`
   or as `text/event-stream`. The stream must pass through *as it arrives* --
   buffering it to parse would destroy the streaming property the agent is
   relying on. So chunks are forwarded immediately and parsed opportunistically
   from a side buffer.

2. **Headers are load-bearing.** Auth, `Mcp-Session-Id`, and content negotiation
   all ride on them. Hop-by-hop headers must be dropped (they describe *our*
   connection, not the upstream's) and everything else passed through untouched.

3. **Transparency now includes status and headers**, not just the body. An agent
   can observe all three, so all three are preserved.

Blocking returns a JSON-RPC error with HTTP 200: at the JSON-RPC layer an error
is a normal response, and returning a 4xx would make a policy decision look like
a transport failure.
"""

from __future__ import annotations

import json
import logging
import uuid
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from kams.protocol import jsonrpc
from kams.transport.stdio import Disposition, Hook, HookResult

log = logging.getLogger("kams.transport.http")

# Headers that describe this hop rather than the payload. Forwarding them
# corrupts the proxied connection.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
})

SSE_MEDIA_TYPE = "text/event-stream"


def _forwardable(headers, *, drop_encoding: bool = False) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in _HOP_BY_HOP:
            continue
        # httpx decompresses transparently, so a stale content-encoding would
        # tell the client to decode already-decoded bytes.
        if drop_encoding and lk == "content-encoding":
            continue
        out[k] = v
    return out


async def _noop(_: Any) -> HookResult:
    return HookResult.forward()


class HttpRelay:
    """Reverse proxy for the MCP streamable-HTTP transport."""

    def __init__(
        self,
        upstream: str,
        *,
        on_client_message: Hook | None = None,
        on_server_message: Hook | None = None,
        path: str = "/mcp",
        timeout: float = 300.0,
    ) -> None:
        self.upstream = upstream.rstrip("/")
        self.on_client_message = on_client_message or _noop
        self.on_server_message = on_server_message or _noop
        self.path = path
        # Generous: an MCP tool call can legitimately take minutes, and a proxy
        # that times out earlier than the upstream invents failures.
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=10.0))

    def app(self) -> Starlette:
        # Starlette 1.x uses lifespan rather than on_shutdown.
        @asynccontextmanager
        async def lifespan(_app):
            yield
            await self.aclose()

        return Starlette(
            routes=[Route(self.path, self._handle, methods=["POST", "GET", "DELETE"])],
            lifespan=lifespan,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # ---- request handling ----------------------------------------------------

    async def _handle(self, request: Request) -> Response:
        body = await request.body()
        correlation = uuid.uuid4().hex
        transport_context = {"kams.correlation": correlation}
        if session_id := request.headers.get("Mcp-Session-Id"):
            transport_context["mcp.session.id"] = session_id

        if request.method == "POST" and body:
            msg = jsonrpc.parse(body)
            msg.context.update(transport_context)
            result = await self._safe(self.on_client_message, msg)
            if result.disposition is Disposition.BLOCK:
                # JSON-RPC error at HTTP 200: a policy decision is a protocol
                # response, not a transport failure.
                return JSONResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": msg.id,
                        "error": {
                            "code": result.error_code,
                            "message": result.error_message,
                            **({"data": result.error_data} if result.error_data else {}),
                        },
                    }
                )
            body = msg.to_bytes()

        try:
            upstream_req = self._client.build_request(
                request.method,
                self.upstream,
                content=body if body else None,
                headers=_forwardable(request.headers),
                params=dict(request.query_params),
            )
            upstream_resp = await self._client.send(upstream_req, stream=True)
        except httpx.RequestError as exc:
            # Relay the failure honestly rather than masking it as a Kams error.
            log.warning("upstream unreachable: %r", exc)
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32001, "message": f"upstream unreachable: {exc}"}},
                status_code=502,
            )

        content_type = upstream_resp.headers.get("content-type", "")
        headers = _forwardable(upstream_resp.headers, drop_encoding=True)
        if response_session := upstream_resp.headers.get("Mcp-Session-Id"):
            transport_context["mcp.session.id"] = response_session

        if SSE_MEDIA_TYPE in content_type:
            return StreamingResponse(
                self._stream_sse(upstream_resp, transport_context),
                status_code=upstream_resp.status_code,
                headers=headers,
                media_type=content_type,
            )

        payload = await upstream_resp.aread()
        await upstream_resp.aclose()
        if payload:
            msg = jsonrpc.parse(payload)
            msg.context.update(transport_context)
            await self._safe(self.on_server_message, msg)
            payload = msg.to_bytes()
        return Response(content=payload, status_code=upstream_resp.status_code, headers=headers)

    # ---- SSE ------------------------------------------------------------------

    async def _stream_sse(
        self,
        upstream_resp: httpx.Response,
        transport_context: dict[str, str] | None = None,
    ) -> AsyncIterator[bytes]:
        """Forward SSE chunks immediately; parse frames from a side buffer.

        Forwarding first is the point. Waiting for a complete frame before
        emitting would convert a streaming response into a buffered one, which
        an agent rendering tokens live would notice immediately.
        """
        transport_context = transport_context or {}
        buffer = b""
        try:
            async for chunk in upstream_resp.aiter_bytes():
                yield chunk

                buffer += chunk
                while b"\n\n" in buffer:
                    frame, buffer = buffer.split(b"\n\n", 1)
                    await self._observe_frame(frame, transport_context)
                # A frame that never terminates must not grow without bound.
                if len(buffer) > 8 * 1024 * 1024:
                    log.warning("oversized SSE frame, dropping observation buffer")
                    buffer = b""
        finally:
            await upstream_resp.aclose()

    async def _observe_frame(
        self,
        frame: bytes,
        transport_context: dict[str, str],
    ) -> None:
        """Extract JSON-RPC from an SSE frame's data lines, for observation only.

        Never rewrites: the bytes have already been sent. Detectors on this path
        observe and may install standing restrictions that affect *subsequent*
        calls, which is the same guarantee the stdio server->client path gives.
        """
        data_lines = [
            line[5:].lstrip() for line in frame.split(b"\n") if line.startswith(b"data:")
        ]
        if not data_lines:
            return
        payload = b"\n".join(data_lines)
        try:
            msg = jsonrpc.parse(payload)
            msg.context.update(transport_context)
            await self._safe(self.on_server_message, msg)
        except Exception as exc:  # noqa: BLE001 - observation must never break the stream
            log.debug("SSE frame observation failed: %r", exc)

    async def _safe(self, hook: Hook, msg) -> HookResult:
        try:
            return await hook(msg)
        except Exception as exc:  # noqa: BLE001 - principle 1
            log.warning("hook raised, treating as no-opinion: %r", exc)
            return HookResult.forward()


def serve(relay: HttpRelay, *, host: str = "127.0.0.1", port: int = 8900) -> None:
    import uvicorn

    uvicorn.run(relay.app(), host=host, port=port, log_level="warning")
