"""HTTP transport transparency.

Same guarantee as stdio, with a wider surface: an HTTP client can observe the
status code and headers as well as the body, so all three are preserved.

The SSE cases matter most. A proxy that buffers a stream to inspect it turns a
streaming response into a batched one — invisible in a body comparison, obvious
to an agent rendering tokens live. `test_sse_frames_arrive_incrementally` is the
test that would catch that.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

from kams.transport.http import HttpRelay
from kams.transport.stdio import HookResult

# Key order is deliberately not alphabetical: a proxy that re-serialises sorts
# it, and the byte comparison catches that.
TOOLS_PAYLOAD = (
    b'{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read_file",'
    b'"description":"Read a file. Caf\xc3\xa9 \xe2\x9c\xa8","inputSchema":{"type":"object"}}]}}'
)


# --- a fake upstream MCP server over HTTP ------------------------------------


async def _upstream_endpoint(request):
    body = await request.body()
    # Tolerant like a real server: a body we cannot parse is not our problem to
    # reject here, and being strict would make this fixture — not Kams — the
    # thing under test.
    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        payload = {}
    method = payload.get("method")
    mid = payload.get("id")

    if method == "tools/list":
        return Response(
            content=TOOLS_PAYLOAD,
            media_type="application/json",
            headers={"Mcp-Session-Id": "sess-123", "X-Upstream-Marker": "present"},
        )

    if method == "stream":
        async def frames():
            for i in range(3):
                chunk = json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"chunk": i}})
                yield f"event: message\ndata: {chunk}\n\n".encode()
                await asyncio.sleep(0.05)

        return StreamingResponse(frames(), media_type="text/event-stream",
                                 headers={"Mcp-Session-Id": "sess-123"})

    if method == "boom":
        return Response(
            content=json.dumps({"jsonrpc": "2.0", "id": mid,
                                "error": {"code": -32001, "message": "nope", "data": {"why": "test"}}}),
            media_type="application/json",
        )

    if method == "teapot":
        return Response(content=b'{"weird":true}', status_code=418, media_type="application/json")

    return Response(
        content=json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"ok": True}}),
        media_type="application/json",
    )


upstream_app = Starlette(routes=[Route("/mcp", _upstream_endpoint, methods=["POST", "GET", "DELETE"])])


@pytest.fixture
def upstream_client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream_app),
                             base_url="http://upstream")


@pytest.fixture
def relay(upstream_client):
    r = HttpRelay("http://upstream/mcp")
    # Route the relay's outbound calls at the in-process upstream.
    r._client = upstream_client
    return r


@pytest.fixture
def proxied(relay):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=relay.app()),
                             base_url="http://proxy")


async def _post(client, url, payload):
    return await client.post(url, json=payload)


@pytest.mark.asyncio
class TestTransparency:
    async def test_body_is_byte_identical(self, upstream_client, proxied):
        req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        direct = await _post(upstream_client, "http://upstream/mcp", req)
        through = await _post(proxied, "http://proxy/mcp", req)
        assert through.content == direct.content
        assert through.content == TOOLS_PAYLOAD

    async def test_status_code_preserved(self, upstream_client, proxied):
        req = {"jsonrpc": "2.0", "id": 9, "method": "teapot"}
        direct = await _post(upstream_client, "http://upstream/mcp", req)
        through = await _post(proxied, "http://proxy/mcp", req)
        assert through.status_code == direct.status_code == 418

    async def test_upstream_headers_pass_through(self, proxied):
        """Mcp-Session-Id is load-bearing: losing it breaks the session."""
        r = await _post(proxied, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert r.headers["mcp-session-id"] == "sess-123"
        assert r.headers["x-upstream-marker"] == "present"

    async def test_hop_by_hop_headers_are_dropped(self, proxied):
        r = await _post(proxied, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert "transfer-encoding" not in {k.lower() for k in r.headers}

    async def test_error_with_data_relayed(self, proxied):
        r = await _post(proxied, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 4, "method": "boom"})
        body = r.json()
        assert body["error"]["code"] == -32001
        assert body["error"]["data"] == {"why": "test"}

    async def test_unknown_method_relayed(self, proxied):
        r = await _post(proxied, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 7, "method": "experimental/x"})
        assert r.json()["result"] == {"ok": True}

    async def test_concurrent_clients_with_same_jsonrpc_id_do_not_cross_wire(self):
        """HTTP request correlation is connection-safe, not keyed by id alone."""
        async def echo(request):
            payload = await request.json()
            marker = payload["params"]["marker"]
            if marker == "slow":
                await asyncio.sleep(0.05)
            return Response(
                content=json.dumps({
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {"marker": marker},
                }),
                media_type="application/json",
            )

        client_markers: dict[str, str] = {}
        observed: list[tuple[str, str]] = []

        async def on_client(msg):
            client_markers[msg.context["kams.correlation"]] = msg.params["marker"]
            return HookResult.forward()

        async def on_server(msg):
            correlation = msg.context["kams.correlation"]
            observed.append((client_markers[correlation], msg.result["marker"]))
            return HookResult.forward()

        echo_app = Starlette(routes=[Route("/mcp", echo, methods=["POST"])])
        r = HttpRelay(
            "http://upstream/mcp",
            on_client_message=on_client,
            on_server_message=on_server,
        )
        r._client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=echo_app),
            base_url="http://upstream",
        )
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=r.app()),
            base_url="http://proxy",
        )
        slow, fast = await asyncio.gather(
            _post(client, "http://proxy/mcp", {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"marker": "slow"},
            }),
            _post(client, "http://proxy/mcp", {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"marker": "fast"},
            }),
        )
        await client.aclose()

        assert slow.json()["result"]["marker"] == "slow"
        assert fast.json()["result"]["marker"] == "fast"
        assert sorted(observed) == [("fast", "fast"), ("slow", "slow")]


@pytest.mark.asyncio
class TestSSE:
    async def test_sse_body_identical(self, upstream_client, proxied):
        req = {"jsonrpc": "2.0", "id": 5, "method": "stream"}
        direct = await _post(upstream_client, "http://upstream/mcp", req)
        through = await _post(proxied, "http://proxy/mcp", req)
        assert through.content == direct.content
        assert through.content.count(b"data:") == 3

    async def test_sse_content_type_preserved(self, proxied):
        r = await _post(proxied, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 5, "method": "stream"})
        assert "text/event-stream" in r.headers["content-type"]

    async def test_sse_frames_arrive_incrementally(self, relay):
        """The stream must stay a stream.

        Exercised against the generator directly rather than through the app:
        `httpx.ASGITransport` buffers the whole response, so an end-to-end
        assertion here would pass whether or not the relay streams. Driving
        `_stream_sse` lets us record the true interleaving.

        A proxy that buffered to inspect would emit nothing until the upstream
        was exhausted, giving the order [p0,p1,p2,r0,r1,r2].
        """
        order: list[str] = []

        class FakeUpstream:
            async def aiter_bytes(self):
                for i in range(3):
                    order.append(f"produced-{i}")
                    yield f"event: message\ndata: {{\"id\":{i}}}\n\n".encode()
                    await asyncio.sleep(0)

            async def aclose(self):
                return None

        async for _ in relay._stream_sse(FakeUpstream()):
            order.append(f"relayed-{len(order)}")

        # Each relayed chunk must appear before the next is produced.
        first_relay = next(i for i, e in enumerate(order) if e.startswith("relayed"))
        last_produce = max(i for i, e in enumerate(order) if e.startswith("produced"))
        assert first_relay < last_produce, f"SSE was buffered, not streamed: {order}"

    async def test_sse_frames_are_observed(self, upstream_client):
        """Observation happens without altering the stream."""
        seen: list = []

        async def observe(msg):
            if msg.payload:
                seen.append(msg.payload)
            return HookResult.forward()

        r = HttpRelay("http://upstream/mcp", on_server_message=observe)
        r._client = upstream_client
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=r.app()), base_url="http://proxy")
        await _post(client, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 5, "method": "stream"})
        await client.aclose()
        assert len(seen) == 3
        assert [p["result"]["chunk"] for p in seen] == [0, 1, 2]


@pytest.mark.asyncio
class TestEnforcement:
    async def test_block_returns_jsonrpc_error_at_http_200(self, upstream_client):
        """A policy decision is a protocol response, not a transport failure."""
        async def block(_msg):
            return HookResult.block("quarantined by test", data={"kams": {"rule": "t"}})

        r = HttpRelay("http://upstream/mcp", on_client_message=block)
        r._client = upstream_client
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=r.app()), base_url="http://proxy")
        resp = await _post(client, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 3, "method": "tools/call"})
        await client.aclose()

        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == 3
        assert body["error"]["message"] == "quarantined by test"
        assert body["error"]["data"]["kams"]["rule"] == "t"

    async def test_blocked_request_never_reaches_upstream(self, upstream_client):
        reached = []

        async def block(_msg):
            return HookResult.block("no")

        async def spy(request):
            reached.append(1)
            return Response(content=b"{}", media_type="application/json")

        spy_app = Starlette(routes=[Route("/mcp", spy, methods=["POST"])])
        r = HttpRelay("http://upstream/mcp", on_client_message=block)
        r._client = httpx.AsyncClient(transport=httpx.ASGITransport(app=spy_app),
                                      base_url="http://upstream")
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=r.app()), base_url="http://proxy")
        await _post(client, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call"})
        await client.aclose()
        assert reached == []


@pytest.mark.asyncio
class TestResilience:
    async def test_hook_exception_does_not_break_the_call(self, upstream_client):
        """Principle 1: a detector that throws must not take the request down."""
        async def exploding(_msg):
            raise RuntimeError("boom")

        r = HttpRelay("http://upstream/mcp", on_client_message=exploding, on_server_message=exploding)
        r._client = upstream_client
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=r.app()), base_url="http://proxy")
        resp = await _post(client, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        await client.aclose()
        assert resp.status_code == 200
        assert resp.content == TOOLS_PAYLOAD

    async def test_unreachable_upstream_is_reported_honestly(self):
        r = HttpRelay("http://127.0.0.1:1/mcp")
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=r.app()), base_url="http://proxy")
        resp = await _post(client, "http://proxy/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        await client.aclose()
        await r.aclose()
        assert resp.status_code == 502
        assert "unreachable" in resp.json()["error"]["message"]

    async def test_non_json_body_is_relayed_not_rejected(self, upstream_client):
        """Anything unparseable passes through rather than 400ing."""
        r = HttpRelay("http://upstream/mcp")
        r._client = upstream_client
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=r.app()), base_url="http://proxy")
        resp = await client.post("http://proxy/mcp", content=b"not json at all",
                                 headers={"content-type": "application/json"})
        await client.aclose()
        assert resp.status_code == 200
