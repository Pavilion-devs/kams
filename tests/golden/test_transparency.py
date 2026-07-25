"""The load-bearing guarantee: an agent cannot tell Kams is in the path.

Runs an identical transcript twice -- once straight against the mock MCP server,
once through `kams shim` -- and asserts the two stdout byte streams are equal.

If this fails, nothing else about Kams matters. Every detector, dashboard, and
policy rule is built on the assumption that interception is invisible.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
MOCK = REPO / "tests" / "fixtures" / "mock_mcp_server.py"

# Each entry is one raw line written to the server's stdin, byte for byte.
# Several are deliberately hostile to a proxy that re-serialises.
TRANSCRIPT: list[bytes] = [
    # Key order not alphabetical; a re-serialising proxy would sort it.
    b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"version":"1.0","name":"golden"}}}',
    # Notification: no id, no response expected.
    b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
    # Tool listing: non-ASCII names and descriptions come back.
    b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
    # Interior whitespace and unicode in arguments.
    b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/a  b/\\u00e9.txt"}}}',
    # Error path must relay faithfully, including `data`.
    b'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"boom","arguments":{}}}',
    # Large payload: past the default 64 KiB stream limit.
    b'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"big","arguments":{}}}',
    # Method the proxy has never heard of -- must pass through untouched.
    b'{"jsonrpc":"2.0","id":6,"method":"experimental/telepathy","params":{"intensity":11}}',
    # Valid JSON, not a JSON-RPC object. Must not crash the relay.
    b'["not","an","object"]',
    # Emoji and combining characters survive the round trip.
    b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"s\\u00f8k","arguments":{"q":"caf\\u00e9 \\u2728"}}}',
]

STDIN_BLOB = b"\n".join(TRANSCRIPT) + b"\n"


def _run(cmd: list[str]) -> bytes:
    proc = subprocess.run(
        cmd,
        input=STDIN_BLOB,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        cwd=REPO,
    )
    return proc.stdout


@pytest.fixture(scope="module")
def direct() -> bytes:
    return _run([sys.executable, str(MOCK)])


@pytest.fixture(scope="module")
def proxied() -> bytes:
    return _run([sys.executable, "-m", "kams.cli", "shim", "--", sys.executable, str(MOCK)])


def test_direct_produces_output(direct: bytes) -> None:
    """Guard against the test passing because both sides emitted nothing."""
    assert direct.strip(), "mock server produced no output; the transcript is not exercising it"
    assert len(direct.splitlines()) >= 7


def test_byte_identical(direct: bytes, proxied: bytes) -> None:
    """The whole point: identical bytes, not merely equivalent JSON."""
    if direct != proxied:
        d_lines = direct.splitlines()
        p_lines = proxied.splitlines()
        for i, (a, b) in enumerate(zip(d_lines, p_lines)):
            if a != b:
                pytest.fail(f"divergence at line {i}:\n  direct : {a[:300]!r}\n  proxied: {b[:300]!r}")
        pytest.fail(f"line count differs: direct={len(d_lines)} proxied={len(p_lines)}")


def test_large_payload_survives(proxied: bytes) -> None:
    """Explicitly assert the >64 KiB frame was not truncated by stream limits."""
    for line in proxied.splitlines():
        payload = json.loads(line)
        if payload.get("id") == 5:
            text = payload["result"]["content"][0]["text"]
            assert len(text) == 200_000
            return
    pytest.fail("large-payload response (id=5) missing from proxied output")


def test_error_relayed_with_data(proxied: bytes) -> None:
    for line in proxied.splitlines():
        payload = json.loads(line)
        if payload.get("id") == 4:
            assert payload["error"]["code"] == -32001
            assert payload["error"]["data"] == {"detail": "on purpose"}
            return
    pytest.fail("error response (id=4) missing from proxied output")


def test_unknown_method_relayed(proxied: bytes) -> None:
    """Principle 5: an unrecognised method degrades to passthrough, not failure."""
    ids = {json.loads(line).get("id") for line in proxied.splitlines()}
    assert 6 in ids, "unknown method was dropped instead of relayed"
