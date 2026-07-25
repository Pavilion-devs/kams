"""stdio transport relay: the data-plane spine.

The agent spawns Kams; Kams spawns the real MCP server. We sit between the two
pipes. Everything here is in the request path, so this module stays boring:
no detection logic, no network, no policy. It relays, it calls hooks, it gets
out of the way.

Transparency guarantees, in order of importance:

1. Bytes are forwarded unmodified unless a hook explicitly rewrites a message.
2. A hook that raises is caught and treated as "no opinion" -- observability
   must never break the workload (principle 1).
3. Message order is preserved. Each direction is a single sequential pump, so
   there is no opportunity to reorder.
4. Unparseable input is relayed verbatim rather than dropped or corrected.
5. Upstream stderr passes through untouched, so the agent's own diagnostics
   still work with Kams in the path.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum

from kams.protocol import jsonrpc
from kams.protocol.jsonrpc import Message

log = logging.getLogger("kams.transport.stdio")

# MCP tool results can be large (file contents, query output). asyncio's default
# StreamReader limit is 64 KiB, which a real workload will exceed. 32 MiB is
# generous enough that we never truncate a legitimate message; beyond that we
# treat it as pathological and let the read fail loudly.
STREAM_LIMIT = 32 * 1024 * 1024

# How long to let the upstream flush pending responses after the agent closes
# stdin. Generous: a slow tool answering a final request is normal, and dropping
# its response would be a correctness bug visible to the agent.
DRAIN_TIMEOUT = 30.0


class Disposition(Enum):
    FORWARD = "forward"
    # Do not forward; synthesise a JSON-RPC error back to the caller instead.
    BLOCK = "block"


@dataclass
class HookResult:
    disposition: Disposition = Disposition.FORWARD
    # Populated only for BLOCK.
    error_code: int = -32000
    error_message: str = "blocked by policy"
    error_data: dict | None = None

    @staticmethod
    def forward() -> HookResult:
        return HookResult()

    @staticmethod
    def block(message: str, code: int = -32000, data: dict | None = None) -> HookResult:
        return HookResult(
            disposition=Disposition.BLOCK,
            error_code=code,
            error_message=message,
            error_data=data,
        )


# A hook may mutate `msg` in place (via msg.rewrite) and returns what to do next.
Hook = Callable[[Message], Awaitable[HookResult]]


async def _noop_hook(_: Message) -> HookResult:
    return HookResult.forward()


class StdioRelay:
    """Relays JSON-RPC between an agent (our stdio) and an upstream MCP server."""

    def __init__(
        self,
        command: list[str],
        *,
        on_client_message: Hook | None = None,
        on_server_message: Hook | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        if not command:
            raise ValueError("upstream command is required")
        self.command = command
        self.on_client_message = on_client_message or _noop_hook
        self.on_server_message = on_server_message or _noop_hook
        self.env = env
        self.cwd = cwd
        self._proc: asyncio.subprocess.Process | None = None

    async def run(self) -> int:
        """Run until either side closes. Returns the upstream exit code."""
        self._proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self.env,
            cwd=self.cwd,
            limit=STREAM_LIMIT,
        )
        proc = self._proc

        agent_in = await _stdin_reader()
        agent_out = await _stdout_writer()

        c2s = asyncio.create_task(
            self._pump_client_to_server(agent_in, proc.stdin, agent_out),
            name="kams-c2s",
        )
        s2c = asyncio.create_task(
            self._pump_server_to_client(proc.stdout, agent_out),
            name="kams-s2c",
        )
        errp = asyncio.create_task(self._pump_stderr(proc.stderr), name="kams-stderr")

        # The authoritative end of session is upstream stdout EOF (s2c), NOT the
        # client closing stdin (c2s).
        #
        # When the agent closes stdin, in-flight requests may still be unanswered.
        # Tearing down on c2s completion would drop those responses on the floor
        # -- which is exactly the bug this ordering exists to prevent. So: if c2s
        # finishes first, upstream stdin is closed and we give the server a
        # bounded window to flush whatever it still owes us.
        done, _ = await asyncio.wait({c2s, s2c}, return_when=asyncio.FIRST_COMPLETED)

        if s2c not in done:
            if c2s.exception() is None:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.shield(s2c), timeout=DRAIN_TIMEOUT)
            else:
                log.error("client pump failed: %r", c2s.exception())

        for task in (c2s, s2c, errp):
            if not task.done():
                task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        for task in (c2s, s2c):
            if task.done() and not task.cancelled() and (exc := task.exception()) is not None:
                log.error("relay pump failed: %r", exc)

        with contextlib.suppress(ProcessLookupError):
            if proc.returncode is None:
                proc.terminate()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(proc.wait(), timeout=5)
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()

        return proc.returncode if proc.returncode is not None else 0

    # ---- pumps ------------------------------------------------------------------

    async def _pump_client_to_server(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter | None,
        agent_out: asyncio.StreamWriter,
    ) -> None:
        assert writer is not None
        async for line in _iter_lines(reader):
            msg = jsonrpc.parse(line)
            result = await self._safe_hook(self.on_client_message, msg)

            if result.disposition is Disposition.BLOCK:
                # Never reaches the upstream server. The agent gets a well-formed
                # JSON-RPC error so it can degrade gracefully instead of hanging.
                await _write_line(agent_out, _error_response(msg, result))
                continue

            await _write_line(writer, msg.to_bytes())

        with contextlib.suppress(Exception):
            writer.close()

    async def _pump_server_to_client(
        self,
        reader: asyncio.StreamReader | None,
        writer: asyncio.StreamWriter,
    ) -> None:
        assert reader is not None
        async for line in _iter_lines(reader):
            msg = jsonrpc.parse(line)
            # A BLOCK on the server->client path is not meaningful: suppressing a
            # response would hang the agent waiting for an id that never returns.
            # Server-side hooks observe and may rewrite (redaction), never block.
            await self._safe_hook(self.on_server_message, msg)
            await _write_line(writer, msg.to_bytes())

    async def _pump_stderr(self, reader: asyncio.StreamReader | None) -> None:
        """Pass upstream stderr through untouched so server diagnostics survive."""
        assert reader is not None
        loop = asyncio.get_running_loop()
        while chunk := await reader.read(8192):
            await loop.run_in_executor(None, _write_stderr, chunk)

    # ---- hook safety -------------------------------------------------------------

    async def _safe_hook(self, hook: Hook, msg: Message) -> HookResult:
        """A detector that throws must not take the workload down (principle 1)."""
        try:
            return await hook(msg)
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the boundary
            log.warning("hook raised, treating as no-opinion: %r", exc)
            return HookResult.forward()


# ---- wire helpers ---------------------------------------------------------------


def _error_response(msg: Message, result: HookResult) -> bytes:
    payload: dict = {
        "jsonrpc": "2.0",
        "id": msg.id,
        "error": {"code": result.error_code, "message": result.error_message},
    }
    if result.error_data:
        payload["error"]["data"] = result.error_data
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


async def _iter_lines(reader: asyncio.StreamReader):
    """Yield complete lines, tolerating oversized frames without dying."""
    while True:
        try:
            line = await reader.readline()
        except (asyncio.LimitOverrunError, ValueError) as exc:
            log.error("oversized frame on stream, closing direction: %r", exc)
            return
        if not line:
            return
        stripped = line.rstrip(b"\r\n")
        if stripped:
            yield stripped


async def _write_line(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data + b"\n")
    await writer.drain()


def _write_stderr(chunk: bytes) -> None:
    import sys

    sys.stderr.buffer.write(chunk)
    sys.stderr.buffer.flush()


async def _stdin_reader() -> asyncio.StreamReader:
    import sys

    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=STREAM_LIMIT)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    return reader


async def _stdout_writer() -> asyncio.StreamWriter:
    import sys

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.connect_write_pipe(asyncio.streams.FlowControlMixin, sys.stdout)
    return asyncio.StreamWriter(transport, protocol, None, loop)
