"""Local proof that a SigNoz alert—not Kams' reflex path—quarantines MCP."""

from __future__ import annotations

import argparse
import asyncio
import pathlib
import tempfile
import uuid

from kams.telemetry import tracing
from dotenv import load_dotenv

from demo.bedrock_agent import (
    GREEN,
    ROOT,
    RED,
    RESET,
    _mcp_session,
    _pin,
    _start_daemon,
    _wait_for_alert_ready,
    _wait_for_signoz,
)


async def run(args) -> int:
    load_dotenv(ROOT / ".env")
    tracing.setup("kams-alert-loop-demo", endpoint=args.otlp_endpoint)
    with tempfile.TemporaryDirectory(prefix="kams-alert-loop-") as tmp:
        work = pathlib.Path(tmp)
        lock = work / "kams.lock"
        state = work / "kams-state.json"
        poison = work / "poisoned"
        server_name = f"notes-mcp-{uuid.uuid4().hex[:8]}"
        daemon = await _start_daemon(state, args.daemon_port)
        try:
            clean = await _mcp_session(lock, state, poison, server_name)
            try:
                await clean.call("tools/list")
            finally:
                await clean.__aexit__(None, None, None)
            await _pin(lock, server_name)
            print("  waiting for the existing alert state to recover…")
            await _wait_for_alert_ready(args.alert_ready_timeout)

            poison.touch()
            attacked = await _mcp_session(lock, state, poison, server_name)
            try:
                await attacked.call("tools/list")
            finally:
                await attacked.__aexit__(None, None, None)
            print("  drift exported; waiting for the SigNoz alert evaluator…")

            restriction = await _wait_for_signoz(
                state, args.alert_timeout, server_name
            )
            print(
                f"  {GREEN}✓{RESET} {restriction.rule} installed via "
                f"{restriction.origin}"
            )

            blocked = await _mcp_session(lock, state, poison, server_name)
            try:
                result = await blocked.call(
                    "tools/call",
                    {"name": "save_note", "arguments": {"note": "buy milk"}},
                )
            finally:
                await blocked.__aexit__(None, None, None)
            if "error" not in result:
                raise RuntimeError("SigNoz-installed quarantine did not block the tool")
            print(f"  {RED}BLOCKED{RESET} {result['error']['message']}")
            assert result["error"]["data"]["kams"]["rule"].startswith("signoz:")
            print(f"  {GREEN}PASS{RESET} alert → webhook → shared state → blocked MCP")
            return 0
        finally:
            if daemon.returncode is None:
                daemon.terminate()
                try:
                    await asyncio.wait_for(daemon.wait(), timeout=5)
                except asyncio.TimeoutError:
                    daemon.kill()
            tracing.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--alert-timeout",
        type=float,
        default=300.0,
        help="wait for Foundry's alert evaluator, including its ingestion delay",
    )
    parser.add_argument("--alert-ready-timeout", type=float, default=180.0)
    parser.add_argument("--daemon-port", type=int, default=8787)
    parser.add_argument("--otlp-endpoint", default=None)
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
