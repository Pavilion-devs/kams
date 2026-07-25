"""Drive realistic MCP traffic so the dashboards have something to show.

A dashboard with no data proves nothing, and a single burst proves almost as
little. This runs repeated sessions with a mix of successes, errors, and a
poisoned server, so the panels show shape rather than a single spike.

    uv run python demo/generate_traffic.py --sessions 25
"""

from __future__ import annotations

import argparse
import asyncio
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demo"))

from scenario import MCPClient  # noqa: E402

POISON_FLAG = ROOT / "demo" / ".poisoned"

# Three servers so per-server panels have more than one line to draw.
SERVERS = [
    ("notes-mcp", "demo/rogue_mcp_server.py", ["save_note", "list_notes"]),
    ("mock-mcp", "tests/fixtures/mock_mcp_server.py", ["read_file", "søk"]),
    ("flaky-mcp", "tests/fixtures/mock_mcp_server.py", ["read_file", "boom"]),
]


def shim(server: str, script: str) -> list[str]:
    return [sys.executable, "-m", "kams.cli", "shim", "--server", server,
            "--lock", "demo/traffic.lock", "--", sys.executable, script]


async def one_session(server: str, script: str, tools: list[str]) -> tuple[int, int]:
    ok = err = 0
    try:
        async with MCPClient(shim(server, script)) as client:
            await client.call("initialize", {"protocolVersion": "2025-06-18"})
            await client.call("tools/list")
            for _ in range(random.randint(2, 5)):
                tool = random.choice(tools)
                resp = await client.call("tools/call", {"name": tool, "arguments": {"note": "x"}})
                if "error" in resp:
                    err += 1
                else:
                    ok += 1
    except Exception as exc:  # noqa: BLE001 - traffic generation is best-effort
        print(f"  session against {server} failed: {exc!r}", file=sys.stderr)
    return ok, err


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, default=20)
    parser.add_argument("--poison-after", type=int, default=12,
                        help="flip notes-mcp to its poisoned definition after N sessions")
    args = parser.parse_args()

    POISON_FLAG.unlink(missing_ok=True)
    (ROOT / "demo" / "traffic.lock").unlink(missing_ok=True)

    print(f"driving {args.sessions} sessions across {len(SERVERS)} servers")
    total_ok = total_err = 0

    for i in range(1, args.sessions + 1):
        if i == args.poison_after:
            # Pin what has been learned so far, then poison -- so the drift
            # lands against a pinned baseline and scores CRITICAL.
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "kams.cli", "pin", "--lock", "demo/traffic.lock",
                cwd=ROOT, stdout=asyncio.subprocess.DEVNULL)
            await proc.wait()
            POISON_FLAG.touch()
            print(f"  [{i}] pinned baselines, poisoned notes-mcp")

        server, script, tools = SERVERS[i % len(SERVERS)]
        ok, err = await one_session(server, script, tools)
        total_ok += ok
        total_err += err
        if i % 5 == 0:
            print(f"  [{i}/{args.sessions}] ok={total_ok} errors={total_err}")
        # Spread across export windows so the graphs have multiple buckets
        # rather than one tall bar.
        await asyncio.sleep(random.uniform(0.4, 1.2))

    POISON_FLAG.unlink(missing_ok=True)
    (ROOT / "demo" / "traffic.lock").unlink(missing_ok=True)
    print(f"\ndone — {total_ok} successful calls, {total_err} errors/blocks")
    print("give the collector ~15s, then check http://localhost:8080")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
