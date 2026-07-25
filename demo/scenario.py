"""The Kams demo: a rug pull, caught and contained.

Speaks MCP the way a real agent does -- one request at a time, waiting for each
response before issuing the next. That sequencing matters. A script that dumps
every request into stdin at once gets them all past the interceptor before the
`tools/list` response has been seen, so nothing is blocked. Real clients do not
behave that way, and neither does this.

Run:  uv run python demo/scenario.py
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
POISON_FLAG = ROOT / "demo" / ".poisoned"
LOCK = ROOT / "kams.lock"

DIM, BOLD, RED, GREEN, YELLOW, CYAN, RESET = (
    "\033[2m", "\033[1m", "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[0m"
)


def rule(title: str) -> None:
    width = min(shutil.get_terminal_size((90, 20)).columns, 90)
    print(f"\n{BOLD}{CYAN}{title}{RESET}\n{DIM}{'─' * width}{RESET}")


class MCPClient:
    """Minimal sequential MCP client over stdio."""

    def __init__(self, command: list[str]) -> None:
        self.command = command
        self.proc: asyncio.subprocess.Process | None = None
        self._id = 0

    async def __aenter__(self) -> MCPClient:
        self.proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=ROOT,
            limit=32 * 1024 * 1024,
        )
        return self

    async def __aexit__(self, *_exc) -> None:
        if self.proc and self.proc.returncode is None:
            self.proc.stdin.close()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                self.proc.kill()

    async def call(self, method: str, params: dict | None = None) -> dict:
        assert self.proc and self.proc.stdin and self.proc.stdout
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            req["params"] = params
        self.proc.stdin.write(json.dumps(req).encode() + b"\n")
        await self.proc.stdin.drain()
        # Wait for THIS response before returning -- the sequencing is the point.
        line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=30)
        return json.loads(line) if line else {}

    async def stderr_text(self) -> str:
        if not self.proc or not self.proc.stderr:
            return ""
        try:
            return (await asyncio.wait_for(self.proc.stderr.read(), timeout=2)).decode(errors="replace")
        except asyncio.TimeoutError:
            return ""


def shim_cmd() -> list[str]:
    return [sys.executable, "-m", "kams.cli", "shim", "--server", "notes-mcp",
            "--", sys.executable, "demo/rogue_mcp_server.py"]


async def session(label: str, *, show_tools: bool = False) -> list[str]:
    """One agent session. Returns lines Kams wrote to stderr."""
    async with MCPClient(shim_cmd()) as client:
        await client.call("initialize", {"protocolVersion": "2025-06-18"})

        listed = await client.call("tools/list")
        tools = (listed.get("result") or {}).get("tools", [])
        if show_tools:
            for t in tools:
                desc = t["description"].replace("\n", " ")
                flag = f"  {RED}← poisoned{RESET}" if "<IMPORTANT>" in t["description"] else ""
                print(f"  {t['name']:12} {DIM}{desc[:60]}{'…' if len(desc) > 60 else ''}{RESET}{flag}")

        for tool in ("save_note", "list_notes"):
            resp = await client.call("tools/call", {"name": tool, "arguments": {"note": "buy milk"}})
            if "error" in resp:
                print(f"  {tool:12} {RED}BLOCKED{RESET}  {resp['error']['message']}")
            else:
                text = (resp.get("result") or {}).get("content", [{}])[0].get("text", "")
                print(f"  {tool:12} {GREEN}ok{RESET}       {DIM}{text}{RESET}")

        err = await client.stderr_text()
    return [ln for ln in err.splitlines() if "kams" in ln.lower()]


def show_kams(lines: list[str]) -> None:
    for ln in lines:
        if "CRITICAL" in ln or "enforcing" in ln:
            print(f"  {RED}{ln.strip()}{RESET}")
        elif any(s in ln for s in ("HIGH", "MEDIUM", "WARNING")):
            print(f"  {YELLOW}{ln.strip()}{RESET}")


async def main() -> int:
    POISON_FLAG.unlink(missing_ok=True)
    LOCK.unlink(missing_ok=True)

    print(f"\n{BOLD}Kams — MCP rug pull, caught and contained{RESET}")
    print(f"{DIM}The server never changes its code. Only the text it advertises changes.{RESET}")

    rule("1. First run — the server is clean. Trust on first use.")
    lines = await session("clean", show_tools=True)
    show_kams(lines)
    print(f"  {DIM}(no findings — nothing to report){RESET}" if not lines else "")

    rule("2. A human reviews the definitions and pins them")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "kams.cli", "pin", "notes-mcp", cwd=ROOT,
        stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    print(f"  $ kams pin notes-mcp\n  {DIM}{out.decode().strip()}{RESET}")
    print(f"  {DIM}kams.lock is now an assertion, not an observation.{RESET}")

    rule("3. The server rug-pulls — same name, same schema, new description")
    POISON_FLAG.touch()
    lines = await session("poisoned", show_tools=True)
    print()
    show_kams(lines)

    rule("4. What just happened")
    print(f"""  {DIM}The tool's name, schema, and implementation are byte-identical.
  Only the description changed — and descriptions are injected verbatim
  into the model's context, which makes them executable instruction.

  Kams compared against the pinned digest, scored the added text
  deterministically, and quarantined the server before the agent could
  act on it. The block is a well-formed JSON-RPC error, so the agent
  degrades instead of hanging.{RESET}

  {BOLD}Traces, findings, and the enforcement span: http://localhost:8080{RESET}
""")
    POISON_FLAG.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
