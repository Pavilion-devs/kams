"""Kams command line.

    kams shim -- <command> [args...]     wrap an MCP server on stdio

Adoption is a one-line change in an existing MCP config: replace the server's
`command` with `kams shim -- <original command>`. No SDK, no code change in the
agent.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from kams.transport.stdio import StdioRelay


def _split_command(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split our args from the upstream command at the `--` sentinel."""
    if "--" not in argv:
        return argv, []
    idx = argv.index("--")
    return argv[:idx], argv[idx + 1 :]


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ours, upstream = _split_command(argv)

    parser = argparse.ArgumentParser(prog="kams", description="Observability and control for MCP")
    sub = parser.add_subparsers(dest="cmd", required=True)

    shim = sub.add_parser("shim", help="wrap an MCP server on stdio")
    shim.add_argument("--server", default=None, help="logical server name (defaults to the binary name)")
    shim.add_argument("--log-level", default=os.environ.get("KAMS_LOG_LEVEL", "warning"))

    args = parser.parse_args(ours)

    # stderr only: stdout is the MCP wire and must carry nothing but protocol.
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.WARNING),
        stream=sys.stderr,
        format="kams %(levelname)s %(name)s: %(message)s",
    )

    if args.cmd == "shim":
        if not upstream:
            parser.error("shim requires an upstream command after `--`")
        relay = StdioRelay(upstream)
        return asyncio.run(relay.run())

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
