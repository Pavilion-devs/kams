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
    shim.add_argument(
        "--no-telemetry",
        action="store_true",
        help="relay only, emit nothing (used by the golden transparency tests)",
    )
    shim.add_argument("--otlp-endpoint", default=None, help="OTLP gRPC endpoint")

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
        return asyncio.run(_run_shim(args, upstream))

    return 1


async def _run_shim(args, upstream: list[str]) -> int:
    server_name = args.server or os.path.basename(upstream[0])

    if args.no_telemetry:
        return await StdioRelay(upstream).run()

    from kams.shim.interceptor import Interceptor
    from kams.telemetry import tracing

    tracing.setup("kams-shim", endpoint=args.otlp_endpoint, extra_resource={"kams.server": server_name})
    interceptor = Interceptor(server_name)

    relay = StdioRelay(
        upstream,
        on_client_message=interceptor.on_client_message,
        on_server_message=interceptor.on_server_message,
    )
    try:
        return await relay.run()
    finally:
        interceptor.close()
        tracing.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
