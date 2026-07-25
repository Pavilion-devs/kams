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
    shim.add_argument("--lock", default="kams.lock", help="path to the pinned tool-definition lockfile")
    shim.add_argument("--no-integrity", action="store_true", help="disable the integrity detector")
    shim.add_argument("--policy", default="policy.yaml", help="path to the policy file")
    shim.add_argument("--no-enforce", action="store_true", help="observe only; never block")

    pin = sub.add_parser(
        "pin",
        help="promote a server's recorded tool definitions to pinned",
        description=(
            "Pinning turns trust-on-first-use into an assertion. After pinning, any "
            "change to a tool's name, description, or schema is a finding -- which is "
            "what makes a rug pull visible."
        ),
    )
    pin.add_argument("server", nargs="?", help="server name (omit to pin every recorded server)")
    pin.add_argument("--lock", default="kams.lock")

    status = sub.add_parser("status", help="show recorded servers and their trust state")
    status.add_argument("--lock", default="kams.lock")

    args = parser.parse_args(ours)

    # stderr only: stdout is the MCP wire and must carry nothing but protocol.
    logging.basicConfig(
        level=getattr(logging, getattr(args, "log_level", "warning").upper(), logging.WARNING),
        stream=sys.stderr,
        format="kams %(levelname)s %(name)s: %(message)s",
    )

    if args.cmd == "shim":
        if not upstream:
            parser.error("shim requires an upstream command after `--`")
        return asyncio.run(_run_shim(args, upstream))
    if args.cmd == "pin":
        return _run_pin(args)
    if args.cmd == "status":
        return _run_status(args)

    return 1


async def _run_shim(args, upstream: list[str]) -> int:
    server_name = args.server or os.path.basename(upstream[0])

    if args.no_telemetry:
        return await StdioRelay(upstream).run()

    from kams.detect.baseline import BaselineStore
    from kams.detect.integrity import IntegrityDetector
    from kams.shim.interceptor import Interceptor
    from kams.telemetry import tracing

    tracing.setup("kams-shim", endpoint=args.otlp_endpoint, extra_resource={"kams.server": server_name})

    store = None
    integrity = None
    if not args.no_integrity:
        store = BaselineStore(args.lock)
        integrity = IntegrityDetector(store)

    engine = None
    if not args.no_enforce:
        from kams.policy.engine import PolicyEngine
        from kams.policy.model import Policy

        try:
            policy = Policy.load(args.policy) if os.path.exists(args.policy) else Policy.permissive()
        except Exception as exc:  # noqa: BLE001
            # A malformed policy must not stop the agent. Fall back to
            # observe-only and say so loudly (principle 1).
            print(f"kams: policy {args.policy} unreadable ({exc}); observing only", file=sys.stderr)
            policy = Policy.permissive()
        engine = PolicyEngine(policy)

    interceptor = Interceptor(server_name, integrity=integrity, policy=engine)
    relay = StdioRelay(
        upstream,
        on_client_message=interceptor.on_client_message,
        on_server_message=interceptor.on_server_message,
    )
    try:
        return await relay.run()
    finally:
        interceptor.close()
        if store is not None:
            # Persist any provisional baseline learned this session, so the next
            # run can detect drift against it.
            try:
                store.save()
            except OSError as exc:
                print(f"kams: could not write {args.lock}: {exc}", file=sys.stderr)
        tracing.shutdown()


def _run_pin(args) -> int:
    from kams.detect.baseline import BaselineStore

    store = BaselineStore(args.lock)
    if not store.servers:
        print(f"kams: nothing recorded in {args.lock} yet — run the shim once first", file=sys.stderr)
        return 1

    targets = [args.server] if args.server else list(store.servers)
    for name in targets:
        if name not in store.servers:
            print(f"kams: unknown server {name!r}", file=sys.stderr)
            return 1
        store.pin(name)
        print(f"pinned {name} ({len(store.servers[name].tools)} tools)")
    store.save()
    return 0


def _run_status(args) -> int:
    from kams.detect.baseline import BaselineStore

    store = BaselineStore(args.lock)
    if not store.servers:
        print(f"no servers recorded in {args.lock}")
        return 0
    for name, baseline in sorted(store.servers.items()):
        print(f"{name:24} {baseline.state:12} {len(baseline.tools)} tools")
        for tname, t in sorted(baseline.tools.items()):
            print(f"    {tname:20} {t.digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
