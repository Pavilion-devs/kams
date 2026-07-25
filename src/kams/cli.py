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
    shim.add_argument("--no-egress", action="store_true", help="disable sensitive-data classification")
    shim.add_argument("--policy", default="policy.yaml", help="path to the policy file")
    shim.add_argument("--no-enforce", action="store_true", help="observe only; never block")
    shim.add_argument("--state", default="kams-state.json",
                      help="shared enforcement state, written by kamsd and other shims")

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
    status.add_argument("--state", default="kams-state.json")

    daemon = sub.add_parser(
        "daemon",
        help="run the control plane: receive SigNoz alert webhooks and enforce",
        description=(
            "The shim sees one connection right now; SigNoz sees every agent over "
            "time. Fleet-scale, time-windowed conditions are not expressible in the "
            "shim, so alerts arrive here and land in the same shared state the "
            "reflex path writes to."
        ),
    )
    daemon.add_argument("--port", type=int, default=8787)
    daemon.add_argument("--state", default="kams-state.json")
    daemon.add_argument("--ttl", default="1h", help="how long an alert-driven quarantine lasts")
    daemon.add_argument("--log-level", default=os.environ.get("KAMS_LOG_LEVEL", "info"))

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
    if args.cmd == "daemon":
        return _run_daemon(args)

    return 1


def _run_daemon(args) -> int:
    import time

    from kams.daemon.state import SharedState
    from kams.daemon.webhook import serve
    from kams.policy.model import parse_duration
    from kams.telemetry import tracing

    tracing.setup("kamsd")
    state = SharedState(args.state)
    ttl = parse_duration(args.ttl) or 3600.0
    serve(state, port=args.port, ttl=ttl)

    print(f"kamsd listening on :{args.port}  state={args.state}  ttl={int(ttl)}s")
    print("point a SigNoz webhook notification channel at this endpoint")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        tracing.shutdown()
    return 0


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
        from kams.daemon.state import SharedState

        engine = PolicyEngine(policy, shared=SharedState(args.state))

    egress = None
    if not args.no_egress:
        from kams.detect.egress import EgressClassifier

        egress = EgressClassifier()

    from kams.detect.cost import ContextCostEstimator

    interceptor = Interceptor(
        server_name, integrity=integrity, policy=engine,
        egress=egress, cost=ContextCostEstimator(),
    )
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

    from kams.daemon.state import SharedState

    store = BaselineStore(args.lock)
    if not store.servers:
        print(f"no servers recorded in {args.lock}")
    for name, baseline in sorted(store.servers.items()):
        print(f"{name:24} {baseline.state:12} {len(baseline.tools)} tools")
        for tname, t in sorted(baseline.tools.items()):
            print(f"    {tname:20} {t.digest}")

    restrictions = SharedState(getattr(args, "state", "kams-state.json")).active(force=True)
    if restrictions:
        print("\nstanding restrictions")
        for r in restrictions:
            remaining = f"{int(r.expires_at - __import__('time').time())}s" if r.expires_at else "no expiry"
            print(f"    {r.server:20} {r.action:18} [{r.rule}] via {r.origin}, {remaining} left")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
