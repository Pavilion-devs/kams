"""Apply dashboards and alerts from versioned JSON.

Dashboards and alerts are code here, not UI state. They live in provisioning/,
diff in review, and are applied by this script — which means the observability
for Kams is reproducible from a clean clone rather than being something someone
clicked together once and cannot recreate.

Applied through SigNoz's own MCP server. That is the dogfood: Kams exists to
observe MCP servers, and it provisions its own dashboards over the protocol it
watches.

    uv run python scripts/provision.py            # apply everything
    uv run python scripts/provision.py --list     # show what exists
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from signoz_mcp import call, signoz_session  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
DASHBOARDS = ROOT / "provisioning" / "dashboards"
ALERTS = ROOT / "provisioning" / "alerts"

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}✗{RESET} {msg}")


async def existing_dashboards(session) -> dict[str, str]:
    """Map title -> id, so re-running updates instead of duplicating."""
    res = await call(session, "signoz_list_dashboards")
    try:
        payload = json.loads(res["text"])
    except (json.JSONDecodeError, TypeError):
        return {}
    rows = payload.get("data") if isinstance(payload, dict) else payload
    out: dict[str, str] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        # The MCP tool returns a flattened summary (`name`, `uuid`); the REST
        # endpoint returns the nested form (`data.title`, `id`). Accept either
        # so this keeps working whichever path is used.
        title = row.get("name") or (row.get("data") or {}).get("title") or row.get("title")
        did = row.get("uuid") or row.get("id")
        if title and did:
            out[title] = did
    return out


async def apply_dashboards(session) -> int:
    if not DASHBOARDS.exists():
        return 0
    current = await existing_dashboards(session)
    failures = 0

    for path in sorted(DASHBOARDS.glob("*.json")):
        spec = json.loads(path.read_text())
        title = spec["title"]
        args = {
            "title": title,
            "description": spec.get("description", ""),
            "tags": spec.get("tags", []),
            "widgets": spec.get("widgets", []),
            "layout": spec.get("layout", []),
            # The tool asks for the originating request; provisioning is
            # automated, so say so rather than inventing a human prompt.
            "searchContext": f"Provisioned from {path.relative_to(ROOT)} by scripts/provision.py",
        }

        if title in current:
            # update takes the complete post-update state under a `dashboard`
            # object, unlike create which takes the fields flattened.
            res = await call(
                session,
                "signoz_update_dashboard",
                id=current[title],
                dashboard={
                    "title": title,
                    "description": args["description"],
                    "tags": args["tags"],
                    "widgets": args["widgets"],
                    "layout": args["layout"],
                },
                searchContext=args["searchContext"],
            )
            verb = "updated"
        else:
            res = await call(session, "signoz_create_dashboard", **args)
            verb = "created"

        if res["is_error"]:
            fail(f"{path.name}: {res['text'][:300]}")
            failures += 1
        else:
            ok(f"{verb} dashboard {BOLD}{title}{RESET} {DIM}({len(spec.get('widgets', []))} panels){RESET}")
    return failures


async def apply_alerts(session) -> int:
    if not ALERTS.exists():
        return 0
    failures = 0
    for path in sorted(ALERTS.glob("*.json")):
        spec = json.loads(path.read_text())
        res = await call(session, "signoz_create_alert", **spec)
        if res["is_error"]:
            fail(f"{path.name}: {res['text'][:400]}")
            failures += 1
        else:
            ok(f"created alert {BOLD}{spec.get('alert')}{RESET}")
    return failures


async def show(session) -> None:
    for tool, label in (
        ("signoz_list_dashboards", "dashboards"),
        ("signoz_list_alert_rules", "alert rules"),
        ("signoz_list_notification_channels", "notification channels"),
    ):
        res = await call(session, tool)
        print(f"\n{BOLD}{label}{RESET}")
        print(f"{DIM}{res['text'][:900]}{RESET}")


async def main() -> int:
    parser = argparse.ArgumentParser(description="Apply Kams dashboards and alerts to SigNoz")
    parser.add_argument("--list", action="store_true", help="show what currently exists")
    args = parser.parse_args()

    async with signoz_session() as session:
        if args.list:
            await show(session)
            return 0
        print(f"{BOLD}Provisioning SigNoz from versioned JSON{RESET}")
        failures = await apply_dashboards(session)
        failures += await apply_alerts(session)
        if failures:
            print(f"\n{RED}{failures} item(s) failed{RESET}")
            return 1
        print(f"\n{GREEN}done{RESET} — http://localhost:8080")
        return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
