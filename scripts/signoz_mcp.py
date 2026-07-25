"""Thin client for the SigNoz MCP server.

Provisioning goes through SigNoz's own MCP server rather than hand-rolled REST
calls. Two reasons, and the second is the better one:

  1. The MCP tools know the current dashboard/alert schema. Hand-writing widget
     JSON against an undocumented internal shape is how you get a dashboard that
     stores fine and renders nothing.

  2. It is the dogfood. Kams exists to observe MCP servers; SigNoz ships one;
     so Kams provisions its own dashboards through the very protocol it watches,
     and that traffic shows up in the dashboards it just created.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

load_dotenv()

MCP_URL = os.environ.get("SIGNOZ_MCP_URL", "http://localhost:8000/mcp")
API_KEY = os.environ.get("SIGNOZ_API_KEY", "")
SIGNOZ_URL = os.environ.get("SIGNOZ_URL", "http://localhost:8080")


@asynccontextmanager
async def signoz_session():
    """Open an MCP session against the SigNoz server.

    The server runs in per-request-header auth mode, so credentials travel on
    each request rather than being baked into the deployment (which is why
    casting.yaml carries no secrets).
    """
    if not API_KEY:
        raise SystemExit("SIGNOZ_API_KEY is not set — see .env.example")

    # Deliberately NOT sending X-SigNoz-URL. The MCP server resolves SigNoz over
    # the Docker network (signoz-signoz-0:8080) from its own environment, and it
    # rejects a "localhost" override outright -- from inside the container that
    # would point at itself. Only override this when running the MCP server
    # somewhere that genuinely needs a different target.
    headers = {"SIGNOZ-API-KEY": API_KEY}
    async with streamablehttp_client(MCP_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def list_tools(session) -> list[str]:
    return [t.name for t in (await session.list_tools()).tools]


async def call(session, name: str, **kwargs) -> Any:
    result = await session.call_tool(name, kwargs)
    texts = [c.text for c in result.content if getattr(c, "type", None) == "text"]
    return {"is_error": bool(result.isError), "text": "\n".join(texts)}


if __name__ == "__main__":
    import asyncio

    async def main() -> None:
        async with signoz_session() as session:
            tools = await list_tools(session)
            print(f"{len(tools)} tools exposed by the SigNoz MCP server\n")
            for group in ("dashboard", "alert", "metric", "notification"):
                matching = [t for t in tools if group in t]
                if matching:
                    print(f"  {group}:")
                    for t in sorted(matching):
                        print(f"    {t}")

    asyncio.run(main())
