"""`kams.lock` -- pinned tool definitions.

MCP servers are third-party dependencies that currently ship with no integrity
checking whatsoever. This is the missing lockfile.

Two trust states, and the distinction drives severity:

  provisional  Trust on first use. We recorded what the server advertised but
               nobody has vouched for it. A change here is worth noting, not
               alarming -- we never asserted the original was good.

  pinned       A human ran `kams pin`. The definition is now an assertion. Any
               deviation is a rug pull until proven otherwise, because the whole
               point of the attack is that the version you approved is not the
               version you later get served.

The file is JSON and meant to be committed, reviewed in diffs, and argued about
in pull requests -- exactly like any other lockfile.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from kams.protocol.mcp import ToolDef

LOCK_VERSION = 1
DEFAULT_LOCK_PATH = Path("kams.lock")


@dataclass
class PinnedTool:
    name: str
    digest: str
    description_digest: str
    schema_digest: str
    # Kept verbatim so drift can be *diffed*, not merely flagged. Knowing a
    # description changed is nearly useless; seeing what it changed to is the
    # whole finding.
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_tooldef(cls, t: ToolDef) -> PinnedTool:
        return cls(
            name=t.name,
            digest=t.digest,
            description_digest=t.description_digest,
            schema_digest=t.schema_digest,
            description=t.description,
            input_schema=t.input_schema,
        )


@dataclass
class ServerBaseline:
    server: str
    pinned: bool = False
    tools: dict[str, PinnedTool] = field(default_factory=dict)

    @property
    def state(self) -> str:
        return "pinned" if self.pinned else "provisional"


class BaselineStore:
    def __init__(self, path: Path | str = DEFAULT_LOCK_PATH) -> None:
        self.path = Path(path)
        self.servers: dict[str, ServerBaseline] = {}
        self.load()

    # ---- persistence ---------------------------------------------------------

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            # A corrupt lockfile must not stop the agent. We start from empty
            # and re-learn provisionally rather than refusing to run.
            return
        for name, entry in (raw.get("servers") or {}).items():
            tools = {
                tname: PinnedTool(**tdata)
                for tname, tdata in (entry.get("tools") or {}).items()
            }
            self.servers[name] = ServerBaseline(
                server=name, pinned=bool(entry.get("pinned")), tools=tools
            )

    def save(self) -> None:
        payload = {
            "version": LOCK_VERSION,
            "servers": {
                name: {
                    "pinned": b.pinned,
                    "tools": {tn: asdict(t) for tn, t in sorted(b.tools.items())},
                }
                for name, b in sorted(self.servers.items())
            },
        }
        # sort_keys + trailing newline so lockfile diffs stay reviewable.
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n")

    # ---- access --------------------------------------------------------------

    def get(self, server: str) -> ServerBaseline | None:
        return self.servers.get(server)

    def record_provisional(self, server: str, tools: list[ToolDef]) -> ServerBaseline:
        """Trust on first use. Does not overwrite an existing baseline."""
        if existing := self.servers.get(server):
            return existing
        baseline = ServerBaseline(
            server=server,
            pinned=False,
            tools={t.name: PinnedTool.from_tooldef(t) for t in tools},
        )
        self.servers[server] = baseline
        return baseline

    def pin(self, server: str, tools: list[ToolDef] | None = None) -> ServerBaseline:
        """Promote to pinned, optionally accepting the current definitions.

        Passing `tools` is how a human accepts a legitimate upstream change:
        review the diff, then re-pin.
        """
        baseline = self.servers.get(server) or ServerBaseline(server=server)
        if tools is not None:
            baseline.tools = {t.name: PinnedTool.from_tooldef(t) for t in tools}
        baseline.pinned = True
        self.servers[server] = baseline
        return baseline
