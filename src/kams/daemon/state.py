"""Standing enforcement state, shared across processes.

The shim is one process per agent-server connection; the daemon receiving SigNoz
alerts is another. A quarantine decided in either must be honoured by all of
them, so the state cannot live in a single process's memory.

Implemented as a small JSON file with atomic replace rather than a socket, and
that is a deliberate choice rather than a shortcut:

  * A shim keeps working when the daemon is not running. A socket makes the
    daemon a hard dependency of every connection, which violates principle 1 --
    observability must never be what stops an agent working.
  * Readers never block writers and vice versa. `os.replace` is atomic on POSIX,
    so a reader sees either the old file or the new one, never a torn one.
  * It is inspectable. `cat kams-state.json` answers "why is this blocked"
    without attaching a debugger to a daemon.

The cost is propagation latency bounded by the reader's poll interval, which for
a sub-second cache is well inside the window that matters.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

log = logging.getLogger("kams.state")

DEFAULT_STATE_PATH = Path("kams-state.json")

# How long a reader trusts its cached copy. Short enough that a quarantine takes
# effect promptly, long enough that a hot relay is not stat()ing on every call.
CACHE_TTL_SECONDS = 1.0


@dataclass
class StoredRestriction:
    action: str
    server: str
    tool: str | None
    rule: str
    reason: str
    created_at: float
    expires_at: float | None
    # Which path installed this: "reflex" (shim detector) or "signoz" (alert
    # webhook). Kept so the enforcement span can say where the decision came
    # from, which is the whole point of having two paths.
    origin: str = "reflex"
    # Present only for rate_limit restrictions; absent in version-1 files is
    # intentionally backward compatible.
    rate: str | None = None

    def expired(self, now: float) -> bool:
        return self.expires_at is not None and now >= self.expires_at


class SharedState:
    def __init__(self, path: Path | str = DEFAULT_STATE_PATH, *, clock=time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self._cache: list[StoredRestriction] = []
        self._cache_read_at = 0.0
        self._cache_mtime = -1.0

    # ---- reading -------------------------------------------------------------

    def active(self, *, force: bool = False) -> list[StoredRestriction]:
        """Current non-expired restrictions, cached briefly."""
        now = self._clock()
        if not force and (now - self._cache_read_at) < CACHE_TTL_SECONDS:
            return [r for r in self._cache if not r.expired(now)]

        self._cache_read_at = now
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            self._cache = []
            self._cache_mtime = -1.0
            return []

        if mtime != self._cache_mtime:
            self._cache = self._read()
            self._cache_mtime = mtime
        return [r for r in self._cache if not r.expired(now)]

    def _read(self) -> list[StoredRestriction]:
        try:
            raw = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            # A corrupt or half-written state file must never break the relay.
            # Fail open: no restrictions rather than no service.
            log.debug("state unreadable, treating as empty: %r", exc)
            return []
        out: list[StoredRestriction] = []
        for item in raw.get("restrictions") or []:
            try:
                out.append(StoredRestriction(**item))
            except TypeError:
                continue
        return out

    # ---- writing -------------------------------------------------------------

    def add(self, restriction: StoredRestriction) -> None:
        current = [r for r in self.active(force=True) if not self._same_target(r, restriction)]
        current.append(restriction)
        self._write(current)

    def lift(self, server: str) -> int:
        current = self.active(force=True)
        remaining = [r for r in current if r.server != server]
        removed = len(current) - len(remaining)
        if removed:
            self._write(remaining)
        return removed

    def clear(self) -> None:
        self._write([])

    def _write(self, restrictions: list[StoredRestriction]) -> None:
        payload = {
            "version": 1,
            "updated_at": self._clock(),
            "restrictions": [asdict(r) for r in restrictions],
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Temp file in the same directory so os.replace stays on one
            # filesystem and therefore stays atomic.
            fd, tmp = tempfile.mkstemp(dir=str(self.path.parent or "."), prefix=".kams-state-")
            with os.fdopen(fd, "w") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(tmp, self.path)
            self._cache = restrictions
            self._cache_mtime = self.path.stat().st_mtime
            self._cache_read_at = self._clock()
        except OSError as exc:
            log.warning("could not persist enforcement state: %r", exc)

    @staticmethod
    def _same_target(a: StoredRestriction, b: StoredRestriction) -> bool:
        return a.server == b.server and a.tool == b.tool and a.action == b.action
