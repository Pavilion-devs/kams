"""Fire-and-forget delivery of findings to kamsd for enrichment.

Principle 2 in practice. The shim is in the request path; a model call takes
seconds. So the shim hands the finding off and forgets it — no await on the
result, no retry, no error surfaced.

Everything here is designed to be droppable:

  * A background daemon thread does the POST, so the relay never blocks on it.
  * The queue is bounded and discards rather than growing.
  * kamsd being absent is the normal case for a standalone shim, and after the
    first refused connection we stop trying rather than logging on every call.

Losing enrichment costs a prose explanation in a log line. Blocking an agent to
obtain one would be a far worse trade.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger("kams.forward")

DEFAULT_ENDPOINT = "http://127.0.0.1:8787/findings"
MAX_QUEUE = 64
POST_TIMEOUT = 3.0
# Stop after this many consecutive failures. A shim running without kamsd is a
# supported configuration, not an error worth repeating.
FAILURE_LIMIT = 3


class FindingForwarder:
    def __init__(self, endpoint: str = DEFAULT_ENDPOINT, *, enabled: bool = True) -> None:
        self.endpoint = endpoint
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=MAX_QUEUE)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._failures = 0
        self.enabled = enabled
        self.sent = 0
        self.dropped = 0

    def start(self) -> None:
        if self._thread is not None or not self.enabled:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="kams-forward")
        self._thread.start()

    def stop(self, *, drain_timeout: float = 2.0) -> None:
        """Give in-flight findings a bounded chance to land, then give up."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=drain_timeout)

    def submit(self, finding: Any, *, trace_id: str | None = None, span_id: str | None = None) -> None:
        """Non-blocking. Silently drops when saturated or disabled."""
        if not self.enabled or self._failures >= FAILURE_LIMIT:
            return
        try:
            payload = {
                "server": finding.server,
                "tool": finding.tool,
                "detector": finding.detector,
                "severity": finding.severity.name,
                "summary": finding.summary,
                # Only the integrity evidence is useful to the judge, and the
                # judge itself allowlists the two description fields out of it.
                "evidence": finding.evidence,
                "trace_id": trace_id,
                "span_id": span_id,
            }
        except AttributeError:
            return
        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                payload = self._queue.get(timeout=0.3)
            except queue.Empty:
                continue
            self._post(payload)

    def _post(self, payload: dict[str, Any]) -> None:
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=POST_TIMEOUT):
                pass
            self.sent += 1
            self._failures = 0
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            self._failures += 1
            if self._failures == FAILURE_LIMIT:
                log.info("kamsd unreachable at %s; enrichment disabled for this session", self.endpoint)
            else:
                log.debug("finding forward failed: %r", exc)
