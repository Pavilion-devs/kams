"""Policy evaluation and standing enforcement state.

Pure apart from an injected clock — no I/O, no network, no ambient time. That is
what makes TTL expiry testable without sleeping, and it is why this module can
be exercised with no Docker, no SigNoz, and no MCP server running.

Two inputs converge on the same state (architecture.md §4):

  reflex path   findings from the shim, evaluated in-process, ~1ms
  SigNoz path   alert webhooks, carrying conditions only the aggregate can see

Both call `apply`. Enforcement therefore behaves identically whether a threat
was spotted locally or inferred fleet-wide, which is the point of routing them
through one engine rather than two code paths.
"""

from __future__ import annotations

import fnmatch
import logging
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kams.detect.base import Finding, Severity
from kams.policy.model import Action, Policy, Rule, parse_rate

log = logging.getLogger("kams.policy")

Clock = Callable[[], float]


@dataclass(frozen=True)
class Decision:
    action: Action
    rule: str
    reason: str
    server: str
    tool: str | None = None
    ttl: float | None = None
    rate: str | None = None
    finding: Finding | None = None

    @property
    def is_enforcing(self) -> bool:
        return self.action.is_enforcing


@dataclass
class Restriction:
    """A standing enforcement, with the provenance to explain itself."""

    action: Action
    server: str
    tool: str | None
    rule: str
    reason: str
    expires_at: float | None
    created_at: float
    rate: str | None = None
    origin: str = "reflex"

    def expired(self, now: float) -> bool:
        return self.expires_at is not None and now >= self.expires_at


@dataclass
class Verdict:
    """Result of the pre-forward check on a single tools/call."""

    allowed: bool
    restriction: Restriction | None = None

    @property
    def message(self) -> str:
        """Phrased for whoever reads it in an agent transcript at 3am.

        Names the rule so nobody has to grep the source to find out why their
        tool stopped working.
        """
        if self.allowed or self.restriction is None:
            return ""
        r = self.restriction
        verb = {
            Action.QUARANTINE_SERVER: f"server '{r.server}' is quarantined",
            Action.BLOCK_TOOL: f"tool '{r.tool or '*'}' is blocked",
            Action.RATE_LIMIT: f"tool '{r.tool or '*'}' is rate-limited",
        }.get(r.action, f"'{r.server}' is restricted")
        detail = f": {r.reason}" if r.reason else ""
        return f"{verb} by Kams policy [{r.rule}]{detail}"


class PolicyEngine:
    def __init__(
        self,
        policy: Policy | None = None,
        *,
        clock: Clock = time.time,
        on_enforce: Callable[[Decision, Restriction], None] | None = None,
        shared: Any | None = None,
    ) -> None:
        self.policy = policy or Policy.permissive()
        self._clock = clock
        self._on_enforce = on_enforce
        # Cross-process standing state. When present, restrictions installed by
        # any other shim or by the SigNoz alert webhook are honoured here too --
        # that is what makes a quarantine fleet-wide rather than per-connection.
        self._shared = shared
        self._restrictions: list[Restriction] = []
        self._rate_hits: dict[tuple[str, str | None, str], deque[float]] = {}

    # ---- evaluation ----------------------------------------------------------

    def evaluate(self, findings: list[Finding]) -> list[Decision]:
        """First matching rule wins, in file order."""
        decisions: list[Decision] = []
        for finding in findings:
            rule = self._first_match(finding)
            if rule is None:
                # Unmatched findings are still observed. Silence from policy is
                # not silence from telemetry.
                continue
            decisions.append(
                Decision(
                    action=rule.action,
                    rule=rule.name,
                    reason=rule.reason or finding.summary,
                    server=finding.server,
                    tool=finding.tool,
                    ttl=rule.ttl,
                    rate=rule.rate,
                    finding=finding,
                )
            )
        return decisions

    def _first_match(self, finding: Finding) -> Rule | None:
        for rule in self.policy.rules:
            try:
                if rule.applies_to(finding):
                    return rule
            except Exception as exc:  # noqa: BLE001 - a bad rule must not break the relay
                log.warning("rule %r failed to evaluate, skipping: %r", rule.name, exc)
        return None

    def apply(self, decisions: list[Decision]) -> list[Restriction]:
        """Install standing restrictions for enforcing decisions."""
        installed: list[Restriction] = []
        now = self._clock()
        for d in decisions:
            if not d.is_enforcing:
                continue
            restriction = Restriction(
                action=d.action,
                server=d.server,
                # A quarantine covers the whole server; other actions are
                # scoped to the tool that triggered them.
                tool=None if d.action is Action.QUARANTINE_SERVER else d.tool,
                rule=d.rule,
                reason=d.reason,
                expires_at=(now + d.ttl) if d.ttl else None,
                created_at=now,
                rate=d.rate,
                origin="reflex",
            )
            self._restrictions.append(restriction)
            installed.append(restriction)
            # Publish so other connections honour it immediately.
            self._publish(restriction, origin="reflex")
            log.warning("enforcing %s on %s [%s]", d.action.value, d.server, d.rule)
            if self._on_enforce:
                try:
                    self._on_enforce(d, restriction)
                except Exception as exc:  # noqa: BLE001
                    log.debug("enforcement callback failed: %r", exc)
        return installed

    # ---- the pre-forward check ----------------------------------------------

    def check(self, server: str, tool: str | None) -> Verdict:
        """Called in the request path. Must stay cheap."""
        self._expire()
        for r in self._all():
            if not _glob(r.server, server):
                continue
            if r.action is Action.QUARANTINE_SERVER:
                return Verdict(allowed=False, restriction=r)
            if r.action is Action.BLOCK_TOOL and tool and _glob(r.tool or "*", tool):
                return Verdict(allowed=False, restriction=r)
            if r.action is Action.RATE_LIMIT and tool and _glob(r.tool or "*", tool):
                parsed = parse_rate(r.rate)
                if parsed is None:
                    continue
                limit, window = parsed
                key = (r.server, r.tool, r.rule)
                hits = self._rate_hits.setdefault(key, deque())
                now = self._clock()
                while hits and hits[0] <= now - window:
                    hits.popleft()
                if len(hits) >= limit:
                    return Verdict(allowed=False, restriction=r)
                hits.append(now)
        return Verdict(allowed=True)

    def _all(self) -> list[Restriction]:
        """In-process restrictions plus anything in shared state.

        Shared state is read through a short-lived cache, so this stays cheap
        enough for the request path. An unreadable state file yields nothing
        rather than raising -- fail open (principle 1).
        """
        out = list(self._restrictions)
        seen = {(r.action.value, r.server, r.tool, r.rule) for r in out}
        if self._shared is None:
            return out
        try:
            for sr in self._shared.active():
                key = (sr.action, sr.server, sr.tool, sr.rule)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Restriction(
                        action=Action(sr.action),
                        server=sr.server,
                        tool=sr.tool,
                        rule=sr.rule,
                        reason=sr.reason,
                        expires_at=sr.expires_at,
                        created_at=sr.created_at,
                        rate=getattr(sr, "rate", None),
                        origin=getattr(sr, "origin", "reflex"),
                    )
                )
        except Exception as exc:  # noqa: BLE001
            log.debug("shared state unavailable: %r", exc)
        return out

    def quarantine(self, server: str, *, rule: str, reason: str, ttl: float | None = None) -> Restriction:
        """Direct entry point for the SigNoz webhook path."""
        now = self._clock()
        r = Restriction(
            action=Action.QUARANTINE_SERVER,
            server=server,
            tool=None,
            rule=rule,
            reason=reason,
            expires_at=(now + ttl) if ttl else None,
            created_at=now,
            origin="signoz",
        )
        self._restrictions.append(r)
        log.warning("quarantined %s [%s]: %s", server, rule, reason)
        return r

    def _publish(self, r: Restriction, *, origin: str) -> None:
        """Best-effort persistence. Never let it break the request path."""
        if self._shared is None:
            return
        try:
            from kams.daemon.state import StoredRestriction

            self._shared.add(
                StoredRestriction(
                    action=r.action.value,
                    server=r.server,
                    tool=r.tool,
                    rule=r.rule,
                    reason=r.reason,
                    created_at=r.created_at,
                    expires_at=r.expires_at,
                    origin=origin,
                    rate=r.rate,
                )
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("could not publish restriction: %r", exc)

    def lift(self, server: str) -> int:
        if self._shared is not None:
            try:
                self._shared.lift(server)
            except Exception as exc:  # noqa: BLE001
                log.debug("could not lift in shared state: %r", exc)
        before = len(self._restrictions)
        self._restrictions = [r for r in self._restrictions if r.server != server]
        return before - len(self._restrictions)

    @property
    def restrictions(self) -> list[Restriction]:
        self._expire()
        return list(self._restrictions)

    def _expire(self) -> None:
        now = self._clock()
        if any(r.expired(now) for r in self._restrictions):
            self._restrictions = [r for r in self._restrictions if not r.expired(now)]


def _glob(pattern: str, value: str) -> bool:
    return pattern == value or fnmatch.fnmatch(value, pattern)


def highest_severity(findings: list[Finding]) -> Severity:
    return max((f.severity for f in findings), default=Severity.INFO)
