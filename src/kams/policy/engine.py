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
from collections.abc import Callable
from dataclasses import dataclass, field

from kams.detect.base import Finding, Severity
from kams.policy.model import Action, Policy, Rule

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
    ) -> None:
        self.policy = policy or Policy.permissive()
        self._clock = clock
        self._on_enforce = on_enforce
        self._restrictions: list[Restriction] = []

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
            )
            self._restrictions.append(restriction)
            installed.append(restriction)
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
        for r in self._restrictions:
            if not _glob(r.server, server):
                continue
            if r.action is Action.QUARANTINE_SERVER:
                return Verdict(allowed=False, restriction=r)
            if r.action is Action.BLOCK_TOOL and tool and _glob(r.tool or "*", tool):
                return Verdict(allowed=False, restriction=r)
        return Verdict(allowed=True)

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
        )
        self._restrictions.append(r)
        log.warning("quarantined %s [%s]: %s", server, rule, reason)
        return r

    def lift(self, server: str) -> int:
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
