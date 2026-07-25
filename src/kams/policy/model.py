"""Policy: declarative rules mapping findings to actions.

Kept deliberately dumb. The engine matches on finding fields and never knows how
a finding was produced, which is what lets a new detector ship without touching
policy code — and lets an operator change what Kams *does* about a threat
without changing Kams.

Ordering is file order, first match wins. That is more predictable than a
specificity or priority score: the file reads top to bottom exactly the way it
evaluates, so an operator can reason about it without running it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from kams.detect.base import FindingKind, Severity


class Action(str, Enum):
    ALLOW = "allow"
    # Record only. The finding is still emitted; nothing is enforced.
    WARN = "warn"
    REDACT_ARGS = "redact_args"
    RATE_LIMIT = "rate_limit"
    BLOCK_TOOL = "block_tool"
    QUARANTINE_SERVER = "quarantine_server"

    @property
    def is_enforcing(self) -> bool:
        return self not in (Action.ALLOW, Action.WARN)


_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd])?\s*$", re.I)
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_RATE = re.compile(r"^\s*(\d+)\s*/\s*(s|sec|second|m|min|minute|h|hour)\s*$", re.I)
_RATE_WINDOWS = {
    "s": 1.0, "sec": 1.0, "second": 1.0,
    "m": 60.0, "min": 60.0, "minute": 60.0,
    "h": 3600.0, "hour": 3600.0,
}


def parse_duration(value: str | int | float | None) -> float | None:
    """Accept `30s`, `15m`, `1h`, `7d`, or a bare number of seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    m = _DURATION.match(str(value))
    if not m:
        raise ValueError(f"bad duration: {value!r}")
    return float(m.group(1)) * _UNITS.get((m.group(2) or "s").lower(), 1)


def parse_rate(value: str | None) -> tuple[int, float] | None:
    """Parse policy rates such as ``4/min`` into (limit, window_seconds)."""
    if value is None:
        return None
    match = _RATE.match(str(value))
    if not match or int(match.group(1)) <= 0:
        raise ValueError(f"bad rate: {value!r}")
    return int(match.group(1)), _RATE_WINDOWS[match.group(2).lower()]


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


@dataclass
class Matcher:
    """A set of conditions ANDed together. Empty matcher matches everything."""

    kind: list[str] = field(default_factory=list)
    detector: list[str] = field(default_factory=list)
    severity: list[Severity] = field(default_factory=list)
    min_severity: Severity | None = None
    server: list[str] = field(default_factory=list)
    tool: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    min_confidence: float | None = None

    @classmethod
    def parse(cls, raw: dict[str, Any] | None) -> Matcher:
        raw = raw or {}
        sev = raw.get("severity")
        return cls(
            kind=[k.upper() for k in _as_list(raw.get("kind"))],
            detector=_as_list(raw.get("detector")),
            severity=[Severity.parse(s) for s in _as_list(sev)] if sev is not None else [],
            min_severity=Severity.parse(raw["min_severity"]) if raw.get("min_severity") else None,
            server=_as_list(raw.get("server")),
            tool=_as_list(raw.get("tool")),
            classes=_as_list(raw.get("classes")),
            min_confidence=float(raw["min_confidence"]) if raw.get("min_confidence") is not None else None,
        )

    @property
    def is_empty(self) -> bool:
        return not any(
            [self.kind, self.detector, self.severity, self.min_severity,
             self.server, self.tool, self.classes, self.min_confidence is not None]
        )

    def matches(self, finding) -> bool:
        if self.kind and finding.kind.value not in self.kind:
            return False
        if self.detector and finding.detector not in self.detector:
            return False
        if self.severity and finding.severity not in self.severity:
            return False
        if self.min_severity is not None and finding.severity < self.min_severity:
            return False
        if self.server and finding.server not in self.server:
            return False
        if self.tool and (finding.tool or "") not in self.tool:
            return False
        if self.min_confidence is not None and finding.confidence < self.min_confidence:
            return False
        if self.classes:
            found = set(finding.evidence.get("classes") or [])
            if not found & set(self.classes):
                return False
        return True


@dataclass
class Rule:
    name: str
    action: Action
    match: Matcher = field(default_factory=Matcher)
    unless: Matcher | None = None
    ttl: float | None = None
    rate: str | None = None
    reason: str = ""

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> Rule:
        if "name" not in raw:
            raise ValueError("every rule needs a name — it is what enforcement spans report")
        try:
            action = Action(str(raw.get("action", "warn")).lower())
        except ValueError as exc:
            raise ValueError(f"rule {raw['name']!r}: unknown action {raw.get('action')!r}") from exc

        unless_raw = raw.get("unless")
        rate = raw.get("rate")
        if action is Action.RATE_LIMIT and parse_rate(rate) is None:
            raise ValueError(f"bad rate: {rate!r}")
        return cls(
            name=str(raw["name"]),
            action=action,
            match=Matcher.parse(raw.get("match")),
            unless=Matcher.parse(unless_raw) if unless_raw else None,
            ttl=parse_duration(raw.get("ttl")),
            rate=str(rate) if rate is not None else None,
            reason=str(raw.get("reason", "")),
        )

    def applies_to(self, finding) -> bool:
        if not self.match.matches(finding):
            return False
        # An empty `unless` would exclude everything, which is never what an
        # operator means when they write `unless: {}`.
        if self.unless is not None and not self.unless.is_empty and self.unless.matches(finding):
            return False
        return True


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)
    default_action: Action = Action.ALLOW
    fail_open: bool = True
    thresholds: dict[str, dict[str, float]] = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> Policy:
        defaults = raw.get("defaults") or {}
        return cls(
            rules=[Rule.parse(r) for r in (raw.get("rules") or [])],
            default_action=Action(str(defaults.get("action", "allow")).lower()),
            fail_open=str(defaults.get("fail_mode", "open")).lower() != "closed",
            thresholds=raw.get("thresholds") or {},
        )

    @classmethod
    def load(cls, path: Path | str) -> Policy:
        import yaml

        return cls.parse(yaml.safe_load(Path(path).read_text()) or {})

    @classmethod
    def permissive(cls) -> Policy:
        """No rules. Kams is still fully useful in pure-observation mode —
        observation and enforcement are separate concerns."""
        return cls()
