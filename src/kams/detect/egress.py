"""What is leaving the process, and to whom.

MCP arguments carry your data off-process into third-party code. This classifies
what is crossing that boundary.

Principle 4 governs every line here: **never log a secret to prove a secret
leaked.** Findings carry the class, a count, the JSON path, and a salted digest
for correlation -- never the value. A detector that copies credentials into your
observability backend has made the problem worse, not visible.

The salt is per-installation and stored beside the lockfile, so digests
correlate locally (same secret seen at two call sites) and mean nothing once the
telemetry leaves the host.

Sensitivity is a property of the (class, destination) pair, not the payload.
Credentials to any unvetted third party is the case with no benign reading;
email addresses to a CRM server is expected and boring. Policy expresses that
pairing; this module only reports what it saw.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kams.detect.base import Finding, FindingKind, Severity

DETECTOR = "egress.sensitive_classes"

# Ordered: the first pattern to match a span wins, so specific credential
# shapes are checked before the generic high-entropy fallback.
_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.CRITICAL),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), Severity.CRITICAL),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"), Severity.CRITICAL),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), Severity.HIGH),
    ("bearer_token", re.compile(r"\b[Bb]earer\s+[A-Za-z0-9._~+/-]{20,}=*"), Severity.HIGH),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"), Severity.MEDIUM),
    ("phone", re.compile(r"(?<![\w.])\+?\d{1,3}[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?![\w.])"), Severity.MEDIUM),
]

# Paths whose *name* implies a secret even when the value looks unremarkable.
_SENSITIVE_KEYS = re.compile(
    r"(?:^|[._-])(?:password|passwd|secret|token|api[._-]?key|auth|credential|private[._-]?key)(?:$|[._-])",
    re.I,
)

_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(digits: str) -> bool:
    """Card-shaped runs are common in ordinary data (ids, timestamps).

    Requiring a Luhn check turns a noisy pattern into a usable signal.
    """
    total, alt = 0, False
    for ch in reversed(digits):
        if not ch.isdigit():
            continue
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0 and len(digits) >= 13


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class Hit:
    cls: str
    path: str
    severity: Severity
    digest: str
    # Where in the string the match sat, so redaction can replace precisely.
    span: tuple[int, int] | None = None


@dataclass
class Scan:
    hits: list[Hit] = field(default_factory=list)

    @property
    def classes(self) -> list[str]:
        return sorted({h.cls for h in self.hits})

    @property
    def severity(self) -> Severity:
        return max((h.severity for h in self.hits), default=Severity.INFO)

    def evidence(self) -> dict[str, Any]:
        """Safe to log by construction: classes, counts, paths, digests."""
        by_class: dict[str, int] = {}
        for h in self.hits:
            by_class[h.cls] = by_class.get(h.cls, 0) + 1
        return {
            "classes": self.classes,
            "counts": by_class,
            "paths": sorted({h.path for h in self.hits})[:20],
            # Truncated digests: enough to correlate the same secret across two
            # call sites, useless for recovering it.
            "digests": sorted({h.digest for h in self.hits})[:20],
        }


class EgressClassifier:
    def __init__(self, salt: str | None = None, *, salt_path: Path | str = ".kams-salt") -> None:
        self._salt = salt or self._load_salt(Path(salt_path))

    @staticmethod
    def _load_salt(path: Path) -> str:
        """Per-installation salt, so digests are meaningless off this host."""
        try:
            if path.exists():
                return path.read_text().strip()
            salt = os.urandom(16).hex()
            path.write_text(salt)
            try:
                path.chmod(0o600)
            except OSError:
                pass
            return salt
        except OSError:
            # Ephemeral fallback. Digests stop correlating across restarts,
            # which is a degraded feature, not a failure (principle 5).
            return os.urandom(16).hex()

    def _digest(self, value: str) -> str:
        return hashlib.sha256((self._salt + value).encode("utf-8")).hexdigest()[:12]

    # ---- scanning ------------------------------------------------------------

    def scan_value(self, value: str, path: str) -> list[Hit]:
        hits: list[Hit] = []
        for cls, pattern, severity in _PATTERNS:
            for m in pattern.finditer(value):
                hits.append(Hit(cls, path, severity, self._digest(m.group()), m.span()))
        for m in _CARD.finditer(value):
            digits = re.sub(r"\D", "", m.group())
            if _luhn(digits):
                hits.append(Hit("card_number", path, Severity.HIGH, self._digest(digits), m.span()))

        if not hits:
            # Only fall back to entropy when nothing specific matched, and only
            # for a whole value that looks like an opaque credential rather than
            # prose. Otherwise this fires on every base64 blob in a document.
            stripped = value.strip()
            if 24 <= len(stripped) <= 200 and " " not in stripped and _entropy(stripped) > 4.2:
                hits.append(Hit("high_entropy_secret", path, Severity.MEDIUM,
                                self._digest(stripped), (0, len(value))))
        return hits

    def scan(self, obj: Any, path: str = "$") -> Scan:
        """Walk a JSON structure, classifying every string leaf."""
        scan = Scan()
        self._walk(obj, path, scan)
        return scan

    def _walk(self, obj: Any, path: str, scan: Scan) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                child = f"{path}.{k}"
                if isinstance(v, str) and _SENSITIVE_KEYS.search(str(k)) and v.strip():
                    # The key name alone is enough. A field called `password`
                    # holding "hunter2" matches no credential pattern, and is
                    # still a credential.
                    scan.hits.append(Hit("named_secret", child, Severity.HIGH, self._digest(v), (0, len(v))))
                    continue
                self._walk(v, child, scan)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._walk(v, f"{path}[{i}]", scan)
        elif isinstance(obj, str):
            scan.hits.extend(self.scan_value(obj, path))

    # ---- findings ------------------------------------------------------------

    def on_tool_call(self, server: str, tool: str, arguments: dict[str, Any]) -> list[Finding]:
        scan = self.scan(arguments, "$.arguments")
        if not scan.hits:
            return []
        return [
            Finding(
                kind=FindingKind.EGRESS_SENSITIVE,
                severity=scan.severity,
                detector=DETECTOR,
                server=server,
                tool=tool,
                summary=(
                    f"{len(scan.hits)} sensitive value(s) of class "
                    f"{', '.join(scan.classes)} about to be sent to '{server}' via '{tool}'"
                ),
                evidence=scan.evidence(),
                confidence=0.9,
            )
        ]


def redact(obj: Any, classifier: EgressClassifier, path: str = "$") -> tuple[Any, int]:
    """Replace sensitive spans with typed placeholders.

    Typed rather than blanked: the model still learns an email was present and
    can reason about it, without receiving the address. Blanking the field
    entirely changes the tool's semantics and tends to make agents retry.
    """
    if isinstance(obj, dict):
        out, n = {}, 0
        for k, v in obj.items():
            if isinstance(v, str) and _SENSITIVE_KEYS.search(str(k)) and v.strip():
                out[k], n = "[kams:redacted:named_secret]", n + 1
                continue
            out[k], c = redact(v, classifier, f"{path}.{k}")
            n += c
        return out, n
    if isinstance(obj, list):
        out_l, n = [], 0
        for i, v in enumerate(obj):
            r, c = redact(v, classifier, f"{path}[{i}]")
            out_l.append(r)
            n += c
        return out_l, n
    if isinstance(obj, str):
        hits = classifier.scan_value(obj, path)
        if not hits:
            return obj, 0
        # Replace right-to-left so earlier spans keep their offsets.
        result = obj
        for h in sorted((h for h in hits if h.span), key=lambda h: h.span[0], reverse=True):
            start, end = h.span
            result = f"{result[:start]}[kams:redacted:{h.cls}]{result[end:]}"
        return result, len(hits)
    return obj, 0
