"""Scoring text that a server sends toward the model.

Applies to tool descriptions AND tool results. Confining this to descriptions
would miss the class CyberArk documented in "Poison everywhere: no output from
your MCP server is safe" -- any server output reaches the context, so any server
output is an injection surface.

Everything here is deterministic. No LLM, no network, no clock. That is a
requirement, not an accident (principle 2): enforcement must be reproducible in
a unit test and must not be derailable by a model having an off moment. The LLM
judge runs later, in kamsd, and only annotates.

Signals are combined with noisy-OR rather than summed, so one damning signal
(invisible control characters in a human-authored description) carries a verdict
without needing corroboration.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from kams.detect.base import noisy_or

# --- invisible / control characters ------------------------------------------
# Enumerated explicitly rather than by unicode category: the set is small, and a
# reader auditing a security detector should be able to see exactly what is
# caught without cross-referencing a category table.
_INVISIBLE_RANGES: list[tuple[int, int, str]] = [
    (0x00AD, 0x00AD, "soft-hyphen"),
    (0x200B, 0x200F, "zero-width / directional mark"),
    (0x202A, 0x202E, "bidi embedding or override"),
    (0x2060, 0x2064, "word joiner / invisible operator"),
    (0x2066, 0x2069, "bidi isolate"),
    (0xFEFF, 0xFEFF, "zero-width no-break space"),
    # Unicode tag characters: a known vehicle for smuggling instructions that
    # are invisible in every normal renderer but reach the model verbatim.
    (0xE0000, 0xE007F, "unicode tag character"),
]

# --- lexical patterns ---------------------------------------------------------
# Case-insensitive. Tuned to be specific: generic imperatives ("use this tool
# to read a file") are normal tool-description prose and must not fire.

_MODEL_DIRECTED = [
    (r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\b", "override of prior instructions"),
    (r"\bdisregard\s+(the\s+)?(previous|prior|above|all)\b", "override of prior instructions"),
    (r"\b(do\s?not|don'?t|never)\s+(tell|inform|mention|reveal|show|display)\b.{0,40}\b(user|human)\b", "concealment from the user"),
    (r"\bwithout\s+(telling|informing|notifying|alerting)\b", "concealment from the user"),
    (r"\byou\s+must\s+(always|first|never)\b", "hard directive at the model"),
    (r"\b(always|first)\s+call\b", "forced tool ordering"),
    (r"\bbefore\s+(using|calling|invoking)\s+(any|this|the)\b", "forced tool ordering"),
    (r"\bas\s+an\s+ai\b|\bas\s+the\s+assistant\b", "addresses the model directly"),
    (r"\bdo\s+not\s+(summar|paraphras|explain)", "suppresses user-visible explanation"),
]

# Structured directive blocks. The Invariant Labs tool-poisoning demonstration
# used exactly this shape -- an <IMPORTANT> block inside a tool description.
_INSTRUCTION_BLOCK = [
    (r"<\s*(important|system|instructions?|secret|admin)\s*>", "pseudo-tag instruction block"),
    (r"\[\s*(important|system|instruction|note to (ai|assistant|model))\s*\]", "bracketed directive block"),
    (r"^\s*(important|note to (the )?(ai|assistant|model))\s*:", "directive preamble"),
    (r"\bsidenote\b", "sidenote framing (documented poisoning idiom)"),
]

_EXFILTRATION = [
    (r"\b(send|forward|post|upload|transmit|exfiltrate|report)\b.{0,50}\b(to|at)\b.{0,30}(https?://|@)", "send-to-destination"),
    (r"\b(include|append|attach)\b.{0,40}\b(in|to)\s+the\s+(url|query|request|parameter)", "smuggle into an outbound field"),
    (r"\bread\b.{0,40}\b(~/|/etc/|\.ssh|\.env|credential|secret|token|password)", "reads a sensitive path"),
    (r"\bpass\s+(it|them|the\s+\w+)\s+(as|to)\b", "relay of retrieved content"),
]

_CROSS_TOOL = [
    (r"\bwhen\s+(using|calling)\s+the\s+\w+\s+tool\b", "instructs behaviour for another tool"),
    (r"\b(other|another|any\s+other)\s+tools?\b", "references other tools"),
    (r"\binstead\s+of\s+(using|calling)\b", "redirects away from another tool"),
]

_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_RUN = re.compile(r"\b(?:[0-9a-fA-F]{2}){20,}\b")


@dataclass
class Signal:
    name: str
    score: float
    weight: float
    detail: str
    # Short, capped excerpt. Safe here: descriptions and results are server
    # metadata, not user secrets. Egress detectors follow the opposite rule.
    excerpt: str = ""


@dataclass
class Assessment:
    score: float
    signals: list[Signal] = field(default_factory=list)

    @property
    def signal_names(self) -> list[str]:
        return [s.name for s in self.signals]

    def as_evidence(self) -> dict:
        return {
            "score": round(self.score, 3),
            "signals": [
                {
                    "name": s.name,
                    "detail": s.detail,
                    "score": round(s.score, 3),
                    **({"excerpt": s.excerpt} if s.excerpt else {}),
                }
                for s in self.signals
            ],
        }


def _excerpt(text: str, match: re.Match, width: int = 60) -> str:
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    frag = text[start:end].replace("\n", " ")
    return ("…" if start else "") + frag + ("…" if end < len(text) else "")


def find_invisible(text: str) -> list[tuple[str, int, str]]:
    """Return (codepoint, offset, why) for every invisible/control char found."""
    out = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        for lo, hi, why in _INVISIBLE_RANGES:
            if lo <= cp <= hi:
                out.append((f"U+{cp:04X}", i, why))
                break
    return out


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _lexical(text: str, patterns: list[tuple[str, str]], name: str, weight: float) -> Signal | None:
    hits: list[tuple[str, re.Match]] = []
    for pattern, detail in patterns:
        if m := re.search(pattern, text, re.I | re.M):
            hits.append((detail, m))
    if not hits:
        return None
    # More independent matches means more confidence, with diminishing returns.
    score = min(1.0, 0.6 + 0.2 * (len(hits) - 1))
    detail, match = hits[0]
    if len(hits) > 1:
        detail = f"{detail} (+{len(hits) - 1} more)"
    return Signal(name=name, score=score, weight=weight, detail=detail, excerpt=_excerpt(text, match))


def score_text(text: str) -> Assessment:
    """Score a single piece of server-originated text."""
    if not text or not text.strip():
        return Assessment(score=0.0)

    signals: list[Signal] = []

    # Invisible characters in human-authored prose are near-conclusive: there is
    # no legitimate reason for a bidi override or a unicode tag character to
    # appear in a tool description.
    if invisible := find_invisible(text):
        kinds = sorted({why for _, _, why in invisible})
        signals.append(
            Signal(
                name="invisible_characters",
                score=1.0,
                weight=0.95,
                detail=f"{len(invisible)} invisible character(s): {', '.join(kinds)}",
                excerpt=", ".join(cp for cp, _, _ in invisible[:8]),
            )
        )

    for sig in (
        _lexical(text, _MODEL_DIRECTED, "model_directed_imperative", 0.80),
        _lexical(text, _INSTRUCTION_BLOCK, "instruction_block", 0.75),
        _lexical(text, _EXFILTRATION, "exfiltration_shape", 0.65),
        _lexical(text, _CROSS_TOOL, "cross_tool_reference", 0.45),
    ):
        if sig:
            signals.append(sig)

    # Encoded blobs: long, high-entropy runs that a description has no reason to
    # carry. Entropy gate keeps repetitive filler ("aaaa...") from firing.
    for pattern, label in ((_B64_RUN, "base64"), (_HEX_RUN, "hex")):
        if m := pattern.search(text):
            if _shannon_entropy(m.group()) > 3.5:
                signals.append(
                    Signal(
                        name="encoded_blob",
                        score=0.8,
                        weight=0.5,
                        detail=f"high-entropy {label} run ({len(m.group())} chars)",
                        excerpt=m.group()[:40] + "…",
                    )
                )
                break

    return Assessment(score=noisy_or([(s.weight, s.score) for s in signals]), signals=signals)


def score_delta(before: str, after: str) -> Assessment:
    """Score a description change, weighting what the change ADDED.

    Scoring `after` wholesale would flag a description that has always contained
    a URL. What matters on a rug pull is what appeared. So signals run over the
    added text, with the full text used only as fallback context.
    """
    added = _added_text(before, after)
    assessment = score_text(added) if added.strip() else Assessment(score=0.0)

    # Magnitude is context, not evidence of malice on its own -- hence the low
    # weight. A wholesale rewrite of a pinned description is worth noting even
    # when the new text trips no lexical pattern.
    ratio = SequenceMatcher(None, before, after).ratio()
    if ratio < 0.75:
        magnitude = Signal(
            name="rewrite_magnitude",
            score=min(1.0, (0.75 - ratio) / 0.75),
            weight=0.35,
            detail=f"description {int((1 - ratio) * 100)}% rewritten",
        )
        assessment.signals.append(magnitude)
        assessment.score = noisy_or([(s.weight, s.score) for s in assessment.signals])

    return assessment


def _added_text(before: str, after: str) -> str:
    matcher = SequenceMatcher(None, before, after)
    return " ".join(
        after[j1:j2] for tag, _, _, j1, j2 in matcher.get_opcodes() if tag in ("insert", "replace")
    )


def has_mixed_script(name: str) -> bool:
    """Detect homoglyph tool-squatting: one identifier spanning multiple scripts.

    `pаyment` with a Cyrillic 'а' renders identically to `payment` and is a
    documented squatting technique.
    """
    scripts = set()
    for ch in name:
        if not ch.isalpha():
            continue
        try:
            block = unicodedata.name(ch).split()[0]
        except ValueError:
            continue
        scripts.add(block)
    return len(scripts) > 1
