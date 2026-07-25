"""Tool-definition drift: the supply-chain detector.

Rejected approach: hash the whole `tools/list` response. Servers legitimately
reorder tools, add tools, and bump versions, so a whole-response hash fires on
every benign change. An alert that fires constantly gets muted, and a muted
alert is worse than no alert.

Actual approach: per-tool digests over a canonicalised (name, description,
schema) triple, with *typed* deltas so severity can track the threat rather than
the diff. A narrowed schema is usually a bug fix. A changed description on a
pinned tool is a rug pull until proven otherwise -- descriptions are injected
verbatim into the model's context, which makes them the poisoning vector.

Threat classes this targets, all documented rather than invented:
  rug pull ............. definition swapped after trust is established
  tool poisoning ....... malicious instructions inside a description
  cross-server shadow .. one server describing behaviour for another's tools
  tool squatting ....... homoglyph or near-miss names
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from kams.detect import injection
from kams.detect.base import Finding, FindingKind, Severity
from kams.detect.baseline import BaselineStore, PinnedTool
from kams.protocol.mcp import ToolDef

DETECTOR_DRIFT = "integrity.definition_drift"
DETECTOR_INJECTION = "integrity.description_injection"
DETECTOR_SQUAT = "integrity.tool_squatting"

# Injection score thresholds. Overridable from policy.yaml; these are the
# defaults the detector ships with.
THRESHOLD_HIGH = 0.55
THRESHOLD_MEDIUM = 0.30


class ChangeClass(str, Enum):
    DESCRIPTION_CHANGED = "DESCRIPTION_CHANGED"
    SCHEMA_WIDENED = "SCHEMA_WIDENED"
    SCHEMA_NARROWED = "SCHEMA_NARROWED"
    SCHEMA_CHANGED = "SCHEMA_CHANGED"
    TOOL_ADDED = "TOOL_ADDED"
    TOOL_REMOVED = "TOOL_REMOVED"


# Base severity per change class, before injection scoring modulates it.
_BASE_SEVERITY: dict[ChangeClass, Severity] = {
    ChangeClass.DESCRIPTION_CHANGED: Severity.HIGH,
    ChangeClass.SCHEMA_WIDENED: Severity.MEDIUM,
    ChangeClass.TOOL_ADDED: Severity.MEDIUM,
    ChangeClass.SCHEMA_CHANGED: Severity.MEDIUM,
    ChangeClass.SCHEMA_NARROWED: Severity.LOW,
    ChangeClass.TOOL_REMOVED: Severity.LOW,
}


@dataclass
class Change:
    change: ChangeClass
    tool: str
    before: PinnedTool | None = None
    after: ToolDef | None = None


def classify_schema(before: dict, after: dict) -> ChangeClass:
    """Widened means more ways in: new properties, or fewer required.

    Widening matters because it enlarges the surface through which data can
    leave -- a new optional `callback_url` parameter is a very different event
    from a tightened type constraint.
    """
    b_props = set((before.get("properties") or {}).keys())
    a_props = set((after.get("properties") or {}).keys())
    b_req = set(before.get("required") or [])
    a_req = set(after.get("required") or [])

    added_props = a_props - b_props
    removed_props = b_props - a_props
    dropped_required = b_req - a_req
    added_required = a_req - b_req

    widened = bool(added_props or dropped_required)
    narrowed = bool(removed_props or added_required)

    if widened and not narrowed:
        return ChangeClass.SCHEMA_WIDENED
    if narrowed and not widened:
        return ChangeClass.SCHEMA_NARROWED
    return ChangeClass.SCHEMA_CHANGED


def diff_tools(baseline: dict[str, PinnedTool], current: list[ToolDef]) -> list[Change]:
    changes: list[Change] = []
    current_by_name = {t.name: t for t in current}

    for name, tool in current_by_name.items():
        prior = baseline.get(name)
        if prior is None:
            changes.append(Change(ChangeClass.TOOL_ADDED, name, after=tool))
            continue
        if prior.digest == tool.digest:
            continue
        if prior.description_digest != tool.description_digest:
            changes.append(Change(ChangeClass.DESCRIPTION_CHANGED, name, before=prior, after=tool))
        if prior.schema_digest != tool.schema_digest:
            changes.append(
                Change(classify_schema(prior.input_schema, tool.input_schema), name, before=prior, after=tool)
            )

    for name, prior in baseline.items():
        if name not in current_by_name:
            changes.append(Change(ChangeClass.TOOL_REMOVED, name, before=prior))

    return changes


class IntegrityDetector:
    """Pure: no I/O beyond the injected baseline store, no clock, no network."""

    def __init__(self, store: BaselineStore, *, threshold_high: float = THRESHOLD_HIGH,
                 threshold_medium: float = THRESHOLD_MEDIUM) -> None:
        self.store = store
        self.threshold_high = threshold_high
        self.threshold_medium = threshold_medium

    def on_tools_list(self, server: str, tools: list[ToolDef]) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_squatting(server, tools))

        baseline = self.store.get(server)
        if baseline is None:
            # First sighting. Record provisionally and score the descriptions as
            # they stand -- a server can arrive already poisoned, so TOFU is not
            # a reason to skip inspection.
            self.store.record_provisional(server, tools)
            findings.extend(self._scan_initial(server, tools))
            return findings

        for change in diff_tools(baseline.tools, tools):
            findings.extend(self._finding_for(server, change, pinned=baseline.pinned))
        return findings

    # ---- individual checks ---------------------------------------------------

    def _scan_initial(self, server: str, tools: list[ToolDef]) -> list[Finding]:
        out: list[Finding] = []
        for tool in tools:
            assessment = injection.score_text(tool.description)
            if assessment.score < self.threshold_medium:
                continue
            out.append(
                Finding(
                    kind=FindingKind.INTEGRITY_INJECTION,
                    severity=self._severity_from_score(assessment.score),
                    detector=DETECTOR_INJECTION,
                    server=server,
                    tool=tool.name,
                    summary=(
                        f"Tool '{tool.name}' was advertised with a description that reads as "
                        f"model-directed instructions ({', '.join(assessment.signal_names)})"
                    ),
                    evidence={"baseline_state": "first_sighting", **assessment.as_evidence()},
                    confidence=min(0.95, assessment.score),
                )
            )
        return out

    def _check_squatting(self, server: str, tools: list[ToolDef]) -> list[Finding]:
        out: list[Finding] = []
        for tool in tools:
            if injection.has_mixed_script(tool.name):
                out.append(
                    Finding(
                        kind=FindingKind.INTEGRITY_INJECTION,
                        severity=Severity.HIGH,
                        detector=DETECTOR_SQUAT,
                        server=server,
                        tool=tool.name,
                        summary=(
                            f"Tool name '{tool.name}' mixes character scripts, which renders "
                            f"identically to an ASCII name -- a homoglyph squatting signature"
                        ),
                        evidence={"tool_name": tool.name, "codepoints": [f"U+{ord(c):04X}" for c in tool.name]},
                        confidence=0.9,
                    )
                )
        return out

    def _finding_for(self, server: str, change: Change, *, pinned: bool) -> list[Finding]:
        base = _BASE_SEVERITY[change.change]
        state = "pinned" if pinned else "provisional"

        # An unpinned baseline was never vouched for, so a change is
        # informational rather than alarming. Pinning is what turns drift into
        # an assertion violation.
        severity = base if pinned else Severity(max(Severity.LOW, base - 1))

        evidence: dict = {"change": change.change.value, "baseline_state": state}
        confidence = 0.99  # the digest comparison itself is exact
        summary = f"Tool '{change.tool}' {change.change.value.replace('_', ' ').lower()} on {state} baseline"

        if change.change is ChangeClass.DESCRIPTION_CHANGED and change.before and change.after:
            assessment = injection.score_delta(change.before.description, change.after.description)
            evidence["injection"] = assessment.as_evidence()
            evidence["description_before"] = change.before.description[:300]
            evidence["description_after"] = change.after.description[:300]

            if assessment.score >= self.threshold_high:
                severity = Severity.CRITICAL if pinned else Severity.HIGH
                summary = (
                    f"Tool '{change.tool}' description changed on a {state} baseline and the new "
                    f"text reads as an injection attempt ({', '.join(assessment.signal_names)})"
                )
            elif assessment.score >= self.threshold_medium:
                severity = max(severity, Severity.HIGH if pinned else Severity.MEDIUM)
                summary = (
                    f"Tool '{change.tool}' description changed on a {state} baseline with "
                    f"suspicious additions ({', '.join(assessment.signal_names)})"
                )
            confidence = max(0.6, assessment.score) if assessment.signals else 0.99

        elif change.change is ChangeClass.SCHEMA_WIDENED and change.before and change.after:
            b = set((change.before.input_schema.get("properties") or {}).keys())
            a = set((change.after.input_schema.get("properties") or {}).keys())
            evidence["added_properties"] = sorted(a - b)
            summary = (
                f"Tool '{change.tool}' schema widened on a {state} baseline "
                f"(new parameters: {', '.join(sorted(a - b)) or 'requirements relaxed'})"
            )

        return [
            Finding(
                kind=FindingKind.INTEGRITY_DRIFT,
                severity=severity,
                detector=DETECTOR_DRIFT,
                server=server,
                tool=change.tool,
                summary=summary,
                evidence=evidence,
                confidence=confidence,
            )
        ]

    def on_result_text(self, server: str, tool: str, texts: list[str]) -> list[Finding]:
        """Scan tool *results*. Injection is not confined to descriptions."""
        out: list[Finding] = []
        for text in texts:
            assessment = injection.score_text(text)
            if assessment.score < self.threshold_high:
                continue
            out.append(
                Finding(
                    kind=FindingKind.INTEGRITY_INJECTION,
                    severity=Severity.HIGH,
                    detector="integrity.result_injection",
                    server=server,
                    tool=tool,
                    summary=(
                        f"Result from '{tool}' contains model-directed instructions "
                        f"({', '.join(assessment.signal_names)})"
                    ),
                    evidence=assessment.as_evidence(),
                    confidence=min(0.95, assessment.score),
                )
            )
        return out

    def _severity_from_score(self, score: float) -> Severity:
        if score >= self.threshold_high:
            return Severity.HIGH
        if score >= self.threshold_medium:
            return Severity.MEDIUM
        return Severity.LOW
