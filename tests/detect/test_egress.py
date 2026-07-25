"""Egress classification tests.

`TestNeverLeaksSecrets` is the one that matters. Everything else here is
detection quality; that class is the guarantee that Kams does not become the
thing it warns about. It runs every finding's serialised form against the raw
fixtures and asserts none of them survive.
"""

from __future__ import annotations

import json

import pytest

from kams.detect.base import FindingKind, Severity
from kams.detect.egress import EgressClassifier, redact

# Fabricated, correctly-shaped credentials. Not real, but they must never
# appear in a finding, a log line, or a span attribute.
SLACK_TOKEN = "-".join(
    ("xoxb", "123456789012", "1234567890123", "abcdefghijklmnopqrstuvwx")
)

SECRETS = {
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "github_token": "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB",
    "slack_token": SLACK_TOKEN,
    "anthropic_key": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
}


@pytest.fixture
def clf(tmp_path):
    return EgressClassifier(salt_path=tmp_path / ".kams-salt")


class TestCredentialDetection:
    @pytest.mark.parametrize("cls,value", list(SECRETS.items()))
    def test_each_class_detected(self, clf, cls, value):
        findings = clf.on_tool_call("evil-mcp", "save_note", {"note": value})
        assert findings, f"{cls} not detected"
        assert cls in findings[0].evidence["classes"]
        assert findings[0].severity >= Severity.HIGH

    def test_named_secret_field_without_a_matching_pattern(self, clf):
        """A field called `password` holding "hunter2" matches no credential
        pattern and is still a credential."""
        findings = clf.on_tool_call("mcp", "login", {"password": "hunter2"})
        assert findings
        assert "named_secret" in findings[0].evidence["classes"]

    def test_nested_arguments_are_walked(self, clf):
        findings = clf.on_tool_call("mcp", "t", {"cfg": {"deep": [{"key": SECRETS["aws_key"]}]}})
        assert findings
        assert any("cfg" in p for p in findings[0].evidence["paths"])

    def test_card_number_requires_luhn(self, clf):
        """Card-shaped runs are common in ordinary data; Luhn makes it usable."""
        valid = clf.on_tool_call("mcp", "t", {"v": "4111111111111111"})
        assert valid and "card_number" in valid[0].evidence["classes"]
        # Same shape, fails Luhn — an id or a timestamp, not a card.
        assert clf.on_tool_call("mcp", "t", {"v": "1234567812345678"}) == []


class TestNoFalsePositives:
    @pytest.mark.parametrize("value", [
        "Read the file at /etc/hosts and summarise it",
        "SELECT * FROM users WHERE created_at > '2026-01-01'",
        "The quick brown fox jumps over the lazy dog",
        "https://docs.example.com/guide/getting-started",
        "commit 3f2a1b9c4d5e6f708192a3b4c5d6e7f8",  # hex, but short and prose-adjacent
        "2026-07-25T16:10:42.242218984Z",
    ])
    def test_ordinary_arguments_stay_quiet(self, clf, value):
        assert clf.on_tool_call("mcp", "t", {"input": value}) == [], value

    def test_prose_with_spaces_is_not_a_secret(self, clf):
        """The entropy fallback must not fire on natural language."""
        assert clf.on_tool_call("mcp", "t", {"x": "correct horse battery staple indeed"}) == []


class TestNeverLeaksSecrets:
    """Principle 4: never log a secret to prove a secret leaked."""

    @pytest.mark.parametrize("cls,value", list(SECRETS.items()))
    def test_finding_never_contains_the_value(self, clf, cls, value):
        findings = clf.on_tool_call("evil-mcp", "exfil", {"note": value})
        assert findings
        blob = json.dumps(
            {
                "summary": findings[0].summary,
                "evidence": findings[0].evidence,
                "attributes": {k: str(v) for k, v in findings[0].to_attributes().items()},
            }
        )
        assert value not in blob
        # Also reject any substantial fragment: a truncated secret is still one.
        for chunk_start in range(0, max(1, len(value) - 16), 8):
            assert value[chunk_start:chunk_start + 16] not in blob

    def test_digest_is_stable_for_correlation(self, clf):
        """Same secret at two call sites must produce the same digest."""
        a = clf.on_tool_call("mcp", "x", {"k": SECRETS["aws_key"]})[0]
        b = clf.on_tool_call("mcp", "y", {"other": SECRETS["aws_key"]})[0]
        assert a.evidence["digests"] == b.evidence["digests"]

    def test_digest_differs_across_installations(self, tmp_path):
        """Salted per installation, so digests are meaningless off this host."""
        one = EgressClassifier(salt="salt-one")
        two = EgressClassifier(salt="salt-two")
        d1 = one.on_tool_call("m", "t", {"k": SECRETS["aws_key"]})[0].evidence["digests"]
        d2 = two.on_tool_call("m", "t", {"k": SECRETS["aws_key"]})[0].evidence["digests"]
        assert d1 != d2


class TestRedaction:
    def test_replaces_with_typed_placeholder(self, clf):
        cleaned, count = redact({"note": f"key is {SECRETS['aws_key']} ok"}, clf)
        assert count == 1
        assert SECRETS["aws_key"] not in json.dumps(cleaned)
        # Typed, not blanked: the model still knows what kind of thing was there.
        assert "[kams:redacted:aws_key]" in cleaned["note"]

    def test_preserves_surrounding_text(self, clf):
        cleaned, _ = redact({"note": f"before {SECRETS['aws_key']} after"}, clf)
        assert cleaned["note"].startswith("before ")
        assert cleaned["note"].endswith(" after")

    def test_multiple_hits_in_one_string(self, clf):
        text = f"{SECRETS['aws_key']} and {SECRETS['github_token']}"
        cleaned, count = redact({"n": text}, clf)
        assert count == 2
        assert SECRETS["aws_key"] not in cleaned["n"]
        assert SECRETS["github_token"] not in cleaned["n"]

    def test_named_secret_field_replaced_wholesale(self, clf):
        cleaned, count = redact({"password": "hunter2"}, clf)
        assert count == 1
        assert cleaned["password"] == "[kams:redacted:named_secret]"

    def test_clean_payload_is_returned_unchanged(self, clf):
        original = {"path": "/etc/hosts", "limit": 10, "nested": {"ok": True}}
        cleaned, count = redact(original, clf)
        assert count == 0
        assert cleaned == original


class TestFindingShape:
    def test_kind_and_classes_match_policy_expectations(self, clf):
        """policy.yaml matches on kind=EGRESS_SENSITIVE and these class names.

        This test exists because those rules were dead until this detector
        landed -- it asserts the contract between detector and policy holds.
        """
        f = clf.on_tool_call("random-mcp", "t", {"k": SECRETS["aws_key"]})[0]
        assert f.kind is FindingKind.EGRESS_SENSITIVE
        assert "aws_key" in f.evidence["classes"]
        assert f.detector == "egress.sensitive_classes"
