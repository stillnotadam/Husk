"""Tests for repo context classification (triage buckets, never suppression)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from husk.context_classifier import classify_repo_context  # noqa: E402


def test_security_tool_repo_is_tagged(tmp_path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: scanner\n---\nThis skill detects malicious prompt injection in untrusted text."
    )
    c = classify_repo_context(str(tmp_path))
    assert c["self_identifies_security_tool"] is True
    assert c["triage_bucket"] == "likely-false-positive"


def test_ordinary_skill_is_review_first(tmp_path):
    (tmp_path / "SKILL.md").write_text("---\nname: notes\n---\nOrganizes your meeting notes.")
    c = classify_repo_context(str(tmp_path))
    assert c["self_identifies_security_tool"] is False
    assert c["triage_bucket"] == "review-first"


def test_pentest_readme_is_tagged(tmp_path):
    (tmp_path / "SKILL.md").write_text("---\nname: x\n---\nA helper.")
    (tmp_path / "README.md").write_text("# Red-team toolkit\nFor penetration testing engagements.")
    assert classify_repo_context(str(tmp_path))["self_identifies_security_tool"] is True


def test_classifier_never_raises_on_empty(tmp_path):
    assert classify_repo_context(str(tmp_path))["triage_bucket"] == "review-first"
