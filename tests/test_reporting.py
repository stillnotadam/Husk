"""
Tests for rule-ID derivation, SARIF output, and finding suppression.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.reporting import (  # noqa: E402
    apply_suppressions,
    derive_rule_id,
    load_suppressions,
    to_sarif,
    write_sarif,
)


def test_same_check_different_instances_gives_same_rule_id():
    f1 = "Line 3: a literal value matching the format of a Stripe API key appears directly in this file ('sk_live_AAAA') - a hardcoded credential"
    f2 = "Line 91: a literal value matching the format of a Stripe API key appears directly in this file ('pk_test_BBBB') - a hardcoded credential"
    assert derive_rule_id(f1) == derive_rule_id(f2)


def test_different_checks_give_different_rule_ids():
    f1 = "Line 3: Uses eval() - runs code built at runtime ('eval(')"
    f2 = "Line 5: Direct shell command execution ('os.system(')"
    assert derive_rule_id(f1) != derive_rule_id(f2)


def test_package_level_prefix_is_stripped_before_deriving():
    f1 = "Line 3: Uses eval() - runs code built at runtime ('eval(')"
    f2 = "'scripts/run.py': Line 12: Uses eval() - runs code built at runtime ('eval(')"
    assert derive_rule_id(f1) == derive_rule_id(f2)


def test_finding_with_no_line_number_still_gets_a_stable_id():
    f = "Exfiltration chain detected: file read (line 2) -> base64 encode (line 3) -> network send (line 5), all within a close window"
    rule_id = derive_rule_id(f)
    assert rule_id and rule_id != "FINDING"


def test_sarif_output_has_valid_top_level_structure():
    findings = ["Line 3: Uses eval() - runs code built at runtime ('eval(')"]
    report = to_sarif(findings, target_path="SKILL.md")
    assert report["version"] == "2.1.0"
    assert "$schema" in report
    assert len(report["runs"]) == 1
    assert report["runs"][0]["tool"]["driver"]["name"] == "Husk"
    assert len(report["runs"][0]["results"]) == 1
    result = report["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "SKILL.md"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_sarif_rule_description_is_stable_not_instance_specific():
    findings = ["Line 3: Uses eval() - runs code built at runtime ('eval(')"]
    report = to_sarif(findings)
    rule_desc = report["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"]
    assert "Line 3" not in rule_desc
    assert "eval(" not in rule_desc or "Uses eval()" in rule_desc


def test_sarif_uses_package_level_path_when_present():
    findings = ["'scripts/bad.py': Line 7: Uses eval() - runs code built at runtime ('eval(')"]
    report = to_sarif(findings, target_path="SHOULD_NOT_BE_USED.md")
    uri = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "scripts/bad.py"


def test_sarif_output_is_json_serializable_end_to_end(tmp_path):
    findings = [
        "Line 3: Uses eval() - runs code built at runtime ('eval(')",
        "Line 9: Direct shell command execution ('os.system(')",
    ]
    out = tmp_path / "report.sarif"
    write_sarif(findings, str(out), target_path="SKILL.md")
    with open(out) as f:
        data = json.load(f)
    assert len(data["runs"][0]["results"]) == 2
    assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 2


def test_load_suppressions_missing_file_is_empty_not_an_error(tmp_path):
    assert load_suppressions(str(tmp_path / "does_not_exist.huskignore")) == set()


def test_load_suppressions_parses_comments_and_blank_lines(tmp_path):
    f = tmp_path / ".huskignore"
    f.write_text("# a comment\n\nSOME_RULE_ID\nANOTHER_RULE_ID  # trailing note\n")
    result = load_suppressions(str(f))
    assert result == {"SOME_RULE_ID", "ANOTHER_RULE_ID"}


def test_apply_suppressions_filters_matching_findings(tmp_path):
    finding = "Line 3: Uses eval() - runs code built at runtime ('eval(')"
    rule_id = derive_rule_id(finding)
    f = tmp_path / ".huskignore"
    f.write_text(f"{rule_id}\n")

    kept, suppressed_count = apply_suppressions([finding], str(f))
    assert kept == []
    assert suppressed_count == 1


def test_apply_suppressions_leaves_unrelated_findings_alone(tmp_path):
    finding = "Line 3: Uses eval() - runs code built at runtime ('eval(')"
    f = tmp_path / ".huskignore"
    f.write_text("SOME_OTHER_RULE_ID\n")

    kept, suppressed_count = apply_suppressions([finding], str(f))
    assert kept == [finding]
    assert suppressed_count == 0
