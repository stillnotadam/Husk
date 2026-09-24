"""
Husk - stable rule IDs, SARIF output, and finding suppression.

WHY THIS EXISTS
----------------
Two real, practical gaps found by comparing against what a tool needs
to actually live in someone's CI pipeline, not just run once from a
terminal:

1. No SARIF output. GitHub Code Scanning, and most CI security
   tooling generally, expects results in SARIF (Static Analysis
   Results Interchange Format), a standard, documented JSON schema.
   Without it, findings only ever show up in a raw text log, not in a
   PR's own "Files changed" view or a repo's Security tab.

2. No suppression mechanism. At Husk's real, honestly-measured
   false-positive rate (see BENCHMARK.md), running the same scan
   repeatedly on the same codebase without a way to say "reviewed,
   this one's fine" is exactly the kind of friction that gets a
   security tool uninstalled from CI, not because the finding was
   wrong, but because there was no way to move past it.

Both need the same missing piece first: a STABLE identifier per
finding type. Husk's 42 detection functions were never built with
explicit rule IDs (each just appends a formatted string to a shared
list), and retrofitting all 42 individually would touch nearly the
whole scanner. Instead, this module derives a stable ID from each
finding's own fixed description text - the part that's constant
across every instance of that check, stripping only the dynamic
line number and the specific matched value. Honest limitation: if a
finding's description text is reworded later, its derived ID changes
too - this is a pragmatic, working solution, not a substitute for
real per-module IDs, and is documented as such rather than presented
as more precise than it is.
"""

import hashlib
import json
import re


def derive_rule_id(finding_text):
    """
    Extracts the stable, descriptive core of a finding string (the
    part that's constant across every instance of that specific
    check) and turns it into a short, readable, deterministic ID.

    Handles the shapes Husk's findings actually use:
    - "Line N: <description> ('<matched value>') - <explanation>"
    - "'<relative/path>': Line N: <description> (...)"
    - "Lines near N: <description>"
    - Findings with no line number at all (e.g. the exfiltration-
      chain finding, which describes a whole sequence)

    Returns a short uppercase slug, e.g. "USES_EVAL_RUNS_CODE_BUILT".
    Two genuinely different findings could theoretically collide to
    the same slug if their first few words happen to match - real,
    stated risk, not hidden - so the ID is also suffixed with a short
    hash of the full stable text to keep collisions practically
    impossible while staying human-readable.
    """
    text = finding_text

    # Strip a package-level "'path/to/file': " prefix, if present.
    package_prefix = re.match(r"^'[^']+':\s*", text)
    if package_prefix:
        text = text[package_prefix.end():]

    # Strip "Line N: " / "Lines near N: " / "Exfiltration chain
    # detected: " style openers - whatever comes before the first
    # colon-space that isn't itself part of the description.
    line_prefix = re.match(r"^(Line\s+\d+|Lines?\s+near\s+\d+):\s*", text)
    if line_prefix:
        text = text[line_prefix.end():]

    # Cut at the first occurrence of a matched-value parenthetical
    # ("('actual matched text')") or a " - " explanation separator,
    # whichever comes first - both mark the end of the stable,
    # descriptive part and the start of the instance-specific part.
    cut_points = [m.start() for m in re.finditer(r"\s\('|\s-\s", text)]
    if cut_points:
        text = text[:min(cut_points)]

    words = re.findall(r"[A-Za-z0-9]+", text.upper())
    slug = "_".join(words[:5]) if words else "FINDING"
    short_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()[:6].upper()
    return f"{slug}_{short_hash}"


def to_sarif(findings, tool_name="Husk", tool_version="1.0.1",
             tool_uri="https://github.com/ctrl-adam/Husk", target_path=None):
    """
    Converts a flat list of Husk finding strings into a SARIF 2.1.0
    report, ready to write to a .sarif file for GitHub Code Scanning
    or any other SARIF-consuming tool.

    Package-level findings ("'relative/path': Line N: ...") get a
    real file location; single-file findings ("Line N: ...") are
    attributed to target_path if given, otherwise left file-less
    (SARIF allows a result with no physicalLocation, though most
    consumers show it less usefully without one).
    """
    results = []
    rules_seen = {}

    def _stable_description(finding_text):
        """The same stripping derive_rule_id does, but returning the
        readable text itself rather than a slug - for the rule's own
        description, which should describe the CHECK, not one
        specific instance's line number and matched value."""
        text = finding_text
        package_prefix = re.match(r"^'[^']+':\s*", text)
        if package_prefix:
            text = text[package_prefix.end():]
        line_prefix = re.match(r"^(Line\s+\d+|Lines?\s+near\s+\d+):\s*", text)
        if line_prefix:
            text = text[line_prefix.end():]
        cut_points = [m.start() for m in re.finditer(r"\s\('|\s-\s", text)]
        if cut_points:
            text = text[:min(cut_points)]
        return text.strip() or "Husk finding"

    for finding in findings:
        rule_id = derive_rule_id(finding)
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": _stable_description(finding)},
                "defaultConfiguration": {"level": "warning"},
            }

        file_path = target_path
        package_match = re.match(r"^'([^']+)':\s*", finding)
        if package_match:
            file_path = package_match.group(1)

        line_match = re.search(r"Line\s+(\d+)", finding)
        line_num = int(line_match.group(1)) if line_match else 1

        result = {
            "ruleId": rule_id,
            "level": "warning",
            "message": {"text": finding},
        }
        if file_path:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": max(1, line_num)},
                }
            }]
        results.append(result)

    run = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": tool_uri,
                "rules": list(rules_seen.values()),
            }
        },
        "results": results,
    }

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [run],
    }


def write_sarif(findings, output_path, **kwargs):
    """Convenience wrapper: builds the SARIF report and writes it."""
    report = to_sarif(findings, **kwargs)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return report


def load_suppressions(suppress_path):
    """
    Loads a .huskignore file: one rule ID per line, '#' comments and
    blank lines skipped. Returns a set of suppressed rule IDs.
    Missing file is not an error - an empty suppression set, since
    having no suppressions configured is the normal default state.
    """
    suppressed = set()
    try:
        with open(suppress_path, encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                suppressed.add(line.split()[0])
    except FileNotFoundError:
        pass
    return suppressed


def apply_suppressions(findings, suppress_path):
    """
    Filters a findings list, dropping any whose derived rule ID
    appears in the suppression file. Returns (kept, suppressed_count)
    so callers can report how many were silenced, not just silently
    drop them without a trace.
    """
    suppressed_ids = load_suppressions(suppress_path)
    if not suppressed_ids:
        return findings, 0
    kept = []
    suppressed_count = 0
    for finding in findings:
        if derive_rule_id(finding) in suppressed_ids:
            suppressed_count += 1
        else:
            kept.append(finding)
    return kept, suppressed_count
