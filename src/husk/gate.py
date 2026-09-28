"""
Husk's pre-publish gate.

The point of this module, and the reason it is the piece a skill registry
actually wants: it turns Husk's findings into a single deterministic
pass / warn / fail decision, in milliseconds, offline, with no API cost.
That is the one thing an expensive post-publish AI review structurally
cannot be - a check a skill author (or a registry's own CI) runs BEFORE a
skill is ever published, on every commit, for free.

A finding is not a verdict. `curl | bash` from bun.sh and a hardcoded C2
IP are both "findings", but only one should block a release. The gate
assigns every finding a severity, then applies a policy (which the author
can tune) to decide whether the package passes. The severity mapping is
derived from the same finding text the scanner already emits, so it stays
in lockstep with the detection rules without a parallel taxonomy to
maintain.

Design choices that matter for adoption:
  * Deterministic. Same input -> same decision, every time. A registry can
    gate on it without flakiness.
  * Offline and instant. No network, no LLM, no secrets. Runs in CI on
    every push.
  * Tunable, not take-it-or-leave-it. `.huskpolicy` lets a project set its
    own bar (e.g. "warnings don't block, criticals do") without forking.
  * Honest about confidence. INFO/soft findings never block on their own;
    they are surfaced, not enforced.
"""

import fnmatch
import json
import os
import re

# Severity tiers, most-severe first. The gate blocks at or above the
# policy's threshold.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Map a finding to a severity by matching signature phrases in the finding
# text Husk already produces. Ordered: the first matching pattern wins, so
# put the most specific/severe patterns first. This deliberately mirrors
# the detection modules rather than inventing a second taxonomy.
_SEVERITY_RULES = [
    # --- critical: unambiguous, high-impact malicious behaviour ---
    ("critical", re.compile(
        r"credential-harvesting pattern"
        r"|REASSEMBLE INTO A DANGEROUS PAYLOAD"
        r"|reads '/etc/shadow'|reads '/etc/sudoers'"
        r"|wallet extension.*network-send|queries a browser's internal"
        r"|identity/memory file.*network-send"
        r"|Exfiltration chain detected"
        r"|taint-tracked data flow"
        r"|downloads .* and later executes it"
        r"|persistence payload into a shell startup"
        r"|writes a persistence payload"
        r"|writes to a system-level, root-required persistence"
        r"|sets the SUID/SGID bit"
        r"|Destructive filesystem command targeting the root"
        r"|is actually a ZIP archive despite"
        r"|Loads raw compiled bytecode via marshal"
        r"|redirects a file descriptor to a socket"
        r"|reverse-shell pattern"
        r"|out-of-band interaction/exfiltration testbed"
        r"|captures the entire process.env"
        r"|fetches the cloud instance-metadata endpoint"
        r"|JS/TS taint-tracked data flow.*(?:credential file|entire environment)"
        r"|posts to a fully-specified Discord webhook"
        r"|sends to a Telegram bot endpoint", re.IGNORECASE)),
    # --- high: strong indicators, but context can occasionally be legit ---
    ("high", re.compile(
        r"Pipes a downloaded script directly into a shell"
        r"|downloads a script over unencrypted HTTP"
        r"|targets a bare IP address"
        r"|points at a tunneling-service domain"
        r"|hidden trigger or concealment tied to running a script"
        r"|covert-execution pattern"
        r"|instruction-override language|role-hijack language"
        r"|instructs disabling the agent's own safety"
        r"|overt secrecy language"
        r"|PowerShell (?:encoded|dynamic|downloads)"
        r"|Invoke-Expression|marshal\.loads|types\.CodeType"
        r"|paste-site link|installs a package directly from a raw archive"
        r"|package\.json (?:preinstall|postinstall)"
        r"|shell command substitution reads a credential"
        r"|prose prompt-injection"
        r"|JS/TS taint-tracked data flow", re.IGNORECASE)),
    # --- medium: runtime code-exec / shell primitives, common but risky ---
    ("medium", re.compile(
        r"Uses exec\(\)|Uses eval\(\)|Compiles a string into executable"
        r"|compile\(\) is called with a variable"
        r"|uses shell=True|Direct shell command execution"
        r"|os\.system|subprocess call directly invokes"
        r"|Decodes base64|large base64-like block"
        r"|SQL query built with an f-string"
        r"|bidirectional-override character"
        r"|Ruby: executes a shell|Go: spawns a shell"
        r"|world-writable|elevated privileges|Docker socket", re.IGNORECASE)),
    # --- low: hygiene / worth-a-look, rarely malicious on its own ---
    ("low", re.compile(
        r"named/typed as a path|'while True:' loop"
        r"|logs a variable whose name suggests a credential"
        r"|osascript|unusually long hidden comment"
        r"|performs network.*not declared|allowed-tools frontmatter", re.IGNORECASE)),
]

_SOFT_MARKER = "\u25b8SOFT\u25b8"


def classify_severity(finding):
    """Return the severity string for a single finding line.

    Soft/INFO-marked findings are always 'info'. Findings that begin with
    '  ->' are sub-lines of a parent finding (e.g. the decoded contents of
    a reassembled blob) and inherit 'info' so they never independently
    escalate the gate.
    """
    if finding.startswith(_SOFT_MARKER):
        return "info"
    if finding.lstrip().startswith("->"):
        return "info"
    for severity, pattern in _SEVERITY_RULES:
        if pattern.search(finding):
            return severity
    # An unmatched hard finding is treated as medium: it fired a real rule,
    # we just don't have a specific tier for it. Never silently 'info'.
    return "medium"


DEFAULT_POLICY = {
    # Block the release if any finding is at or above this severity.
    "block_on": "high",
    # Findings below block_on but at or above this are shown as warnings
    # (reported, non-blocking).
    "warn_on": "medium",
    # Rule IDs / finding substrings to ignore entirely (author's call).
    "ignore": [],
    # Author-declared documentation/example paths. Findings whose file path
    # matches one of these globs are demoted to 'info' (reported, never
    # blocking) - for security tools and tutorials whose reference/example
    # files legitimately CONTAIN attack strings as data to detect or teach,
    # not as instructions to the agent. This is deliberately author-declared,
    # not auto-detected: benchmarking showed attackers disguise malware as
    # "security tooling" convincingly enough that auto-demoting files that
    # merely look like scanners would let real malicious packages through.
    # Putting the declaration in the author's own policy file makes it
    # explicit and auditable.
    "example_paths": [],
}


def load_policy(package_path):
    """Read a .huskpolicy JSON file from the package root if present,
    merged over the defaults. Never raises: a malformed policy falls back
    to the default and is reported via the returned 'policy_error'."""
    policy = dict(DEFAULT_POLICY)
    policy_error = None
    path = os.path.join(package_path, ".huskpolicy")
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                user = json.load(fh)
            if not isinstance(user, dict):
                raise ValueError("policy must be a JSON object")
            for key in ("block_on", "warn_on"):
                if key in user:
                    if user[key] not in SEVERITY_ORDER:
                        raise ValueError(f"{key} must be one of {SEVERITY_ORDER}")
                    policy[key] = user[key]
            if "ignore" in user:
                if not isinstance(user["ignore"], list):
                    raise ValueError("ignore must be a list of strings")
                policy["ignore"] = [str(x) for x in user["ignore"]]
            if "example_paths" in user:
                if not isinstance(user["example_paths"], list):
                    raise ValueError("example_paths must be a list of path globs")
                policy["example_paths"] = [str(x) for x in user["example_paths"]]
        except Exception as exc:  # noqa: BLE001 - reported, never fatal
            policy_error = f"{os.path.basename(path)} ignored ({exc}); using defaults"
    return policy, policy_error


_FINDING_PATH_RE = re.compile(r"^'([^']+)'\s*:")


def _finding_in_example_path(finding, example_paths):
    """True if the finding's file path (the leading \'rel/path\': prefix Husk
    emits for package findings) matches one of the author-declared example
    globs."""
    if not example_paths:
        return False
    m = _FINDING_PATH_RE.match(finding.replace(_SOFT_MARKER, ""))
    if not m:
        return False
    rel = m.group(1).replace(os.sep, "/")
    return any(fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(rel, glob.rstrip("/") + "/*")
               for glob in example_paths)


def _at_or_above(severity, threshold):
    return SEVERITY_ORDER.index(severity) <= SEVERITY_ORDER.index(threshold)


def evaluate(findings, policy=None):
    """Turn a flat list of finding strings into a gate decision.

    Returns a dict:
      {
        "decision": "pass" | "warn" | "fail",
        "blocking": [ {finding, severity}, ... ],
        "warnings": [ {finding, severity}, ... ],
        "info":     [ {finding, severity}, ... ],
        "counts":   {critical: n, high: n, ...},
      }

    "pass" = nothing at or above warn_on. "warn" = something in the warn
    band but nothing blocking. "fail" = at least one blocking finding.
    """
    policy = policy or DEFAULT_POLICY
    ignore = policy.get("ignore", [])
    example_paths = policy.get("example_paths", [])
    block_on = policy.get("block_on", "high")
    warn_on = policy.get("warn_on", "medium")

    blocking, warnings, info = [], [], []
    counts = dict.fromkeys(SEVERITY_ORDER, 0)

    for finding in findings:
        if any(ig and ig in finding for ig in ignore):
            continue
        severity = classify_severity(finding)
        if severity != "info" and _finding_in_example_path(finding, example_paths):
            severity = "info"
        counts[severity] += 1
        entry = {"finding": finding.replace(_SOFT_MARKER, "").strip(), "severity": severity}
        if _at_or_above(severity, block_on):
            blocking.append(entry)
        elif _at_or_above(severity, warn_on):
            warnings.append(entry)
        else:
            info.append(entry)

    decision = "fail" if blocking else ("warn" if warnings else "pass")
    return {
        "decision": decision,
        "blocking": blocking,
        "warnings": warnings,
        "info": info,
        "counts": counts,
    }
