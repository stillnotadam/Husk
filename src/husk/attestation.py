"""
Husk attestation: a deterministic, verifiable record of a skill's scan.

This is the capability an AI review structurally cannot provide. An LLM gives
a different answer on rerun and cannot prove what it looked at. Husk produces
a signed, reproducible attestation - "this exact skill content, scanned by
this exact ruleset, produced this exact verdict" - in the real in-toto
Statement v1 / SLSA Verification Summary format that supply-chain tooling
(Sigstore, in-toto, GitHub attestations, policy engines) already understands.

Two properties make it valuable and independent of any single marketplace:

  * Deterministic. The same skill content and the same Husk version produce a
    byte-identical attestation. Anyone can re-run `husk attest` and get the
    same digest, or `husk verify-attestation` to confirm a claimed verdict
    matches the skill they actually hold. No trust in Husk's servers, no
    network, no API.

  * Content-bound. The subject digest is a SHA-256 over the skill's canonical
    manifest (every scannable file, sorted, hashed). Change one byte of one
    file and the digest changes, so an attestation can never silently apply to
    a tampered skill.

The optional signing layer (Sigstore keyless, if `sigstore` is installed) wraps
the statement in a DSSE envelope so a third party can verify WHO attested it,
not just what it says. Signing is optional; the deterministic statement is the
core value and works with zero dependencies.
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from . import __version__ as _pkg_version
from .gate import DEFAULT_POLICY, evaluate
from .package_scanner import PACKAGE_SCANNABLE_EXTENSIONS
from .reporting import derive_rule_id

# The in-toto Statement type and our predicate type. The Statement type is the
# real, stable v1 identifier; the predicate type is Husk's own namespace under
# the project's canonical URL.
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
HUSK_PREDICATE_TYPE = "https://husk.zone/attestation/skill-scan/v1"

HUSK_VERSION = _pkg_version


def _canonical_manifest(package_path):
    """A deterministic list of (relative_posix_path, sha256) for every
    scannable file in the package, sorted by path. This is what the subject
    digest is computed over, so the attestation is bound to the exact bytes
    of the skill, independent of filesystem order or absolute location."""
    entries = []
    for dirpath, _dirs, filenames in os.walk(package_path):
        for name in sorted(filenames):
            if not name.lower().endswith(PACKAGE_SCANNABLE_EXTENSIONS):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, package_path).replace(os.sep, "/")
            try:
                with open(full, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
            except OSError:
                continue
            entries.append((rel, digest))
    entries.sort()
    return entries


def compute_subject_digest(package_path):
    """SHA-256 over the canonical manifest - a single stable identifier for
    the skill's content. Two checkouts of the same skill on different machines
    yield the same digest; any file change yields a different one."""
    manifest = _canonical_manifest(package_path)
    blob = "\n".join(f"{rel} {digest}" for rel, digest in manifest).encode("utf-8")
    return hashlib.sha256(blob).hexdigest(), manifest


def compute_ruleset_digest():
    """A digest of the exact detection ruleset that produced a verdict, so an
    attestation records not just the verdict but the code that reached it. Two
    Husk versions with different rules produce different ruleset digests, which
    is what lets a consumer say 'this was scanned by a ruleset I trust'."""
    here = os.path.dirname(os.path.abspath(__file__))
    rule_files = ["skill_scanner.py", "package_scanner.py", "taint_analysis.py",
                  "pickle_scanner.py", "gate.py"]
    hasher = hashlib.sha256()
    for name in rule_files:
        path = os.path.join(here, name)
        try:
            with open(path, "rb") as fh:
                hasher.update(name.encode("utf-8"))
                hasher.update(hasher.copy().digest())  # domain-separate
                hasher.update(hashlib.sha256(fh.read()).digest())
        except OSError:
            continue
    return hasher.hexdigest()


def build_attestation(package_path, findings, policy=None, skill_ref=None,
                      timestamp=None):
    """
    Build an in-toto Statement v1 attesting to a Husk scan of a skill.

    Deterministic except for the `verifiedAt` timestamp: pass a fixed
    `timestamp` (or set it to None to omit) to get byte-identical output for
    the same skill + ruleset, which is what makes the attestation
    independently reproducible. The verdict, digests, and rule findings never
    depend on wall-clock time.

    Returns the Statement as a dict, ready to json.dump.
    """
    policy = policy or DEFAULT_POLICY
    subject_digest, manifest = compute_subject_digest(package_path)
    ruleset_digest = compute_ruleset_digest()
    result = evaluate(findings, policy)

    # A stable, sorted list of the rules that fired - by rule id, not the full
    # finding text, so the attestation is compact and comparable across scans.
    fired_rules = sorted({derive_rule_id(f): None for f in findings})

    subject_name = skill_ref or os.path.basename(os.path.abspath(package_path)) or "skill"

    predicate = {
        "verdict": result["decision"].upper(),        # PASS / WARN / FAIL
        "verificationResult": "PASSED" if result["decision"] != "fail" else "FAILED",
        "scanner": {
            "name": "husk",
            "version": HUSK_VERSION,
            "uri": "https://github.com/ctrl-adam/Husk",
            "rulesetDigest": {"sha256": ruleset_digest},
        },
        "policy": {
            "blockOn": policy.get("block_on", "high"),
            "warnOn": policy.get("warn_on", "medium"),
        },
        "severityCounts": result["counts"],
        "firedRules": fired_rules,
        "fileCount": len(manifest),
    }
    if timestamp is not None:
        predicate["verifiedAt"] = timestamp

    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {"name": subject_name, "digest": {"sha256": subject_digest}},
        ],
        "predicateType": HUSK_PREDICATE_TYPE,
        "predicate": predicate,
    }


def canonical_json(statement):
    """Deterministic serialization: sorted keys, compact separators. Two
    equal statements serialize to identical bytes, so their SHA-256 matches -
    this is the string that gets signed and compared."""
    return json.dumps(statement, sort_keys=True, separators=(",", ":"))


def now_timestamp():
    """RFC3339 UTC timestamp for the verifiedAt field."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def verify_attestation(package_path, statement):
    """
    Re-derive the skill's digest and (optionally) the ruleset digest from the
    package on disk and check them against a claimed attestation. Returns a
    dict describing the match. This is the offline, no-trust verification path:
    a consumer who holds both the skill and the attestation can confirm the
    attestation really describes THIS skill, with no network and no faith in
    whoever produced it.
    """
    result = {"subject_match": False, "ruleset_match": None, "errors": []}

    subjects = statement.get("subject") or []
    claimed = None
    for s in subjects:
        d = (s.get("digest") or {}).get("sha256")
        if d:
            claimed = d
            break
    if not claimed:
        result["errors"].append("attestation has no sha256 subject digest")
        return result

    actual_digest, _ = compute_subject_digest(package_path)
    result["subject_match"] = (actual_digest == claimed)
    result["actual_digest"] = actual_digest
    result["claimed_digest"] = claimed
    if not result["subject_match"]:
        result["errors"].append(
            "subject digest mismatch: the skill on disk is not the one this "
            "attestation was made for (it was modified, or this is a different skill)."
        )

    predicate = statement.get("predicate") or {}
    claimed_ruleset = ((predicate.get("scanner") or {}).get("rulesetDigest") or {}).get("sha256")
    if claimed_ruleset:
        actual_ruleset = compute_ruleset_digest()
        result["ruleset_match"] = (actual_ruleset == claimed_ruleset)
        result["claimed_ruleset"] = claimed_ruleset
        result["actual_ruleset"] = actual_ruleset
        if not result["ruleset_match"]:
            result["errors"].append(
                "ruleset digest differs: this Husk version's rules are not the "
                "ones that produced the attestation (verdict may differ if re-run)."
            )

    return result
