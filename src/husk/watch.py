"""
Husk watch: the time dimension no point-in-time scanner covers.

A skill is clean when you install it. Weeks later a malicious update ships.
The gate ran once, at install; the attestation described that one version; a
marketplace's review ran at publish. None of them tell you the thing that
already ran on your machine just changed. `husk watch` closes that gap: it
keeps a local baseline of every skill it has seen (its content digest and
Husk's verdict) and, on each subsequent run, reports what changed - and
crucially, whether a skill that used to be SAFE is now FLAGGED.

The baseline is a plain JSON file the user owns (default ~/.husk/watch.json).
Everything is local, deterministic, and reuses the same canonical content
digest as `husk attest`, so a change is detected at the byte level, not by
trusting a version number a malicious update could lie about.
"""

import json
import os
from datetime import datetime, timezone

from .attestation import compute_subject_digest
from .scan_cache import load_cache, save_cache, scan_package_cached

DEFAULT_BASELINE = os.path.join(os.path.expanduser("~"), ".husk", "watch.json")

# Where agent skills commonly live, so `husk watch` can auto-discover them.
DEFAULT_SKILL_ROOTS = [
    "~/.agents/skills",
    "~/.claude/skills",
    "~/.openclaw/skills",
    "~/.config/openclaw/skills",
    "~/.kiro/skills",
    "~/.cline/skills",
]


def _looks_like_skill_dir(path):
    """A directory is a skill if it contains a SKILL.md (any case)."""
    try:
        return any(name.lower() == "skill.md" for name in os.listdir(path))
    except OSError:
        return False


def discover_skills(roots=None):
    """Find installed skill directories under the given roots (or the common
    defaults). Returns a sorted list of absolute paths."""
    roots = roots or DEFAULT_SKILL_ROOTS
    found = []
    for root in roots:
        base = os.path.expanduser(root)
        if not os.path.isdir(base):
            continue
        # a skill is a direct child dir with a SKILL.md, OR the root itself
        if _looks_like_skill_dir(base):
            found.append(os.path.abspath(base))
            continue
        for entry in sorted(os.listdir(base)):
            full = os.path.join(base, entry)
            if os.path.isdir(full) and _looks_like_skill_dir(full):
                found.append(os.path.abspath(full))
    return sorted(set(found))


def load_baseline(path=None):
    """Load the watch baseline; returns {} if absent or unreadable."""
    path = path or DEFAULT_BASELINE
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_baseline(baseline, path=None):
    """Write the baseline atomically. Returns (ok, error)."""
    path = path or DEFAULT_BASELINE
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(baseline, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
        return True, None
    except OSError as exc:
        return False, str(exc)


def _snapshot(skill_path, cache=None):
    """Digest + verdict for one skill right now (cache-accelerated)."""
    digest, _ = compute_subject_digest(skill_path)
    if cache is not None:
        findings, _hit = scan_package_cached(skill_path, cache=cache, save=False)
    else:
        from .package_scanner import scan_package  # noqa: PLC0415
        findings = scan_package(skill_path)
    return {
        "digest": digest,
        "verdict": "FLAGGED" if findings else "SAFE",
        "finding_count": len(findings),
        "seen_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def watch(paths=None, roots=None, baseline_path=None, update=True):
    """
    Scan the given skill paths (or auto-discover under roots), compare each to
    the stored baseline, and report changes.

    Returns a dict:
      {
        "checked": int,
        "new": [ {path, verdict}, ... ],                  # first time seen
        "unchanged": int,
        "changed": [ {path, from_verdict, to_verdict,     # content changed
                      from_digest, to_digest} ... ],
        "newly_flagged": [ ... subset of changed where SAFE -> FLAGGED ],
        "alerts": [ ... human-readable ],
      }

    `newly_flagged` is the headline: a skill that was safe when you installed
    it and is malicious now - the exact attack no point-in-time check sees.
    """
    baseline = load_baseline(baseline_path)
    skills = ([os.path.abspath(os.path.expanduser(p)) for p in paths]
              if paths else discover_skills(roots))

    report = {"checked": 0, "new": [], "unchanged": 0, "changed": [],
              "newly_flagged": [], "alerts": []}

    scan_cache = load_cache()
    for path in skills:
        if not os.path.isdir(path):
            continue
        report["checked"] += 1
        snap = _snapshot(path, cache=scan_cache)
        prior = baseline.get(path)
        if prior is None:
            report["new"].append({"path": path, "verdict": snap["verdict"]})
        elif prior.get("digest") == snap["digest"]:
            report["unchanged"] += 1
        else:
            change = {
                "path": path,
                "from_verdict": prior.get("verdict"),
                "to_verdict": snap["verdict"],
                "from_digest": prior.get("digest"),
                "to_digest": snap["digest"],
            }
            report["changed"].append(change)
            if prior.get("verdict") == "SAFE" and snap["verdict"] == "FLAGGED":
                report["newly_flagged"].append(change)
        baseline[path] = snap

    for c in report["newly_flagged"]:
        report["alerts"].append(
            f"MALICIOUS UPDATE: '{os.path.basename(c['path'])}' was SAFE and is now "
            f"FLAGGED after a content change - a skill you already trusted just "
            f"changed into something Husk flags. Path: {c['path']}"
        )
    for c in report["changed"]:
        if c not in report["newly_flagged"]:
            report["alerts"].append(
                f"changed: '{os.path.basename(c['path'])}' content changed "
                f"({c['from_verdict']} -> {c['to_verdict']}) - review the update."
            )

    save_cache(scan_cache)
    if update:
        save_baseline(baseline, baseline_path)
    return report
