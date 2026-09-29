#!/usr/bin/env python3
"""
Husk vs. the commercial auditors on skills.sh (Socket, Snyk, Gen Agent Trust Hub).

skills.sh publishes, on every skill's public page, an independent security
verdict from up to three commercial auditors:
  - Socket     /security/socket
  - Snyk       /security/snyk
  - Gen (Agent Trust Hub)  /security/agent-trust-hub
each as a Pass / Warn / Fail badge.

This harness takes a list of real skills.sh skills, and for each one:
  1. fetches the skill's actual content and runs Husk's own scan, and
  2. reads each commercial auditor's published verdict for the same skill,
then writes a comparison: where Husk agrees with each auditor, and, most
usefully, the skills Husk flagged that a commercial auditor passed (and vice
versa).

This is a fair, checkable benchmark: every auditor verdict is a public page
anyone can open, and every Husk verdict is reproducible with `husk skill`.

Run it on a machine with open internet (skills.sh is not reachable from the
dev sandbox):

    python benchmarks/skillssh_auditor_benchmark.py --leaderboard 200 --out bench_report
    python benchmarks/skillssh_auditor_benchmark.py skills.txt --out bench_report

`skills.txt` is one skills.sh ref per line, as `org/repo/skill`
(e.g. `mattpocock/skills/grill-me`). Get a starter list from the trending or
all-time leaderboard at skills.sh, or from `/api/skills`.
"""

import argparse
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from husk.aggregator import owned_temp_dir, resolve_skillssh_skill  # noqa: E402
from husk.package_scanner import scan_package  # noqa: E402

UA = "husk-benchmark (+https://github.com/ctrl-adam/Husk)"
AUDITORS = {
    "socket": "Socket",
    "snyk": "Snyk",
    "agent-trust-hub": "Gen Agent Trust Hub",
}


def _http(url, timeout=20):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": UA,
            "Accept": "text/html,application/json,*/*",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed skills.sh host
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError):
        return None


def fetch_auditor_verdict(skill_path, auditor):
    """Read one commercial auditor's Pass/Warn/Fail badge for a skills.sh skill.
    Robust against raw HTML: strips tags, then finds the verdict word right
    before 'Audited by <auditor> on'. Returns 'Pass'|'Warn'|'Fail'|None."""
    url = f"https://www.skills.sh/{skill_path}/security/{auditor}"
    html = _http(url)
    if not html:
        return None
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)
    if "Audited by" not in text and "Security Audit" not in text:
        return None
    am = re.search(r"Audited by\s+([\w\s-]+?)\s+on\s+", text)
    badge = None
    if am:
        for m in re.finditer(r"\b(Pass|Warn|Fail)\b", text[:am.start()]):
            badge = m.group(1)
    if badge is None:
        m = re.search(r"\b(Pass|Warn|Fail)\b", text)
        badge = m.group(1) if m else None
    return badge


def husk_verdict(skill_ref):
    """Husk's own verdict for a skills.sh skill: 'FLAGGED' | 'SAFE' | None."""
    try:
        path = resolve_skillssh_skill(skill_ref)
    except Exception:  # noqa: BLE001
        return None, []
    if not path:
        return None, []
    try:
        findings = scan_package(path)
    finally:
        owned = owned_temp_dir(path)
        if owned:
            shutil.rmtree(owned, ignore_errors=True)
    return ("FLAGGED" if findings else "SAFE"), [str(f) for f in findings][:5]


def normalize_auditor(badge):
    """Map an auditor Pass/Warn/Fail to the same axis as Husk (flagged or not)."""
    if badge is None:
        return None
    return "FLAGGED" if badge in ("Warn", "Fail") else "SAFE"



_LINK = re.compile(r'<a\b[^>]*?href="(?:https://(?:www\.)?skills\.sh)?/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)"', re.S)
_RESERVED = {"topic", "agent", "docs", "packs", "official", "audits", "trending", "hot", "about",
             "contact", "privacy", "terms", "site", "api", "agents"}


def refs_from_leaderboard(n):
    """The top-n skills from the public skills.sh leaderboard pages (all-time,
    then trending), as org/repo/skill refs, in rank order, no duplicates."""
    out = []
    for view in ("", "trending"):
        html = _http(f"https://www.skills.sh/{view}") or ""
        for owner, repo, skill in _LINK.findall(html):
            ref = f"{owner}/{repo}/{skill}"
            if owner.lower() not in _RESERVED and ref not in out:
                out.append(ref)
    return out[:n]

def benchmark(refs, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows_path = os.path.join(out_dir, "results.jsonl")
    done = set()
    if os.path.exists(rows_path):
        for line in open(rows_path, encoding="utf-8"):
            try:
                done.add(json.loads(line)["ref"])
            except Exception:  # noqa: BLE001
                pass

    with open(rows_path, "a", encoding="utf-8") as out:
        for i, ref in enumerate(refs, 1):
            ref = ref.strip()
            if not ref or ref in done:
                continue
            # normalize an org/repo/skill path for the auditor URLs
            parts = [p for p in ref.split("/") if p]
            skill_path = "/".join(parts[:3]) if len(parts) >= 3 else (
                f"{parts[0]}/{parts[1]}/{parts[1]}" if len(parts) == 2 else ref)

            hv, findings = husk_verdict(ref)
            auditors = {}
            for slug in AUDITORS:
                auditors[slug] = fetch_auditor_verdict(skill_path, slug)
                time.sleep(0.3)

            row = {"ref": ref, "skill_path": skill_path, "husk": hv,
                   "husk_findings": findings, "auditors": auditors}
            out.write(json.dumps(row) + "\n")
            out.flush()
            print(f"[{i}/{len(refs)}] {ref}: husk={hv} "
                  + " ".join(f"{AUDITORS[s]}={auditors[s]}" for s in AUDITORS if auditors[s]))
            time.sleep(0.4)

    write_report(rows_path, os.path.join(out_dir, "report.md"))


def write_report(rows_path, md_path):
    rows = [json.loads(l) for l in open(rows_path, encoding="utf-8")]
    scanned = [r for r in rows if r.get("husk")]

    L = ["# Husk vs. commercial auditors on skills.sh", "",
         f"Compared **{len(scanned)}** real skills.sh skills against Husk and up "
         "to three commercial auditors (Socket, Snyk, Gen Agent Trust Hub), each "
         "verdict a public page anyone can open.", ""]

    for slug, name in AUDITORS.items():
        # only skills where BOTH Husk and this auditor produced a verdict
        pairs = [(r["husk"], normalize_auditor(r["auditors"].get(slug)))
                 for r in scanned if r["auditors"].get(slug)]
        pairs = [(h, a) for h, a in pairs if h and a]
        if not pairs:
            L.append(f"## vs {name}\n\nNo overlapping verdicts yet.\n")
            continue
        agree = sum(1 for h, a in pairs if h == a)
        husk_caught_they_passed = sum(1 for h, a in pairs if h == "FLAGGED" and a == "SAFE")
        they_caught_husk_passed = sum(1 for h, a in pairs if h == "SAFE" and a == "FLAGGED")
        L += [
            f"## vs {name}",
            "",
            f"- Skills both scored: **{len(pairs)}**",
            f"- Agreement: **{agree}/{len(pairs)} ({100*agree//len(pairs)}%)**",
            f"- Husk flagged, {name} passed: **{husk_caught_they_passed}**",
            f"- {name} flagged, Husk passed: **{they_caught_husk_passed}**",
            "",
        ]

    # the headline list: skills Husk flagged that ALL auditors passed
    L += ["## Skills Husk flagged that every auditor passed", "",
          "These are the most interesting cases to inspect by hand \u2014 Husk saw "
          "something the commercial scanners didn't. (Some will be Husk false "
          "positives; some may be real misses by the others. That's the point of "
          "the comparison.)", ""]
    for r in scanned:
        if r["husk"] != "FLAGGED":
            continue
        auditor_norms = [normalize_auditor(r["auditors"].get(s)) for s in AUDITORS]
        published = [n for n in auditor_norms if n]
        if published and all(n == "SAFE" for n in published):
            L.append(f"### [{r['ref']}](https://www.skills.sh/{r['skill_path']})")
            for f in r["husk_findings"]:
                L.append(f"- {f}")
            L.append("")

    open(md_path, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"\nReport -> {md_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("skills_file", nargs="?", help="one skills.sh ref per line (org/repo/skill)")
    ap.add_argument("--leaderboard", type=int, metavar="N",
                    help="instead of a file, take the top N skills from the skills.sh leaderboard")
    ap.add_argument("--out", default="bench_report")
    args = ap.parse_args()
    if args.leaderboard:
        refs = refs_from_leaderboard(args.leaderboard)
        print(f"Took {len(refs)} skills from the skills.sh leaderboard.")
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "skills.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(refs) + "\n")
    elif args.skills_file:
        with open(args.skills_file, encoding="utf-8") as fh:
            refs = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    else:
        ap.error("give a skills file or --leaderboard N")
    print(f"Benchmarking Husk against Socket/Snyk/Gen on {len(refs)} skills...\n")
    benchmark(refs, args.out)


if __name__ == "__main__":
    sys.exit(main())
