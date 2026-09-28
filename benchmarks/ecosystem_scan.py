#!/usr/bin/env python3
"""
Husk ecosystem research harness.

Pulls a large sample of live skills from a marketplace, scans each with Husk's
full engine, ranks them by severity, and writes a report of the scariest ones -
the raw material for "we scanned the agent-skill ecosystem; here's what's
actually out there."

Run it on a machine with open internet (it uses the marketplace's public API):

    pip install --upgrade husk-scanner
    python ecosystem_scan.py --limit 3000 --out ecosystem_report

Output (in --out):
  results.jsonl   one line per skill: ref, severity counts, gate decision,
                  top findings, link. Resumable - re-running skips done skills.
  report.md       ranked shortlist of the highest-severity skills (the triage
                  list), plus ecosystem-wide stats. This is the artifact.

Only reads public listing + download endpoints, is rate-limit aware, caches by
content digest, and never executes anything it downloads.
"""

import argparse
import collections
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import husk.aggregator as agg
from husk.gate import evaluate as gate_evaluate
from husk.package_scanner import scan_package

UA = "husk-ecosystem-research (+https://github.com/ctrl-adam/Husk)"


def call(api, path, tries=5):
    for attempt in range(tries):
        req = urllib.request.Request(
            api + path, method="GET",
            headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - fixed public API base
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                wait = float(e.headers.get("Retry-After") or 2 ** attempt)
                time.sleep(min(wait, 60) + random.random())
                continue
            raise
        except urllib.error.URLError:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"giving up on GET {path}")


def list_skills(api, limit, sorts):
    """Sample skills across several sort orders so the picture isn't skewed to
    only the newest or only the most-downloaded."""
    seen, items = set(), []
    for sort in sorts:
        cursor = None
        got = 0
        while got < limit:
            q = {"limit": min(200, limit - got), "sort": sort}
            if cursor:
                q["cursor"] = cursor
            page = call(api, "/api/v1/skills?" + urllib.parse.urlencode(q))
            batch = page.get("items", [])
            if not batch:
                break
            for it in batch:
                owner = it.get("ownerHandle") or (it.get("owner") or {}).get("handle")
                slug = it.get("slug")
                if not owner or not slug:
                    continue
                key = (owner, slug)
                if key in seen:
                    continue
                seen.add(key)
                it["_ref"] = f"{owner}/{slug}"
                items.append(it)
                got += 1
            cursor = page.get("nextCursor")
            if not cursor:
                break
            time.sleep(0.3)
    return items


_SEV_WEIGHT = {"critical": 1000, "high": 100, "medium": 10, "low": 1, "info": 0}


def severity_score(counts):
    return sum(_SEV_WEIGHT[s] * n for s, n in counts.items())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=1500, help="skills per sort order")
    ap.add_argument("--sorts", default="createdAt,downloads,updatedAt",
                    help="comma list of sort orders to sample across")
    ap.add_argument("--api", default="https://clawhub.ai")
    ap.add_argument("--out", default="ecosystem_report")
    ap.add_argument("--top", type=int, default=50, help="how many to list in report.md")
    args = ap.parse_args()
    agg.CLAWHUB_API = args.api
    os.makedirs(args.out, exist_ok=True)
    res_path = os.path.join(args.out, "results.jsonl")

    done = set()
    if os.path.exists(res_path):
        for line in open(res_path, encoding="utf-8"):
            try:
                done.add(json.loads(line)["ref"])
            except Exception:
                pass

    sorts = [s.strip() for s in args.sorts.split(",") if s.strip()]
    print(f"Listing skills from {args.api} across sorts {sorts} ...")
    skills = list_skills(args.api, args.limit, sorts)
    todo = [s for s in skills if s["_ref"] not in done]
    print(f"{len(skills)} unique skills sampled, {len(done)} already scanned, {len(todo)} to go.\n")

    import tempfile
    with open(res_path, "a", encoding="utf-8") as out:
        for n, s in enumerate(todo, 1):
            ref = s["_ref"]
            findings, err = [], None
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    path, err = agg.fetch_clawhub_skill(ref, tmp)
                    if path:
                        findings = scan_package(path)
            except Exception as exc:  # one bad skill never stops the run
                err = f"{type(exc).__name__}: {exc}"[:200]

            result = gate_evaluate(findings)
            row = {
                "ref": ref,
                "url": f"https://clawhub.ai/{ref.replace('/', '/skills/', 1)}",
                "decision": result["decision"],
                "counts": result["counts"],
                "score": severity_score(result["counts"]),
                "top_findings": [b["finding"] for b in (result["blocking"] + result["warnings"])[:6]],
                "error": err,
            }
            out.write(json.dumps(row) + "\n")
            out.flush()
            tag = err or f"{result['decision']} score={row['score']}"
            print(f"[{n}/{len(todo)}] {ref}: {tag}")
            time.sleep(0.4)

    write_report(res_path, os.path.join(args.out, "report.md"), args.top)


def write_report(res_path, md_path, top_n):
    rows = [json.loads(l) for l in open(res_path, encoding="utf-8")]
    scanned = [r for r in rows if not r["error"]]
    errored = [r for r in rows if r["error"]]
    ranked = sorted(scanned, key=lambda r: -r["score"])

    dist = collections.Counter(r["decision"] for r in scanned)
    sev_totals = collections.Counter()
    for r in scanned:
        for s, n in r["counts"].items():
            sev_totals[s] += n
    fail = [r for r in scanned if r["decision"] == "fail"]

    L = ["# Husk ecosystem scan", "",
         f"Scanned **{len(scanned)}** live skills "
         f"({len(errored)} could not be fetched).", "",
         f"Gate decision: **{dist.get('fail', 0)} fail**, "
         f"{dist.get('warn', 0)} warn, {dist.get('pass', 0)} pass.", "",
         f"Severity totals across all findings: {dict(sev_totals)}", "",
         f"**{len(fail)} skills would be BLOCKED** by the default gate "
         f"(a high/critical finding).", "",
         "## Triage shortlist (highest severity first)", "",
         "Each of these is a candidate - Husk flags it, but a human must "
         "confirm real malice vs. an aggressive-but-legit pattern. This is the "
         "list to review.", ""]
    for r in ranked[:top_n]:
        if r["score"] == 0:
            break
        c = r["counts"]
        L.append(f"### [{r['ref']}]({r['url']}) — score {r['score']} "
                 f"({c['critical']}C/{c['high']}H/{c['medium']}M)")
        for f in r["top_findings"]:
            L.append(f"- {f}")
        L.append("")

    if errored:
        reasons = collections.Counter((r["error"] or "")[:80] for r in errored)
        L += ["## Fetch errors", ""]
        L += [f"- {n}x {k}" for k, n in reasons.most_common(10)]

    open(md_path, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"\nReport written to {md_path}")
    print(f"  {len(fail)} would-be-blocked skills, top score {ranked[0]['score'] if ranked else 0}")


if __name__ == "__main__":
    sys.exit(main())
