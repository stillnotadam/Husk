"""
Husk vs ClawHub: compare Husk's verdict with ClawHub's own published
security verdict on a sample of real, public ClawHub skills.

Run on your own machine (needs internet access to clawhub.ai):

    pip install --upgrade husk-scanner
    python benchmarks/clawhub_benchmark.py --limit 300

Uses only ClawHub's documented public API (docs.openclaw.ai/clawhub/http-api):
  GET  /api/v1/skills                      catalogue listing (paginated)
  POST /api/v1/skills/-/security-verdicts  ClawHub's verdicts, 100 per call
  GET  /api/v1/download?slug=...           the skill's files (via Husk)
It stays far below ClawHub's published rate limits, honours 429 +
Retry-After, and is resumable: re-running skips skills already done.

Outputs (in --out, default ./clawhub_benchmark_results):
  results.jsonl  one line per skill
  summary.md     agreement table + every disagreement, with links
"""
import argparse
import collections
import json
import os
import random
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import husk.aggregator as agg
from husk.package_scanner import scan_package

UA = "husk-scanner-benchmark (+https://github.com/ctrl-adam/Husk)"


def call(api, method, path, body=None, tries=5):
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(tries):
        req = urllib.request.Request(api + path, data=data, method=method,
                                     headers={"User-Agent": UA, "Accept": "application/json",
                                              **({"Content-Type": "application/json"} if data else {})})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - fixed ClawHub API base
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                wait = float(e.headers.get("Retry-After") or 2 ** attempt)
                time.sleep(min(wait, 60) + random.random())
                continue
            raise
        except urllib.error.URLError:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"giving up on {method} {path}")


def list_skills(api, limit, sort):
    items, cursor = [], None
    while len(items) < limit:
        q = {"limit": min(200, limit - len(items)), "sort": sort}
        if cursor:
            q["cursor"] = cursor
        page = call(api, "GET", "/api/v1/skills?" + urllib.parse.urlencode(q))
        for it in page.get("items", []):
            if it.get("latestVersion") and it.get("slug") and it.get("ownerHandle"):
                items.append(it)
        cursor = page.get("nextCursor")
        if not cursor:
            break
        time.sleep(0.3)
    return items[:limit]


def verdicts(api, skills):
    out = {}
    for i in range(0, len(skills), 100):
        batch = skills[i:i + 100]
        body = {"items": [{"slug": s["slug"], "ownerHandle": s["ownerHandle"],
                           "version": s["latestVersion"]["version"]} for s in batch]}
        res = call(api, "POST", "/api/v1/skills/-/security-verdicts", body)
        for s, item in zip(batch, res.get("items", [])):
            out[(s["ownerHandle"], s["slug"])] = item
        time.sleep(0.5)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=300, help="skills per sort order")
    ap.add_argument("--sorts", default="createdAt,downloads",
                    help="comma list: createdAt (newest), downloads, updated, trending")
    ap.add_argument("--out", default="clawhub_benchmark_results")
    ap.add_argument("--api", default="https://clawhub.ai")
    ap.add_argument("--retry-errors", action="store_true",
                    help="drop previously failed skills from results and scan them again")
    ap.add_argument("--analyze", action="store_true",
                    help="only (re)write summary.md from existing results, no network")
    args = ap.parse_args()
    if args.analyze:
        write_summary(os.path.join(args.out, "results.jsonl"), os.path.join(args.out, "summary.md"))
        return 0
    agg.CLAWHUB_API = args.api
    os.makedirs(args.out, exist_ok=True)
    res_path = os.path.join(args.out, "results.jsonl")
    done = set()
    if args.retry_errors and os.path.exists(res_path):
        kept = []
        for line in open(res_path, encoding="utf-8"):
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("husk"):
                kept.append(line if line.endswith("\n") else line + "\n")
        with open(res_path, "w", encoding="utf-8") as fh:
            fh.writelines(kept)
    if os.path.exists(res_path):
        for line in open(res_path, encoding="utf-8"):
            try:
                r = json.loads(line); done.add((r["owner"], r["slug"]))
            except Exception:
                pass

    skills, seen = [], set()
    for sort in [s.strip() for s in args.sorts.split(",") if s.strip()]:
        for it in list_skills(args.api, args.limit, sort):
            key = (it["ownerHandle"], it["slug"])
            if key not in seen:
                seen.add(key); it["_sampled_by"] = sort; skills.append(it)
    todo = [s for s in skills if (s["ownerHandle"], s["slug"]) not in done]
    print(f"{len(skills)} skills sampled, {len(done)} already done, {len(todo)} to scan")
    vmap = verdicts(args.api, todo) if todo else {}

    with open(res_path, "a", encoding="utf-8") as out:
        for n, s in enumerate(todo, 1):
            owner, slug = s["ownerHandle"], s["slug"]
            item = vmap.get((owner, slug)) or {}
            ch = (item.get("security") or {}).get("status")
            findings, err = [], None
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    path, err = agg.fetch_clawhub_skill(f"{owner}/{slug}", tmp)
                    findings = scan_package(path) if path else []
            except Exception as exc:  # one bad skill must never stop the run
                err = f"scan crashed: {type(exc).__name__}: {exc}"[:300]
            row = {"owner": owner, "slug": slug, "version": s["latestVersion"]["version"],
                   "sampled_by": s["_sampled_by"], "clawhub": ch,
                   "clawhub_decision": item.get("decision"), "audit_url": item.get("securityAuditUrl"),
                   "husk": None if err else ("FLAGGED" if findings else "SAFE"),
                   "husk_error": err, "husk_findings": findings[:10],
                   "url": f"https://clawhub.ai/{owner}/skills/{slug}"}
            out.write(json.dumps(row) + "\n"); out.flush()
            print(f"[{n}/{len(todo)}] {owner}/{slug}: husk={row['husk'] or 'error'} clawhub={ch}"
                  + (f"  <- {err[:110]}" if err else ""))
            time.sleep(0.4)
    write_summary(res_path, os.path.join(args.out, "summary.md"))


def write_summary(res_path, md_path):
    rows = [json.loads(l) for l in open(res_path, encoding="utf-8")]
    ok = [r for r in rows if r["husk"] and r["clawhub"] in ("clean", "suspicious", "malicious")]
    ch_dist = collections.Counter(r["clawhub"] for r in rows)
    t = collections.Counter((r["husk"] == "FLAGGED", r["clawhub"] != "clean") for r in ok)
    both_flag, both_clean = t[(True, True)], t[(False, False)]
    husk_only, ch_only = t[(True, False)], t[(False, True)]
    agree = (both_flag + both_clean) / len(ok) * 100 if ok else 0
    L = ["# Husk vs ClawHub - benchmark summary", "",
         f"Skills sampled: {len(rows)}; comparable (both verdicts available): {len(ok)}", "",
         f"ClawHub verdict distribution: {dict(ch_dist)}", "",
         "| | ClawHub clean | ClawHub suspicious/malicious |", "|---|---|---|",
         f"| **Husk SAFE** | {both_clean} | {ch_only} |",
         f"| **Husk FLAGGED** | {husk_only} | {both_flag} |", "",
         f"Overall agreement: **{agree:.1f}%**", "",
         "Note: ClawHub's 'suspicious' includes risk-hygiene findings (e.g. unpinned installers) "
         "from AI reviewers; Husk flags likely-malicious behaviour. Read disagreements before "
         "treating either side as wrong.", ""]
    for title, pred in [("Husk flagged, ClawHub clean", lambda r: r["husk"] == "FLAGGED" and r["clawhub"] == "clean"),
                        ("ClawHub flagged, Husk safe", lambda r: r["husk"] == "SAFE" and r["clawhub"] != "clean")]:
        L += [f"## {title}", ""]
        for r in (x for x in ok if pred(x)):
            L.append(f"- [{r['owner']}/{r['slug']}]({r['url']}) - ClawHub: {r['clawhub']}"
                     + (f" ([audit]({r['audit_url']}))" if r.get("audit_url") else ""))
            for f in r["husk_findings"][:3]:
                L.append(f"  - Husk: {f[:200]}")
        L.append("")
    def kind(f):
        f = f.split("': ", 1)[-1]
        f = f.split(": ", 1)[-1] if f.startswith("Line") else f
        return f.split(" (", 1)[0].split(" - ", 1)[0][:90]
    only_husk = [r for r in ok if r["husk"] == "FLAGGED" and r["clawhub"] == "clean"]
    kinds = collections.Counter(k for r in only_husk for k in {kind(f) for f in r["husk_findings"]})
    L += ["## Most common Husk findings where ClawHub said clean (candidate false positives)", ""]
    L += [f"- {n} skills: {k}" for k, n in kinds.most_common(15)] + [""]
    errs = [r for r in rows if not r["husk"]]
    if errs:
        reasons = collections.Counter((r["husk_error"] or "")[:120] for r in errs)
        L += [f"## Download/scan error reasons ({len(errs)} skills)", ""]
        L += [f"- {n}x {k}" for k, n in reasons.most_common(10)] + [""]
    if errs:
        L += [f"## Could not download ({len(errs)})", ""] + [f"- {r['owner']}/{r['slug']}: {r['husk_error']}" for r in errs[:50]]
    open(md_path, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"\nSummary written to {md_path}  (agreement {agree:.1f}% on {len(ok)} comparable skills)")


if __name__ == "__main__":
    sys.exit(main())
