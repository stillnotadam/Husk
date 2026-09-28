#!/usr/bin/env python3
"""
Husk ecosystem scanner (GitHub edition).

Finds agent-skill repositories on GitHub, scans each with Husk's full engine,
ranks them by severity, and writes a triage shortlist of the scariest ones -
the raw material for "we scanned the agent-skill ecosystem; here's what's
actually out there."

Run it on your machine with a GitHub token (5000 req/hr instead of 60, which is
the difference between a 3-hour run and a 3-day one):

    cd Husk && git pull
    pip install --upgrade husk-scanner
    export GITHUB_TOKEN=ghp_your_token_here      # a classic PAT, no scopes needed
    python benchmarks/ecosystem_scan_github.py --pages 30 --out report

Output (in --out/):
  results.jsonl   one row per repo: severity counts, gate decision, top
                  findings, stars, url. Resumable - re-running skips done repos.
  report.md       ranked shortlist of the highest-severity repos (the triage
                  list) + ecosystem-wide stats. Paste this back for analysis.

Only reads public repos, is rate-limit aware, fetches per-repo tarballs once,
skips vendored/huge files, and never executes anything it downloads.
"""

import argparse
import collections
import io
import json
import os
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from husk.context_classifier import classify_repo_context
from husk.gate import evaluate as gate_evaluate
from husk.package_scanner import scan_package

TOKEN = os.environ.get("GITHUB_TOKEN", "")
UA = "husk-ecosystem-research (+https://github.com/ctrl-adam/Husk)"
SEV = {"critical": 1000, "high": 100, "medium": 10, "low": 1, "info": 0}

# Files worth scanning; everything else in a repo is skipped so a bundled
# node_modules or a vendored asset never inflates a score or slows the run.
SKIP_DIR = ("node_modules/", "/vendor/", "dist/", "build/", ".git/",
            "__pycache__/", "site-packages/", ".venv/", "assets/vendor/")


def gh_api(url):
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    for _ in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - fixed api.github.com
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                reset = e.headers.get("X-RateLimit-Reset")
                wait = max(2, int(reset) - int(time.time())) if reset else 15
                time.sleep(min(wait, 90) + 1)
                continue
            raise
        except urllib.error.URLError:
            time.sleep(5)
    raise RuntimeError(f"giving up on {url}")


def find_repos(queries, pages, seen):
    repos = []
    for q in queries:
        for page in range(1, pages + 1):
            url = ("https://api.github.com/search/repositories?q="
                   + urllib.parse.quote(q)
                   + f"&sort=updated&order=desc&per_page=100&page={page}")
            try:
                d = gh_api(url)
            except Exception:
                break
            items = d.get("items", [])
            if not items:
                break
            for r in items:
                if r["full_name"] not in seen:
                    seen.add(r["full_name"])
                    repos.append(r)
            time.sleep(1)
    return repos


def scan_repo(full, branch):
    for br in ([branch] if branch else []) + ["main", "master"]:
        try:
            url = f"https://codeload.github.com/{full}/tar.gz/refs/heads/{br}"
            data = urllib.request.urlopen(  # noqa: S310 - fixed codeload host
                urllib.request.Request(url, headers={"User-Agent": UA}), timeout=45).read()
            break
        except Exception:
            data = None
    if not data or len(data) > 60 * 1024 * 1024:
        return None
    d = tempfile.mkdtemp()
    n_files = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            for m in tf.getmembers():
                if not m.isfile() or m.name.startswith("/") or ".." in m.name.split("/"):
                    continue
                low = m.name.lower()
                if any(s in low for s in SKIP_DIR) or m.size > 3 * 1024 * 1024:
                    continue
                # cap files per repo so a giant repo can't stall the scan
                if n_files >= 400:
                    break
                try:
                    tf.extract(m, d)
                    n_files += 1
                except Exception:
                    pass
    except Exception:
        return None
    # hard per-repo timeout: one pathological file (catastrophic regex, etc.)
    # must not halt the whole run.
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            findings = ex.submit(scan_package, d).result(timeout=90)
    except FutureTimeout:
        return {"decision": "timeout", "counts": dict.fromkeys(SEV, 0),
                "score": 0, "blocking": [], "error": "scan timed out (>90s)"}
    except Exception as exc:
        return {"decision": "error", "counts": dict.fromkeys(SEV, 0),
                "score": 0, "blocking": [], "error": f"{type(exc).__name__}"}
    res = gate_evaluate(findings)
    c = res["counts"]
    ctx = classify_repo_context(d)
    return {"decision": res["decision"], "counts": c,
            "score": sum(SEV[s] * n for s, n in c.items()),
            "blocking": [b["finding"] for b in res["blocking"][:8]],
            "sec_tool": ctx["self_identifies_security_tool"],
            "bucket": ctx["triage_bucket"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=int, default=20, help="search pages/query (100 repos each)")
    ap.add_argument("--out", default="report")
    ap.add_argument("--top", type=int, default=60)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    res_path = os.path.join(args.out, "results.jsonl")

    if not TOKEN:
        print("WARNING: no GITHUB_TOKEN set - you'll be rate-limited to ~60 req/hr.\n"
              "         export GITHUB_TOKEN=<a classic PAT> for a fast run.\n", file=sys.stderr)

    done = set()
    if os.path.exists(res_path):
        for line in open(res_path, encoding="utf-8"):
            try:
                done.add(json.loads(line)["repo"])
            except Exception:
                pass

    queries = [
        "SKILL.md in:path",
        "path:SKILL.md allowed-tools",
        "claude agent skill in:name,description,readme",
    ]
    print("Finding skill repos on GitHub ...")
    repos = find_repos(queries, args.pages, set(done))
    todo = [r for r in repos if r["full_name"] not in done]
    print(f"{len(repos)} repos found, {len(done)} already scanned, {len(todo)} to go.\n")

    with open(res_path, "a", encoding="utf-8") as out:
        for n, r in enumerate(todo, 1):
            full = r["full_name"]
            try:
                res = scan_repo(full, r.get("default_branch"))
            except Exception as exc:
                res = {"error": f"{type(exc).__name__}: {exc}"[:150]}
            if res is None:
                res = {"error": "no skill files / unfetchable", "decision": "skip",
                       "counts": dict.fromkeys(SEV, 0), "score": 0, "blocking": []}
            res.update({"repo": full, "stars": r.get("stargazers_count", 0), "url": r["html_url"]})
            out.write(json.dumps(res) + "\n")
            out.flush()
            flag = "" if res["score"] < 1000 else f"  <-- HIGH {res['score']}"
            print(f"[{n}/{len(todo)}] {full}: {res.get('decision', '?')} score={res['score']}{flag}")
            time.sleep(0.3)

    write_report(res_path, os.path.join(args.out, "report.md"), args.top)


def write_report(res_path, md_path, top_n):
    rows = [json.loads(l) for l in open(res_path, encoding="utf-8")]
    scanned = [r for r in rows if not r.get("error")]
    ranked = sorted(scanned, key=lambda r: -r["score"])
    dist = collections.Counter(r["decision"] for r in scanned)
    fails = [r for r in scanned if r["decision"] == "fail"]

    review_first = [r for r in ranked if r["score"] > 0 and not r.get("sec_tool")]
    likely_fp = [r for r in ranked if r["score"] > 0 and r.get("sec_tool")]

    L = ["# Husk ecosystem scan (GitHub)", "",
         f"Scanned **{len(scanned)}** skill repositories.", "",
         f"Gate: **{dist.get('fail', 0)} would be BLOCKED**, "
         f"{dist.get('warn', 0)} warn, {dist.get('pass', 0)} pass.", "",
         f"Of the flagged repos, **{len(review_first)} do NOT claim to be "
         f"security tools** (review these first - this is where real malware "
         f"hides) and **{len(likely_fp)} self-identify as security/scanning "
         f"tools** (likely false positives - their attack strings are probably "
         f"data, not directives).", "",
         "## Bucket A — REVIEW FIRST (flagged, not a self-described security tool)", ""]

    def emit(repos):
        for r in repos[:top_n]:
            c = r["counts"]
            L.append(f"### [{r['repo']}]({r['url']}) — score {r['score']} "
                     f"({c['critical']}C/{c['high']}H/{c['medium']}M) — {r['stars']}★")
            for f in r["blocking"]:
                L.append(f"- {f}")
            L.append("")

    emit(review_first)
    L += ["## Bucket B — likely false positives (self-described security tools)", ""]
    emit(likely_fp)
    open(md_path, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"\nReport -> {md_path}  ({len(fails)} would-be-blocked, "
          f"top score {ranked[0]['score'] if ranked else 0})")
    print("Paste report.md back into the chat for triage.")


if __name__ == "__main__":
    sys.exit(main())
