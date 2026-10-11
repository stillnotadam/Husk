"""Score Husk on local skill datasets, deterministically.

Usage:
  python benchmarks/dataset_bench.py <out.jsonl> <label>=<dir-of-skill-dirs> [...]
      (<label>=<dir>/** instead scans every folder under <dir> holding a SKILL.md)
  python benchmarks/dataset_bench.py --stb <SkillTrustBench dir> <out.jsonl>
  python benchmarks/dataset_bench.py --compare <old.jsonl> <new.jsonl>

Each skill directory is scanned with scan_package and run through the gate
with the default policy. A skill counts as caught when the gate FAILs
(a high or critical finding: the "strict" reading in BENCHMARK.md) and as
flagged when it has any hard finding ("loose"). --compare prints both rates
per label and lists every skill whose strict outcome changed.
"""
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Husk without its dependencies still runs, minus the JavaScript analysis
# (esprima) and PDF text (pypdf), so a benchmark in a bare interpreter would
# measure a different scanner than the one users install. Before 1.6.0 the
# published numbers were measured that way; refuse instead.
for _dep in ("esprima", "pypdf"):
    try:
        __import__(_dep)
    except ImportError:
        sys.exit(f"dataset_bench: '{_dep}' is not installed; install Husk's dependencies "
                 f"(pip install -e .) so the benchmark measures the scanner users get.")

from husk.gate import evaluate
from husk.package_scanner import scan_package


def _one(job):
    label, path = job
    try:
        findings = scan_package(path)
        result = evaluate(findings)
        c = result["counts"]
        return {"label": label, "path": path, "fail": result["decision"] == "fail",
                "hard": any(c[k] for k in ("critical", "high", "medium", "low")),
                "counts": c, "top": [b["finding"][:160] for b in result["blocking"][:3]]}
    except Exception as exc:  # a crash is recorded, never hidden
        return {"label": label, "path": path, "fail": None, "hard": None, "error": repr(exc)[:300]}


def _jobs_from_dirs(specs):
    jobs = []
    for spec in specs:
        label, root = spec.split("=", 1)
        if root.endswith("/**"):
            # Every folder holding a SKILL.md, at any depth (dxta-skills keeps
            # its skills in category folders), skipping hidden folders.
            root = root[:-3]
            for d, subdirs, files in os.walk(root):
                subdirs[:] = sorted(s for s in subdirs if not s.startswith("."))
                if "SKILL.md" in files:
                    jobs.append((label, d))
            continue
        for name in sorted(os.listdir(root)):
            p = os.path.join(root, name)
            if os.path.isdir(p):
                jobs.append((label, p))
    return jobs


def _jobs_from_stb(root):
    """SkillTrustBench v1.0: <root>/ground_truth.json lists test_cases with
    a judgment (malicious / suspicious / normal) and a case directory."""
    gt = json.load(open(os.path.join(root, "ground_truth.json"), encoding="utf-8"))
    jobs = []
    for case in gt["test_cases"]:
        p = os.path.join(root, case["id"])
        if os.path.isdir(p):
            jobs.append((f"stb_{case['judgment']}", p))
    return sorted(jobs, key=lambda j: j[1])


def run(jobs, out):
    with open(out, "w", encoding="utf-8") as fh, ProcessPoolExecutor() as ex:
        for rec in ex.map(_one, jobs, chunksize=8):
            fh.write(json.dumps(rec) + "\n")


def _load(path):
    return {r["path"]: r for r in map(json.loads, open(path, encoding="utf-8"))}


def summary(rows):
    by = {}
    for r in rows.values():
        b = by.setdefault(r["label"], {"n": 0, "fail": 0, "hard": 0, "err": 0})
        b["n"] += 1
        if r.get("fail") is None:
            b["err"] += 1
        b["fail"] += bool(r.get("fail"))
        b["hard"] += bool(r.get("hard"))
    return by


def compare(old_path, new_path):
    old, new = _load(old_path), _load(new_path)
    so, sn = summary(old), summary(new)
    print(f"{'label':22} {'n':>5}  {'strict old':>10} {'strict new':>10}  {'loose old':>9} {'loose new':>9}  errors")
    for label in sorted(sn):
        o, n = so.get(label, {"n": 1, "fail": 0, "hard": 0}), sn[label]
        print(f"{label:22} {n['n']:5}  {o['fail'] / o['n']:10.1%} {n['fail'] / n['n']:10.1%}"
              f"  {o['hard'] / o['n']:9.1%} {n['hard'] / n['n']:9.1%}  {n['err']}")
    changed = [(p, old[p].get("fail"), r.get("fail"), r["label"]) for p, r in new.items()
               if p in old and bool(old[p].get("fail")) != bool(r.get("fail"))]
    print(f"\n{len(changed)} skills changed strict outcome:")
    for p, a, b, label in sorted(changed, key=lambda x: x[3]):
        print(f"  {label:18} {'FAIL' if a else 'pass'} -> {'FAIL' if b else 'pass'}  {p}")
        if b:
            for t in new[p].get("top", []):
                print(f"      {t}")


if __name__ == "__main__":
    if sys.argv[1] == "--compare":
        compare(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "--stb":
        run(_jobs_from_stb(sys.argv[2]), sys.argv[3])
    else:
        run(_jobs_from_dirs(sys.argv[2:]), sys.argv[1])
