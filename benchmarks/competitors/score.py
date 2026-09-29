"""Score every tool on the same fixed sample with the same rules.
Each tool's raw output is reduced to one highest severity on a shared scale:
  none < info < low < medium < high < critical
strict flag = high or above (the tool's own block level)
loose  flag = low or above (anything but pure info notes)
Husk emits one verdict, so flagged counts as high for both readings."""
import json, re, sys, os, glob
RANK = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
def norm(s):
    s = str(s or "").lower().strip()
    if s in ("safe", "clean", "pass", "none", "null", ""): return "none"
    for k in ("critical", "high", "medium", "low", "info"):
        if k in s: return k
    if s in ("moderate", "warn", "warning"): return "medium"
    return "none"
def top(levels): return max((norm(l) for l in levels), key=RANK.get, default="none")
def jload(t):
    t = t.strip(); i = min([x for x in (t.find("{"), t.find("[")) if x >= 0], default=-1)
    return json.loads(t[i:]) if i >= 0 else None
def sev(tool, r):
    o = r["out"]
    if r["code"] is None: return None                        # timeout
    try:
        if tool == "husk": return "high" if jload(o)["flagged"] else "none"
        if tool == "cisco": return norm(jload(o)["max_severity"])
        if tool == "skillspector":
            d = jload(o); return top([i.get("severity") for i in d.get("issues", [])])
        if tool == "skillfortify":
            d = jload(o); d = d if isinstance(d, list) else d.get("skills", [])
            return top([x.get("max_severity") for x in d])
        if tool == "skillfrisk": return top([f["severity"] for f in jload(o)["findings"]])
        if tool == "agentaudit": return top([f["severity"] for f in jload(o)["findings"]])
        if tool == "clawhubbridge":
            d = jload(o); d = d if isinstance(d, list) else [d]
            return top([k for x in d for k, n in (x.get("by_severity") or {}).items() if n])
        if tool == "opentrapp":
            s = jload(o)["summary"]; return top([k for k in ("critical", "high", "medium") if s.get(k, 0)])
        if tool == "skillscansec": return top([f.get("severity") for f in jload(o).get("findings", [])])
        if tool == "steffano":
            m = re.search(r"Trust Score:\s*(\d+)/100", o)
            if not m: return None
            sc = int(m.group(1)); return "none" if sc >= 80 else "medium" if sc >= 60 else "high"
        if tool == "malwar":
            d = jload(o); d = d if isinstance(d, list) else [d]
            return top([k for x in d for k, n in (x.get("finding_count_by_severity") or {}).items() if n])
        if tool == "secureai":
            s = jload(o)["summary"]["bySeverity"]; return top([k for k in RANK if s.get(k, 0)])
        if tool in ("agentauditkit", "npmskillaudit"):
            s = jload(o)["summary"]; return top([k for k in RANK if s.get(k, 0)])
        if tool == "skillguard":
            return top([x.get("risk_level") for x in jload(o).get("results", [])])
        if tool == "syedabbast": return norm(jload(o)["overall_risk"])
        if tool == "agentscan":
            m = re.search(r"summary: critical=(\d+) high=(\d+) medium=(\d+) low=(\d+) info=(\d+)", o)
            if not m: return None
            return top([k for k, n in zip(("critical", "high", "medium", "low", "info"), m.groups()) if int(n)])
        if tool == "shielder":
            m = re.search(r"\*\*Verdict\*\*:\s*\*\*(\w+)", o)
            return {"PASS": "none", "WARN": "medium", "WARNING": "medium", "FAIL": "high"}.get(m.group(1).upper(), "none") if m else None
    except Exception:
        return None
SMALL = None
def main():
    global SMALL
    if len(sys.argv) > 1 and sys.argv[1] == "--subset":
        SMALL = {p for v in json.load(open("sample_small.json")).values() for p in v}
    rows = []
    for f in sorted(glob.glob("raw/*.jsonl")):
        tool = os.path.basename(f)[:-6]
        recs = list({r["path"]: r for r in (json.loads(l) for l in open(f))}.values())  # one result per skill
        if SMALL is not None:
            recs = [r for r in recs if r["path"] in SMALL]
            if len({r["path"] for r in recs}) < 150: continue   # tool hasn't covered the subset yet
        by = {}
        for r in recs:
            s = sev(tool, r); by.setdefault(r["set"], []).append(s)
        def rate(sets, mal, th):
            v = [x for k in sets for x in by.get(k, [])]
            ok = sum(1 for x in v if x is not None and ((RANK[x] >= th) == mal))
            return ok, len(v), sum(1 for x in v if x is None)
        secs = sum(r["secs"] for r in recs) / max(1, len(recs))
        for mode, th in (("strict", 4), ("loose", 2)):
            if tool == "husk" and mode == "loose": continue
            m = rate(["msb_mal", "asb_mal"], True, th); c = rate(["curated"], False, th); b = rate(["msb_ben"], False, th)
            rows.append((tool, mode, m, c, b, secs, len(recs)))
    print("SUBSET (same 200 skills for every tool: 100 malware, 50 hand-checked legit, 50 research benign)" if SMALL else "FULL SAMPLE (699 skills)")
    print(f"{'tool':15s} {'mode':6s} {'catch rate (300 mal)':22s} {'curated clean (249)':20s} {'MSB benign clean (150)':22s} {'s/scan':6s} n")
    for t, mode, m, c, b, secs, n in sorted(rows, key=lambda r: -r[3][0]):
        f = lambda x: f"{x[0]}/{x[1]} {100*x[0]/max(1,x[1]):5.1f}%" + (f" ({x[2]} err)" if x[2] else "")
        print(f"{t:15s} {mode:6s} {f(m):22s} {f(c):20s} {f(b):22s} {secs:5.1f}  {n}")
if __name__ == "__main__": main()
