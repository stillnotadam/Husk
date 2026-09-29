"""Build the markdown comparison straight from raw results (no hand-typed numbers)."""
import json, sys
sys.argv = [sys.argv[0]]
import score
META = json.load(open("meta.json"))
def table(subset, want_mode="strict"):
    score.SMALL = {p for v in json.load(open("sample_small.json")).values() for p in v} if subset else None
    rows = []
    import glob, os
    for f in sorted(glob.glob("raw/*.jsonl")):
        tool = os.path.basename(f)[:-6]
        if tool not in META: continue
        recs = list({r["path"]: r for r in map(json.loads, open(f))}.values())
        if subset: recs = [r for r in recs if r["path"] in score.SMALL]
        full_n = 200 if subset else 699
        if len(recs) < full_n * 0.95: continue
        sev = {}
        for r in recs: sev.setdefault(r["set"], []).append(score.sev(tool, r))
        for mode, th in (("strict", 4), ("loose", 2)):
            if mode != want_mode and not (tool == "husk" and mode == "strict"): continue
            if tool == "husk" and mode == "loose": continue
            def rate(sets, mal):
                v = [x for k in sets for x in sev.get(k, [])]; scored = [x for x in v if x is not None]
                ok = sum(1 for x in scored if (score.RANK[x] >= th) == mal)
                return ok, len(scored), len(v) - len(scored)   # no-result skills are excluded, reported separately
            rows.append((tool, mode, rate(["msb_mal", "asb_mal"], True), rate(["curated"], False), rate(["msb_ben"], False)))
    rows.sort(key=lambda r: -(r[2][0] / max(1, r[2][1])))
    f = lambda x: f"{100*x[0]/max(1,x[1]):.1f}% ({x[0]}/{x[1]})" + (f", {x[2]} no result" if x[2] else "")
    out = ["| Scanner | Reading | Malware caught | Hand-checked legit passed | Research benign passed |", "|---|---|---|---|---|"]
    for t, m, a, b, c in rows:
        name = f"**{META[t][0]}**" if t == "husk" else META[t][0]
        out.append(f"| {name} {META[t][1]} | {m} | {f(a)} | {f(b)} | {f(c)} |")
    return "\n".join(out)
if __name__ == "__main__":
    for sub, title in ((False, "Full sample (699 skills)"), (True, "Same 200-skill subset")):
        for m in ("strict", "loose"):
            print(f"### {title}, {m}\n"); print(table(sub, m)); print()
