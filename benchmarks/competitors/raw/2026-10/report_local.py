"""2026-10 refresh of the head-to-head on the 549 sample skills available
locally (MalSkillBench malicious 150, hand-checked legit 249, MalSkillBench
benign 150). Tools with a new release were re-run (raw/<tool>.jsonl here);
every other tool is re-scored from its 2026-09 raw output on the same 549."""
import gzip, json, os, sys
sys.argv = [sys.argv[0]]
H = os.path.expanduser("~")
os.chdir(H + "/cbench")
import score
OLD = os.environ.get("HUSK_OLD_RAW", "benchmarks/competitors/raw")  # the 2026-09 raw/*.jsonl.gz
META = json.load(open("meta.json"))
NEW = {"husk": "1.4.0", "huskdev": "1.4.1", "cisco": "2.2.2", "agentauditkit": "0.6.20", "secureai": "0.12.0"}
LOCAL = {o for L in json.load(open("sample_local.json")).values() for o, _ in L}
SMALL = {p for v in json.load(open("sample_small.json")).values() for p in v} & LOCAL

def load(tool):
    f = f"raw/{tool}.jsonl"
    if os.path.exists(f):
        return list({r["path"]: r for r in map(json.loads, open(f))}.values()), NEW[tool]
    g = f"{OLD}/{tool}.jsonl.gz"
    if os.path.exists(g):
        return list({r["path"]: r for r in map(json.loads, gzip.open(g, "rt"))}.values()), META[tool][1]
    return None, None

def rows(subset):
    want = SMALL if subset else LOCAL
    out = []
    tools = sorted(set(META) | {"huskdev"})
    for tool in tools:
        recs, ver = load(tool)
        if recs is None:
            continue
        recs = [r for r in recs if r["path"] in want]
        if len(recs) < len(want) * 0.95:
            continue
        sev = {}
        for r in recs:
            sev.setdefault(r["set"], []).append(score.sev("husk" if tool == "huskdev" else tool, r))
        for mode, th in (("strict", 4), ("loose", 2)):
            if tool.startswith("husk") and mode == "loose":
                continue
            def rate(k, mal):
                v = sev.get(k, []); s = [x for x in v if x is not None]
                return sum(1 for x in s if (score.RANK[x] >= th) == mal), len(s), len(v) - len(s)
            name = "Husk" if tool.startswith("husk") else META[tool][0]
            out.append((name, ver, mode, rate("msb_mal", True), rate("curated", False), rate("msb_ben", False), tool.startswith("husk")))
    return out

def table(subset, mode):
    f = lambda x: f"{100*x[0]/max(1,x[1]):.1f}% ({x[0]}/{x[1]})" + (f", {x[2]} no result" if x[2] else "")
    rs = [r for r in rows(subset) if r[2] == mode or r[6]]
    rs.sort(key=lambda r: -(r[3][0] / max(1, r[3][1])))
    L = ["| Scanner | Reading | Malware caught | Hand-checked legit passed | Research benign passed |", "|---|---|---|---|---|"]
    for name, ver, m, a, b, c, h in rs:
        nm = f"**{name}** {ver}" if h else f"{name} {ver}"
        L.append(f"| {nm} | {m} | {f(a)} | {f(b)} | {f(c)} |")
    return "\n".join(L)

for sub, title in ((False, f"549 skills"), (True, f"Shared {len(SMALL)}-skill subset")):
    for m in ("strict", "loose"):
        print(f"### {title}, {m}\n"); print(table(sub, m)); print()
