"""Run one scanner over the fixed sample. Usage: runner.py <tool> <workers>
Each tool is a shell command template with {path}; raw stdout/stderr/exit code
are stored per skill (JSONL, resumable) so verdicts can be re-scored later."""
import json, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
TOOLS = json.load(open("/home/claude/cbench/tools.json"))
tool, workers = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 4
cfg = TOOLS[tool]; S = json.load(open(os.environ.get("SAMPLE", "/home/claude/cbench/sample.json")))
out = f"/home/claude/cbench/raw/{tool}.jsonl"; os.makedirs(os.path.dirname(out), exist_ok=True)
done = set()
if os.path.exists(out):
    for l in open(out):
        try: done.add(json.loads(l)["path"])
        except Exception: pass
jobs = [(k, p) for k, L in S.items() for p in L if p not in done]
def one(job):
    k, p = job; t = time.time()
    try:
        r = subprocess.run(cfg["cmd"].format(path=p), shell=True, capture_output=True, text=True,
                           timeout=cfg.get("timeout", 60), cwd=cfg.get("cwd"), env={**os.environ, **cfg.get("env", {})})
        rec = dict(set=k, path=p, code=r.returncode, out=r.stdout[-3000000:], err=r.stderr[-3000:], secs=round(time.time()-t, 2))
    except subprocess.TimeoutExpired:
        rec = dict(set=k, path=p, code=None, out="", err="TIMEOUT", secs=round(time.time()-t, 2))
    return rec
with open(out, "a") as f, ThreadPoolExecutor(workers) as ex:
    for i, rec in enumerate(ex.map(one, jobs), 1):
        f.write(json.dumps(rec) + "\n"); f.flush()
        if i % 50 == 0: print(f"{tool}: {i}/{len(jobs)}", flush=True)
print(f"{tool}: done ({len(jobs)} new)", flush=True)
