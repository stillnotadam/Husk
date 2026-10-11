"""runner.py for this machine: runs one tool over sample_local.json ([orig_path, local_path]
pairs), stores records keyed by the ORIGINAL path so they line up with the 2026-09 raw data."""
import json, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
H = os.path.expanduser("~")
TOOLS = {
    "huskdev": {"cmd": H + "/cvenv/huskdev/bin/python " + H + "/cbench/husk_one.py '{path}'", "timeout": 60},
    "husk": {"cmd": H + "/cvenv/husk/bin/python " + H + "/cbench/husk_one.py '{path}'", "timeout": 60},
    "cisco": {"cmd": H + "/cvenv/cisco/bin/skill-scanner scan '{path}' --format json --lenient", "timeout": 120},
    "agentauditkit": {"cmd": H + "/cvenv/aak/bin/agent-audit-kit scan '{path}' --format json", "timeout": 60},
    "secureai": {"cmd": "bash " + H + "/cbench/sa.sh '{path}'", "timeout": 60},
}
tool, workers = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 4
cfg = TOOLS[tool]
S = json.load(open(H + "/cbench/sample_local.json"))
out = f"{H}/cbench/raw/{tool}.jsonl"
done = set()
if os.path.exists(out):
    for l in open(out):
        try: done.add(json.loads(l)["path"])
        except Exception: pass
jobs = [(k, o, p) for k, L in S.items() for o, p in L if o not in done]
def one(job):
    k, o, p = job; t = time.time()
    try:
        r = subprocess.run(cfg["cmd"].format(path=p), shell=True, capture_output=True, text=True,
                           timeout=cfg["timeout"], cwd="/tmp")
        return dict(set=k, path=o, code=r.returncode, out=r.stdout[-3000000:], err=r.stderr[-3000:], secs=round(time.time()-t, 2))
    except subprocess.TimeoutExpired:
        return dict(set=k, path=o, code=None, out="", err="TIMEOUT", secs=round(time.time()-t, 2))
with open(out, "a") as f, ThreadPoolExecutor(workers) as ex:
    for i, rec in enumerate(ex.map(one, jobs), 1):
        f.write(json.dumps(rec) + "\n"); f.flush()
        if i % 50 == 0: print(f"{tool}: {i}/{len(jobs)}", flush=True)
print(f"{tool}: done ({len(jobs)} new)", flush=True)
