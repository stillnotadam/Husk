"""Fetch just one skill's folder from a huge GitHub repo: list the repo tree via
the API once, find the folder holding <skill>/SKILL.md, download only those files."""
import json, os, sys, urllib.request, tempfile
UA = {"User-Agent": "husk-bench"}
_TREES = {}
def tree(owner, repo):
    k = f"{owner}/{repo}"
    if k not in _TREES:
        with urllib.request.urlopen(urllib.request.Request(f"https://api.github.com/repos/{k}/git/trees/HEAD?recursive=1", headers=UA), timeout=60) as r:
            d = json.load(r)
        _TREES[k] = ([e["path"] for e in d["tree"] if e["type"] == "blob"], d.get("truncated"))
    return _TREES[k]
def fetch(ref, cap_files=300):
    owner, repo, skill = ref.split("/", 2); skill = skill.split("/")[-1].lower()
    paths, trunc = tree(owner, repo)
    cands = [p[:-len("SKILL.md")] for p in paths if p.endswith("/SKILL.md") and p[:-len("/SKILL.md")].split("/")[-1].lower() == skill]
    if not cands: return None, f"no folder named {skill} (tree truncated={trunc})"
    base = min(cands, key=lambda c: (c.count("/"), len(c)))
    files = [p for p in paths if p.startswith(base)][:cap_files]
    d = tempfile.mkdtemp(prefix="husk_mondoo_")
    for p in files:
        dest = os.path.join(d, p[len(base):]); os.makedirs(os.path.dirname(dest), exist_ok=True)
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/" + urllib.request.quote(p)
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r, open(dest, "wb") as fh:
            fh.write(r.read(4 * 1024 * 1024))
    return d, base
