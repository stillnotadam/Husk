"""Husk analysis engine.

The regex checks in skill_scanner.py match the shape of an attack. The
engine models what code does: front ends (shell, Python, JavaScript) turn code into
values carrying labels (remote, secret, decoded) with a provenance trail,
and record every time such a value reaches a sink (exec, send, persist).
Rules - data, in rules/*.yml - say which of those flows are findings.

Every finding carries its evidence chain, e.g.
    Line 7: [HUSK-RCE-001 high] downloaded code is executed:
    line 3 fetches https://x/p -> line 3 saves it to /tmp/p -> line 7 runs /tmp/p with sh
"""
import os
import re

from .extract import snippets
from .js_frontend import analyze_js
from .model import CURRENT_FILE, Files, Flow, Step, Value
from .python_frontend import analyze_python
from .rules import Rule, RuleError, load_rules, parse_rules
from .shell import analyze_shell

__all__ = ["Flow", "Rule", "RuleError", "Step", "Value", "analyze", "analyze_flows", "analyze_package",
           "findings_for", "load_rules", "parse_rules", "report"]

SOFT_MARKER = "▸SOFT▸"  # same marker skill_scanner/gate use for info-only findings


class Context:
    def __init__(self):
        self.flows = []
        self.files = Files()        # shared by every front end, so a file written in one
        self.module_returns = {}    # snippet or language and run in another is connected


def analyze_flows(text, ext, shebang_shell=False, ctx=None, module=None):
    """All flows found in one file's text. With a shared ctx (a package),
    `module` names the file for imports from other files."""
    ctx = ctx or Context()
    start = len(ctx.flows)
    shell_state = None
    for lang, code, line in snippets(text, ext, shebang_shell):
        if lang == "shell":
            shell_state = analyze_shell(code, ctx, line, state=shell_state)
        elif lang == "python":
            a = analyze_python(code, ctx, line)
            if module and a is not None and a.returns:
                ctx.module_returns.setdefault(("py", module), {}).update(a.returns)
        elif lang == "js":
            a = analyze_js(code, ctx, line)
            if module and a is not None and a.returns:
                ctx.module_returns.setdefault(("js", module), {}).update(a.returns)
    return ctx.flows[start:]


MAX_PACKAGE_FILES = 400


def analyze_package(items, rules=None):
    """Flows whose evidence spans two or more files of one package.

    items: (relative path, text, ext, shebang_shell) for each file. Two rounds:
    the first learns what every file writes to disk and what its functions
    return; the second analyses each file knowing that, so a download saved
    by setup.sh and run from SKILL.md, or fetched in helpers.py and executed
    in main.py, is one flow. Flows inside a single file are left to the
    per-file scan, so nothing is reported twice."""
    items = list(items)[:MAX_PACKAGE_FILES]
    ctx = Context()
    for _ in range(2):
        del ctx.flows[:]
        for rel, text, ext, shebang in items:
            token = CURRENT_FILE.set(rel)
            try:
                analyze_flows(text, ext, shebang, ctx=ctx, module=os.path.splitext(os.path.basename(rel))[0])
            except RecursionError:
                continue
            finally:
                CURRENT_FILE.reset(token)
    cross = [f for f in ctx.flows if len({s.file for s in f.value.trail} | {f.step.file}) > 1]
    return report(cross, rules)  # each finding's "file" is where the sink is


def _location_trusted(loc):
    """loc is "host/path". Same matching as the regex layer's
    _url_is_trusted_installer (exact host, path prefix where one is listed),
    plus GitHub release assets: binaries published on a repository's
    Releases page are how most CLI tools ship."""
    from ..skill_scanner import TRUSTED_INSTALL_HOSTS  # noqa: PLC0415 - skill_scanner imports the engine
    host, _, path = loc.partition("/")
    path = "/" + path
    if host == "github.com" and re.match(r"^/[\w.-]+/[\w.-]+/releases/(?:latest/)?download/", path):
        return True
    for entry in TRUSTED_INSTALL_HOSTS:
        t_host, _, t_path = entry.lower().partition("/")
        if host == t_host and (not t_path or path.lower().startswith("/" + t_path)):
            return True
    return False


def _trusted(locations):
    return bool(locations) and all(_location_trusted(loc) for loc in locations)


def report(flows, rules=None):
    """Structured findings, one per (rule, line): what `husk explain --json`
    prints and what the finding strings are built from."""
    rules = load_rules() if rules is None else rules
    out, seen = [], set()
    for flow in flows:
        rule = next((r for r in rules if r.matches(flow)), None)
        if rule is None:
            continue
        severity = rule.severity
        if rule.trusted_installers and "remote" in flow.value.labels and _trusted(flow.value.hosts):
            severity = rule.trusted_installers
        key = (rule.id, flow.step.file, flow.step.line)
        if key in seen:
            continue
        seen.add(key)
        steps = [s for s in flow.value.trail if s != flow.step] + [flow.step]
        out.append({"rule": rule.id, "severity": severity, "title": rule.title, "line": flow.step.line,
                    "language": flow.language, "chain": flow.chain(),
                    "steps": [{"line": s.line, "text": s.text, **({"file": s.file} if s.file else {})} for s in steps],
                    **({"file": flow.step.file} if flow.step.file else {})})
    return out


def findings_for(flows, rules=None):
    """Turn flows into finding strings, one per (rule, line)."""
    return [f"{SOFT_MARKER if r['severity'] == 'info' else ''}Line {r['line']}: "
            f"[{r['rule']} {r['severity']}] {r['title']}: {r['chain']}" for r in report(flows, rules)]


def analyze(text, ext, shebang_shell=False, rules=None):
    """Engine findings for one file. Never raises on odd input: a front end
    that cannot parse something simply finds nothing in it."""
    try:
        flows = analyze_flows(text, ext, shebang_shell)
    except RecursionError:
        return []
    return findings_for(flows, rules)
