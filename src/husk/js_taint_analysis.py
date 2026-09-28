"""
AST-based taint analysis for JavaScript and TypeScript.

The counterpart to taint_analysis.py (Python). Most agent skills that ship code
ship JS/TS, and until now Husk only ran generic regex patterns on them - it
could not follow a value from a sensitive source, through variable assignments,
to a dangerous sink the way it does for Python. This module closes that: it
parses JS/TS with esprima (a real, pure-Python JS parser), walks the AST, and
reports flows where data from a source (process.env, request input, a
credential file read, a fetched network response) reaches a sink (a shell exec,
eval/Function, or a network send).

Same discipline as the Python engine: it tracks assignments so the source and
sink can be far apart, and it is deliberately conservative - a file it cannot
parse yields no taint findings (the generic pattern checks still run on it),
and a finding requires a real source->variable->sink chain, not mere
co-occurrence.

TypeScript: esprima parses JavaScript, so TS-only syntax (type annotations,
interfaces, generics) is stripped first with a light preprocessor. If stripping
still leaves something unparseable, the file is skipped rather than guessed at.
"""

import re

try:
    import esprima
    _HAVE_ESPRIMA = True
except ImportError:  # pragma: no cover - esprima is a declared dependency
    _HAVE_ESPRIMA = False


# ---- source / sink vocabulary -------------------------------------------

# A member expression like process.env is a source. Stored as the dotted path.
_SOURCE_MEMBER_PREFIXES = (
    "process.env",           # environment (secrets)
    "req.body", "req.query", "req.params", "req.headers",
    "request.body", "request.query", "request.headers",
)

# Function/method calls whose return value is tainted (credential/file reads,
# network responses). Matched by the callee's trailing member name.
_SOURCE_CALL_NAMES = {
    "readFileSync": "a file read",
    "readFile": "a file read",
}

# Sinks: callee member name -> human description.
_EXEC_SINKS = {
    "exec": "a shell command execution (child_process.exec)",
    "execSync": "a synchronous shell execution (child_process.execSync)",
    "spawn": "a process spawn (child_process.spawn)",
    "spawnSync": "a synchronous process spawn",
    "execFile": "a file execution (child_process.execFile)",
}
_EVAL_SINKS = {
    "eval": "eval() - runtime code execution",
    "Function": "the Function constructor - runtime code execution",
}
_NET_SINKS = {
    "post": "a network POST",
    "put": "a network PUT",
    "request": "a network request",
    "fetch": "a network fetch",
    "sendMail": "an email send",
    "send": "a network send",
}

# A credential-shaped path literal inside a file read makes that read a source.
_CRED_PATH = re.compile(r"\.env\b|\.aws|\.ssh|credentials|id_rsa|id_ed25519|\.npmrc|\.netrc|\.pem\b", re.IGNORECASE)


class JsTaintFinding:
    def __init__(self, line, source_desc, sink_desc, var_name, source_line=None):
        self.line = line
        self.source_desc = source_desc
        self.sink_desc = sink_desc
        self.var_name = var_name
        self.source_line = source_line

    def __str__(self):
        origin = f" (from line {self.source_line})" if self.source_line else ""
        return (
            f"Line {self.line}: JS/TS taint-tracked data flow - a value from "
            f"{self.source_desc}{origin} (via '{self.var_name}') reaches "
            f"{self.sink_desc}. Found by AST analysis of variable assignments, "
            f"not text matching."
        )

    def trace(self):
        src = f"line {self.source_line}" if self.source_line else "an earlier statement"
        return [
            f"1. SOURCE ({src}): a value is read from {self.source_desc}.",
            f"2. FLOW: it is held in '{self.var_name}' and carried through the code.",
            f"3. SINK (line {self.line}): '{self.var_name}' reaches {self.sink_desc}.",
        ]

    def to_dict(self):
        return {"sink_line": self.line, "source_line": self.source_line,
                "source": self.source_desc, "variable": self.var_name,
                "sink": self.sink_desc, "trace": self.trace()}


# ---- TypeScript stripping + parsing --------------------------------------

def _strip_ts(code):
    """Remove TS-only syntax esprima can't parse. Conservative - if this
    leaves something invalid, parsing simply fails and the file is skipped."""
    code = re.sub(r"\binterface\s+\w+\s*\{[^{}]*\}", "", code)
    code = re.sub(r"\btype\s+\w+\s*=\s*[^;\n]+;", "", code)
    # generic type args on calls/annotations: <T>, <string, number>
    code = re.sub(r":\s*[A-Za-z_$][\w$.\[\]]*(?:<[^<>;=\n]*>)?(?:\[\])?(?:\s*\|\s*[A-Za-z_$][\w$.\[\]]*)*", "", code)
    code = re.sub(r"\bas\s+[A-Za-z_$][\w$.<>\[\]]*", "", code)
    code = re.sub(r"\b(public|private|readonly|protected|declare)\s+", "", code)
    code = re.sub(r"<[A-Za-z_$][\w$,\s.<>\[\]]*>(?=\s*\()", "", code)
    return code


def _parse(code):
    """Return an esprima AST or None. Tries plain, TS-stripped, and
    async-wrapped variants (the last enables top-level await)."""
    if not _HAVE_ESPRIMA:
        return None
    stripped = _strip_ts(code)
    variants = [
        code, stripped,
        f"async function __husk_wrap__() {{\n{code}\n}}",
        f"async function __husk_wrap__() {{\n{stripped}\n}}",
    ]
    for v in variants:
        for parse in (esprima.parseModule, esprima.parseScript):
            try:
                return parse(v, tolerant=True, loc=True)
            except Exception:  # noqa: BLE001,S112 - try the next parse variant
                continue
    return None


# ---- AST helpers ---------------------------------------------------------

def _member_path(node):
    """Dotted path of a MemberExpression/Identifier, e.g. 'process.env' or
    'axios.post'. Returns '' for anything else."""
    if node is None:
        return ""
    t = node.type
    if t == "Identifier":
        return node.name
    if t == "MemberExpression":
        obj = _member_path(node.object)
        prop = node.property.name if getattr(node.property, "type", "") == "Identifier" else ""
        return f"{obj}.{prop}" if obj and prop else (obj or prop)
    return ""


def _callee_name(call):
    """Trailing name of a call's callee: 'post' for axios.post(...), 'exec'
    for exec(...) or child_process.exec(...)."""
    callee = call.callee
    if getattr(callee, "type", "") == "Identifier":
        return callee.name
    if getattr(callee, "type", "") == "MemberExpression":
        prop = callee.property
        return prop.name if getattr(prop, "type", "") == "Identifier" else ""
    return ""


def _names_in(node, out):
    """Collect all identifier names referenced anywhere under node."""
    if node is None or not hasattr(node, "type"):
        if isinstance(node, list):
            for x in node:
                _names_in(x, out)
        return
    if node.type == "Identifier":
        out.add(node.name)
    for key in dir(node):
        if key.startswith("_") or key in ("type", "name"):
            continue
        try:
            val = getattr(node, key)
        except Exception:  # noqa: BLE001,S112
            continue
        if hasattr(val, "type"):
            _names_in(val, out)
        elif isinstance(val, list):
            for x in val:
                if hasattr(x, "type"):
                    _names_in(x, out)


def _expr_source(node):
    """If an expression reads from a source, return (description, True).
    Handles process.env member reads, whole process.env, and cred-file reads."""
    if node is None or not hasattr(node, "type"):
        return None, False
    # member read: process.env, process.env.X, req.body...
    path = _member_path(node)
    for prefix in _SOURCE_MEMBER_PREFIXES:
        if path == prefix or path.startswith(prefix + "."):
            if path == "process.env":
                # the WHOLE environment object - bulk secret capture
                return "the entire environment (process.env)", True
            if path.startswith("process.env."):
                # a single named env var - a secret, but sending it to its own
                # API is normal; only dangerous reaching exec/eval
                return "an environment variable", True
            return "request/user input", True
    # a call whose name is a source (readFileSync of a cred path)
    if node.type in ("CallExpression", "AwaitExpression"):
        call = node.argument if node.type == "AwaitExpression" else node
        if getattr(call, "type", "") == "CallExpression":
            name = _callee_name(call)
            if name in _SOURCE_CALL_NAMES:
                # only a source if the read targets a credential-shaped path
                for arg in call.arguments:
                    if getattr(arg, "type", "") == "Literal" and _CRED_PATH.search(str(getattr(arg, "value", ""))):
                        return "a credential file", True
    return None, False


def _line_of(node):
    loc = getattr(node, "loc", None)
    if loc and getattr(loc, "start", None):
        return loc.start.line
    return 0


# ---- the analysis --------------------------------------------------------

def analyze_js_taint(source_code):
    """Return a list of JsTaintFinding for source->sink flows. Never raises;
    an unparseable file returns []."""
    ast = _parse(source_code)
    if ast is None:
        return []

    tainted = {}   # var name -> (description, source_line)
    findings = []

    def record_assignment(target_name, value_node):
        desc, is_src = _expr_source(value_node)
        if is_src:
            tainted[target_name] = (desc, _line_of(value_node))
            return
        used = set()
        _names_in(value_node, used)
        hit = used & tainted.keys()
        if hit:
            tainted[target_name] = tainted[next(iter(hit))]

    def check_sink(call):
        name = _callee_name(call)
        kind = None
        if name in _EXEC_SINKS:
            kind, desc = "exec", _EXEC_SINKS[name]
        elif name in _EVAL_SINKS:
            kind, desc = "eval", _EVAL_SINKS[name]
        elif name in _NET_SINKS:
            kind, desc = "net", _NET_SINKS[name]
        if kind is None:
            return
        args_names = set()
        for arg in call.arguments:
            _names_in(arg, args_names)
        hit = args_names & tainted.keys()
        if hit:
            var = next(iter(hit))
            src_desc, src_line = tainted[var]
            # env-derived data reaching a network sink, or any tainted value
            # reaching exec/eval, is the dangerous case.
            dangerous = (
                kind in ("exec", "eval")  # any tainted value executed
                or src_desc in ("the entire environment (process.env)",  # bulk env anywhere
                                "a credential file")           # credential file anywhere
            )
            if dangerous:
                findings.append(JsTaintFinding(
                    line=_line_of(call), source_desc=src_desc,
                    sink_desc=desc, var_name=var, source_line=src_line))

    def walk(node):
        if node is None:
            return
        if isinstance(node, list):
            for x in node:
                walk(x)
            return
        if not hasattr(node, "type"):
            return

        t = node.type
        if t == "VariableDeclaration":
            for decl in node.declarations:
                if getattr(decl.id, "type", "") == "Identifier" and decl.init is not None:
                    record_assignment(decl.id.name, decl.init)
                elif getattr(decl.id, "type", "") == "ObjectPattern" and decl.init is not None:
                    # const {A, B} = process.env
                    d, is_src = _expr_source(decl.init)
                    if is_src:
                        for prop in decl.id.properties:
                            key = getattr(getattr(prop, "value", None), "name", None) or \
                                  getattr(getattr(prop, "key", None), "name", None)
                            if key:
                                tainted[key] = (d, _line_of(decl.init))
        elif t == "AssignmentExpression":
            if getattr(node.left, "type", "") == "Identifier":
                record_assignment(node.left.name, node.right)
        elif t == "CallExpression":
            check_sink(node)

        # recurse into every child
        for key in dir(node):
            if key.startswith("_") or key in ("type", "name", "loc", "range"):
                continue
            try:
                val = getattr(node, key)
            except Exception:  # noqa: BLE001,S112
                continue
            if hasattr(val, "type") or isinstance(val, list):
                walk(val)

    walk(ast)

    # dedupe by (line, var, sink)
    seen, out = set(), []
    for f in findings:
        k = (f.line, f.var_name, f.sink_desc)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
