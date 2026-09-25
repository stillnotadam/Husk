"""
Husk - AST-based taint tracking (Tier 4.1).

WHY THIS EXISTS
----------------
Every other check in this project (skill_scanner.py) is regex/text-
pattern based. That works well for a lot of real attacks, but it has a
real structural weakness: it can only see patterns that are textually
close together, or shaped exactly the way the pattern expects. Several
real bugs found and hand-patched this session were exactly this
failure mode:
- credential_theft detection missed a real AWS-credential-stealing
  sample because the credential filename was defined in a list at the
  top of the file, and opened via a loop variable much later -
  "structurally connected but not textually adjacent"
- the shell=True detector broke on nested function calls between the
  subprocess call and shell=True, because a naive regex counts
  parentheses, not real code structure

A proper fix for this whole CLASS of bug is taint tracking: parse the
code into a real syntax tree (Python's own `ast` module - no new
dependency), then trace whether a value that came from a sensitive
SOURCE (reading a credential file, an environment variable) can reach
a dangerous SINK (a network call, exec, a subprocess call) through any
chain of variable assignments - regardless of how far apart they sit
in the text, or how many other function calls happen in between.

This is a genuine, different detection layer from skill_scanner.py's
regex checks, not a replacement for them - both run, and either can
catch something the other misses.

HONEST SCOPE
------------
This started as a v1, purely intra-procedural tracker. Real-world
testing against the exact sample this module was built for (a real
AWS-credential-theft skill) found that pure intra-procedural tracking
missed it entirely, because the real code splits work across two
functions - a common, idiomatic Python pattern (a helper that gathers
data and returns it, a caller that sends it) that crosses a function
boundary. A LIGHT inter-procedural extension was added to close this
specific gap: the tracker now knows whether a given function's `return`
statement returns tainted data, and propagates that taint to whatever
variable captures the result at any call site elsewhere in the file
(including nested inside other calls, e.g. `json.dumps(_gather())`).

This is still not full inter-procedural tracking, but a real gap was
closed since: taint now DOES flow INTO a function through its
parameters, for the specific, common shape of a small helper that
takes a value and immediately uses it in a sink (e.g.
`def leak(data): requests.post(url, data=data)`, called as
`leak(stolen_value)`). This does NOT re-trace taint propagating deeper
inside a callee's own body (if the callee reassigns the parameter to
another variable before using it, that's outside this check's scope),
and it does not follow calls across module/file boundaries. It closes
the specific "gather then return, call then send" and "helper takes a
tainted value and sends it" patterns found in real testing, not the
fully general case of arbitrary-depth cross-function data flow.
"""

import ast
import warnings

# Function/attribute names whose return value should be treated as
# potentially sensitive (credentials, secrets, environment data).
SOURCE_CALL_NAMES = {
    "getenv", "environ",  # os.getenv(...), os.environ[...] / .get(...)
}

# Filename substrings that make an `open(...)` call a sensitive source,
# regardless of how the path was constructed (a literal, a variable, a
# list element opened in a loop - AST tracking doesn't care).
CREDENTIAL_FILENAME_MARKERS = [
    ".env", ".pem", "credentials.json", "service-account.json",
    ".aws/credentials", ".ssh/id_rsa", "id_rsa", "wallet",
    "metamask", "phantom", "login data", "cookies",
    "bash_history", "zsh_history", ".netrc", "id_dsa", "id_ed25519",
]

# Dangerous sink functions: if a tainted value reaches any argument of
# one of these calls, that's the finding.
SINK_CALL_NAMES = {
    "system": "os.system - direct shell execution",
    "popen": "subprocess.Popen/os.popen - process execution",
    "run": "subprocess.run - process execution",
    "call": "subprocess.call - process execution",
    "eval": "eval() - arbitrary code execution",
    "exec": "exec() - arbitrary code execution",
    "post": "a network POST call - likely exfiltration",
    "put": "a network PUT call - likely exfiltration",
    "urlopen": "urllib network call",
    "send": "a network send call",
}


class TaintFinding:
    def __init__(self, line, source_desc, sink_desc, var_name):
        self.line = line
        self.source_desc = source_desc
        self.sink_desc = sink_desc
        self.var_name = var_name

    def __str__(self):
        return (
            f"Line {self.line}: taint-tracked data flow - a value from "
            f"{self.source_desc} (via variable '{self.var_name}') reaches "
            f"{self.sink_desc}. This flow was found by tracing actual "
            f"variable assignments through the code (AST-based analysis), "
            f"not by pattern-matching nearby text - it would be caught even "
            f"if the source and sink are far apart or separated by other code."
        )


def _call_name(node):
    """Returns the simple function/attribute name of a Call node, e.g.
    'run' for both `subprocess.run(...)` and `run(...)`."""
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _extract_path_string(node):
    """
    Attempts to extract a plain string from a path-like expression,
    seeing through common wrapper calls that don't change the
    underlying path's meaning: os.path.expanduser(...), Path(...),
    pathlib.Path(...), str(...). Found necessary via real-world
    testing: the exact real AWS-credential-theft sample this module
    was built to catch wraps its literal path in
    os.path.expanduser(p) - a bare literal-string check alone (v1's
    first version) never fires on any real code using this extremely
    common pattern.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Call) and node.args:
        name = _call_name(node)
        if name in ("expanduser", "Path", "str", "abspath", "normpath", "realpath"):
            return _extract_path_string(node.args[0])
    return None


def _is_source_call(node):
    """True if this Call node reads sensitive data: os.getenv/environ,
    or open() on a credential-shaped path."""
    name = _call_name(node)
    if name in SOURCE_CALL_NAMES:
        return True, "an environment variable"
    if name == "open" and node.args:
        path_str = _extract_path_string(node.args[0])
        if path_str is not None:
            path_lower = path_str.lower()
            for marker in CREDENTIAL_FILENAME_MARKERS:
                if marker in path_lower:
                    return True, f"a credential-shaped file path ('{marker}')"
    return False, None


def _is_sink_call(node):
    name = _call_name(node)
    if name in SINK_CALL_NAMES:
        return True, SINK_CALL_NAMES[name]
    return False, None


def _names_used_in(node):
    """Returns the set of all Name identifiers referenced anywhere
    inside an expression subtree (used to check if a tainted variable
    appears anywhere in an assignment's right-hand side or a call's
    arguments, regardless of how deeply nested)."""
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names


def _called_function_names_in(node):
    """Returns the set of function/attribute names CALLED anywhere
    inside an expression subtree, however deeply nested - e.g. for
    `json.dumps(_gather()).encode("utf-8")`, returns {'dumps',
    '_gather', 'encode'}. Needed because a tracked tainted-returning
    function call is often nested inside other calls, not the
    outermost one - found via the real credential-theft sample this
    module targets, where the actual call shape is
    `json.dumps(_gather()).encode(...)`, not a bare `_gather()`."""
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _call_name(child)
            if name:
                names.add(name)
    return names


def _list_contains_credential_marker(list_node):
    """True if an ast.List literal contains at least one string constant
    matching a known credential-filename marker - used to taint loop
    variables in `for p in ['~/.aws/credentials', ...]:` patterns,
    exactly the real shape found in a real AWS-credential-theft sample
    during testing (paths defined in a list, opened later via the loop
    variable - structurally connected, not textually adjacent, which
    is precisely the class of bug this whole module exists to catch)."""
    if not isinstance(list_node, ast.List):
        return False
    for elt in list_node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            path_lower = elt.value.lower()
            if any(marker in path_lower for marker in CREDENTIAL_FILENAME_MARKERS):
                return True
    return False


def _collect_function_defs(tree):
    """
    Returns {func_name: (param_names, body)} for every function
    definition anywhere in the tree, collected in one pass up front.
    This lets a call site check what happens inside a called function
    without needing the call to occur after the definition in file
    order (Python itself doesn't require that either, for top-level
    functions).
    """
    defs = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            param_names = [a.arg for a in node.args.args]
            defs[node.name] = (param_names, node.body)
    return defs


def _function_sinks_on_param(body, param_name):
    """
    Returns a sink description if the function body (a list of
    statements) contains a sink call reachable from param_name -
    either directly in a sink call's arguments, or after any number
    of reassignments within the function body first.

    Originally scoped to only the direct case (a small helper that
    takes a value and immediately sends/executes it). Found via real
    testing against a real credential-reconnaissance sample: the
    actual chain was param -> reassigned into a dict key -> that dict
    passed to json.dumps().encode() -> reassigned again -> wrapped in
    a Request(data=...) object -> passed to urlopen() - four
    reassignments deep, well past the direct-only check. Extended with
    its own small, LOCALLY SCOPED taint set (never touching
    analyze_taint_flows's shared `tainted` dict, so this can't bleed
    taint across unrelated call sites or change the main walker's
    existing, tested behavior), reusing the same _is_sink_call/
    _names_used_in primitives the rest of this module already uses.
    Still intra-procedural only - taint doesn't follow INTO a further
    nested function call from here, matching this module's existing,
    stated scope.
    """
    local_tainted = {param_name}

    def walk(stmts):
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                rhs_names = _names_used_in(stmt.value)
                if rhs_names & local_tainted:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            local_tainted.add(target.id)
                        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                            local_tainted.add(target.value.id)

            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    is_sink, sink_desc = _is_sink_call(node)
                    if not is_sink:
                        continue
                    names_in_args = set()
                    for arg in node.args:
                        names_in_args |= _names_used_in(arg)
                    for kw in node.keywords:
                        if kw.value is not None:
                            names_in_args |= _names_used_in(kw.value)
                    if names_in_args & local_tainted:
                        return sink_desc

            nested_bodies = []
            if isinstance(stmt, (ast.If, ast.For, ast.While, ast.With)):
                nested_bodies.append(stmt.body)
                nested_bodies.append(getattr(stmt, "orelse", []))
            elif isinstance(stmt, ast.Try):
                nested_bodies.append(stmt.body)
                for handler in stmt.handlers:
                    nested_bodies.append(handler.body)
                nested_bodies.append(stmt.orelse)
                nested_bodies.append(stmt.finalbody)
            for nested in nested_bodies:
                result = walk(nested)
                if result:
                    return result
        return None

    return walk(body)


def _analyze_taint_flows_once(source_code, filename, seed_tainted_returning):
    """
    Single pass of the real analysis, seeded with an already-known set
    of tainted-returning functions (see analyze_taint_flows below for
    why a single pass alone isn't order-independent, and needs this).
    Returns (findings, tainted_returning_functions) - the second so
    the caller can use it to seed a further pass.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(source_code, filename=filename)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # ValueError: source containing null bytes (found on a real ClawHub
        # skill - it crashed the whole package scan). RecursionError /
        # MemoryError: pathologically nested or huge input. Taint analysis
        # is skipped for that file; every other check still runs on it.
        return [], {}

    findings = []
    # func_name -> (param_names, body) for every function definition in
    # the file, collected up front so parameter-taint checks below
    # don't depend on call-site/definition order.
    function_defs = _collect_function_defs(tree)
    # var_name -> description of why it's tainted
    tainted = {}
    # var_name -> True, for variables assigned a list literal containing
    # a credential-marker string (tracked separately from `tainted`
    # itself, since the list variable holds paths, not secret data -
    # it's what PRODUCES tainted values when iterated).
    credential_list_vars = set()
    # func_name -> taint description, for functions whose `return`
    # statement returns a tainted value. Found necessary via real-world
    # testing: the actual real credential-theft sample this module was
    # built for splits work across two functions - a helper that reads
    # credentials and returns them, and main() that calls the helper
    # and sends the result. This is an extremely common, idiomatic
    # Python pattern (separating "gather" from "send"), and a v1 that
    # only tracks taint within one function misses it entirely. This
    # is deliberately a LIGHT inter-procedural extension, not full
    # cross-module tracking: it only knows "this specific function,
    # called with no arguments considered, returns tainted data" - it
    # does not track taint flowing INTO a function through its
    # parameters, only OUT through its return value.
    tainted_returning_functions = dict(seed_tainted_returning)

    # Walk top-level statements plus function bodies (intra-procedural:
    # each function's own body is tracked independently, taint doesn't
    # cross function boundaries in this v1).
    def walk_body(body, current_func=None):
        for stmt in body:
            # Assignment: check if the RHS contains a source call, or
            # already-tainted names, and propagate.
            if isinstance(stmt, ast.Assign):
                rhs = stmt.value
                source_hit = False
                source_desc = None
                if isinstance(rhs, ast.Call):
                    is_src, desc = _is_source_call(rhs)
                    if is_src:
                        source_hit = True
                        source_desc = desc
                if not source_hit:
                    used = _names_used_in(rhs)
                    tainted_used = used & tainted.keys()
                    if tainted_used:
                        source_hit = True
                        source_desc = tainted[next(iter(tainted_used))]
                    else:
                        # x = json.dumps(some_helper_func()).encode(...)
                        # style: the tracked tainted-returning function
                        # call might be nested anywhere in the RHS
                        # expression, not just be the whole RHS itself.
                        called_names = _called_function_names_in(rhs)
                        tainted_calls = called_names & tainted_returning_functions.keys()
                        if tainted_calls:
                            source_hit = True
                            source_desc = tainted_returning_functions[next(iter(tainted_calls))]

                if source_hit:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            tainted[target.id] = source_desc
                        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                            # blob[p] = tainted_value - treat the whole
                            # container as tainted, not per-key (a
                            # reasonable, conservative simplification).
                            # Found necessary via the real credential-
                            # theft sample this module targets: it
                            # collects stolen file contents into a dict
                            # via subscript assignment, not a plain
                            # variable.
                            tainted[target.value.id] = source_desc

                # Separately: track `_TARGETS = ['~/.aws/credentials', ...]`
                # style assignments, so a later `for p in _TARGETS:` can
                # recognize _TARGETS as a credential-path list even
                # though the list literal isn't inline in the for-loop
                # itself - exactly the real shape found in testing.
                if _list_contains_credential_marker(rhs):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            credential_list_vars.add(target.id)

            # `with open(path, ...) as fh:` - a source call bound via
            # a with-statement's `as` clause, not a plain assignment.
            # Missed in the first version of this tracker; found via a
            # real sample using exactly this idiom for credential theft.
            if isinstance(stmt, ast.With):
                for item in stmt.items:
                    if isinstance(item.context_expr, ast.Call) and item.optional_vars is not None:
                        is_src, desc = _is_source_call(item.context_expr)
                        if is_src and isinstance(item.optional_vars, ast.Name):
                            tainted[item.optional_vars.id] = desc
                        else:
                            # The path argument might itself be a
                            # variable already tainted (e.g. a loop
                            # variable from a credential-marker list -
                            # see the `for` handling below).
                            arg_names = set()
                            for arg in item.context_expr.args:
                                arg_names |= _names_used_in(arg)
                            hit = arg_names & tainted.keys()
                            if hit and isinstance(item.optional_vars, ast.Name):
                                tainted[item.optional_vars.id] = tainted[next(iter(hit))]

            # `for p in ['~/.aws/credentials', ...]:` - taint the loop
            # variable when iterating a list literal that contains a
            # credential-shaped path, exactly the real shape found in
            # testing (paths defined once, opened later via the loop
            # variable, often not even in the same statement).
            if isinstance(stmt, ast.For) and isinstance(stmt.target, ast.Name):
                if _list_contains_credential_marker(stmt.iter) or isinstance(stmt.iter, ast.Name) and stmt.iter.id in credential_list_vars:
                    tainted[stmt.target.id] = "a credential-shaped path from a list of targets"
                elif isinstance(stmt.iter, ast.Name) and stmt.iter.id in tainted:
                    tainted[stmt.target.id] = tainted[stmt.iter.id]

            # Any Call anywhere in this statement: check if it's a sink
            # receiving tainted data.
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    is_sink, sink_desc = _is_sink_call(node)
                    if not is_sink:
                        continue
                    args_names = set()
                    for arg in node.args:
                        args_names |= _names_used_in(arg)
                    for kw in node.keywords:
                        if kw.value is not None:
                            args_names |= _names_used_in(kw.value)
                    hit = args_names & tainted.keys()
                    if hit:
                        var_name = next(iter(hit))
                        findings.append(TaintFinding(
                            line=getattr(node, "lineno", 0),
                            source_desc=tainted[var_name],
                            sink_desc=sink_desc,
                            var_name=var_name,
                        ))

            # Taint flowing INTO a function through its parameters, not
            # just OUT through return values (the earlier limitation -
            # see the module docstring's "still not full inter-
            # procedural tracking" note, now partially closed). If a
            # tainted value is passed to a LOCALLY DEFINED function,
            # and that function's own body directly uses the matching
            # parameter in a sink call, report the flow at this call
            # site.
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue
                called_name = _call_name(node)
                if called_name not in function_defs:
                    continue
                param_names, func_body = function_defs[called_name]
                for i, arg in enumerate(node.args):
                    if i >= len(param_names):
                        continue
                    tainted_arg = _names_used_in(arg) & tainted.keys()
                    if not tainted_arg:
                        continue
                    sink_desc = _function_sinks_on_param(func_body, param_names[i])
                    if sink_desc:
                        var_name = next(iter(tainted_arg))
                        findings.append(TaintFinding(
                            line=getattr(node, "lineno", 0),
                            source_desc=tainted[var_name],
                            sink_desc=f"{sink_desc} (via parameter "
                                      f"'{param_names[i]}' of '{called_name}()')",
                            var_name=var_name,
                        ))
                for kw in node.keywords:
                    if kw.arg not in param_names or kw.value is None:
                        continue
                    tainted_arg = _names_used_in(kw.value) & tainted.keys()
                    if not tainted_arg:
                        continue
                    sink_desc = _function_sinks_on_param(func_body, kw.arg)
                    if sink_desc:
                        var_name = next(iter(tainted_arg))
                        findings.append(TaintFinding(
                            line=getattr(node, "lineno", 0),
                            source_desc=tainted[var_name],
                            sink_desc=f"{sink_desc} (via parameter "
                                      f"'{kw.arg}' of '{called_name}()')",
                            var_name=var_name,
                        ))

            # `return <expr>` where expr contains a tainted name - marks
            # the enclosing function as tainted-returning, so callers of
            # it elsewhere in the file get taint propagated too.
            if isinstance(stmt, ast.Return) and stmt.value is not None and current_func:
                returned_names = _names_used_in(stmt.value)
                hit = returned_names & tainted.keys()
                if hit:
                    tainted_returning_functions[current_func] = tainted[next(iter(hit))]

            # Recurse into function/class bodies as their own scope.
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                func_name = stmt.name if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) else None
                walk_body(stmt.body, current_func=func_name)
            elif isinstance(stmt, (ast.If, ast.For, ast.While, ast.With)):
                walk_body(stmt.body, current_func=current_func)
                walk_body(getattr(stmt, "orelse", []), current_func=current_func)
            elif isinstance(stmt, ast.Try):
                walk_body(stmt.body, current_func=current_func)
                for handler in stmt.handlers:
                    walk_body(handler.body, current_func=current_func)
                walk_body(stmt.orelse, current_func=current_func)
                walk_body(stmt.finalbody, current_func=current_func)

    walk_body(tree.body)

    # Deduplicate: the same flow can occasionally be discovered via more
    # than one path through the walker (e.g. a sink call visited both
    # directly and via a nested ast.walk during a parent statement's
    # sink-check) - dedupe by (line, var_name, sink_desc) rather than
    # object identity.
    seen = set()
    deduped = []
    for f in findings:
        key = (f.line, f.var_name, f.sink_desc)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped, tainted_returning_functions


def analyze_taint_flows(source_code, filename="<skill script>"):
    """
    Parses Python source and traces sensitive-source-to-dangerous-sink
    data flows through variable assignments. Public entry point.

    Runs _analyze_taint_flows_once TWICE. Real bug found via testing
    against a real credential-reconnaissance sample: a helper function
    defined LATER in the file (returning a tainted value) was called
    by a function defined EARLIER in the file. Since the single-pass
    walker processes functions in textual order, and
    tainted_returning_functions is only populated progressively AS
    each function's own body gets walked, the earlier-defined caller
    never saw the later-defined callee as tainted-returning - a real,
    order-dependent miss, not by design (the sibling mechanism for
    tainted PARAMETERS was already explicitly built to be order-
    independent via an upfront _collect_function_defs pass; this one
    wasn't). Fixed the same way: a first "priming" pass discovers
    every tainted-returning function regardless of where it's defined
    relative to its callers, then a second, real pass runs seeded with
    that complete set, so it no longer matters which one comes first
    in the file.
    """
    _, primed_returning_functions = _analyze_taint_flows_once(source_code, filename, {})
    findings, _ = _analyze_taint_flows_once(source_code, filename, primed_returning_functions)
    return findings
