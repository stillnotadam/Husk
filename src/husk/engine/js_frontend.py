"""JavaScript / TypeScript front end: label propagation over the esprima AST.

Values are tracked through declarations (destructuring included), assignments,
template literals, concatenation, `await`, promise callbacks and stream
events, functions' return values and files written to disk. Modules are
resolved through require/import aliases, so `const {exec: run} =
require("node:child_process")` is still child_process.exec.

  sources  fetch / axios / got / needle / superagent / ky / request / undici,
           http(s).get and .request (callback parameters included); the whole
           process.env; reads of credential files; Buffer.from(x, "base64"),
           atob, String.fromCharCode
  exec     eval, new Function, vm.*, module._compile, a string passed to
           setTimeout, new Worker(code, {eval: true}), require() of a file
           written with downloaded content; child_process commands are
           handed to the shell front end with the JavaScript values bound as
           shell variables, so `exec(`curl ${u} | sh`)` is analyzed exactly
           as the shell line would be
  send     a request body, a secret in a URL, writes to an http.request /
           socket / WebSocket handle, sendBeacon, sendMail, DNS lookups of a
           secret-bearing name
  persist  fs writes to a shell startup file, cron, launchd, systemd, ...

Like the Python front end it over-approximates inside one file (a value
built from a labelled value keeps the label) and gets its precision from
narrow sinks. A file esprima cannot parse, even after the TypeScript and
modern-syntax rewrites below, yields nothing.
"""
import re
from types import SimpleNamespace

from .model import EMPTY, Flow, Step, Value, union
from .shell import CRED_PATH, MAX_DEPTH, PERSIST_PATH, _decode_text, _short, analyze_shell, hosts_in

try:
    import esprima
except ImportError:  # pragma: no cover - esprima is a declared dependency
    esprima = None

MAX_SOURCE = 200_000  # esprima is pure Python; minified bundles are not skill code

_FETCH_ROOTS = {"axios", "got", "needle", "superagent", "ky", "request", "undici", "phin", "bent"}
_NOT_FETCH = {"create", "extend", "isCancel", "all", "spread", "use", "defaults", "interceptors", "CancelToken",
              "isAxiosError", "mergeConfig", "toFormData", "formToJSON", "getAdapter"}
_SEND_METHODS = {"post", "put", "patch"}
_BODY_KEYS = ("body", "data", "json", "form", "formData", "files")
_MODULE_ALIASES = {"node-fetch": "fetch", "cross-fetch": "fetch", "isomorphic-fetch": "fetch", "fs/promises": "fs.promises",
                   "fs-extra": "fs", "graceful-fs": "fs", "dns/promises": "dns.promises", "timers/promises": "timers"}
_HANDLE_FACTORIES = re.compile(r"^(?:https?\.request|http2\.connect|net\.(?:connect|createConnection|Socket)|"
                               r"tls\.connect|dgram\.createSocket|WebSocket|ws|XMLHttpRequest|ws\.WebSocket)$")
_FS_READ = {"readFileSync", "readFile"}
_FS_WRITE = {"writeFileSync", "writeFile", "appendFileSync", "appendFile", "outputFile", "outputFileSync"}
_VM_RUN = {"runInNewContext", "runInThisContext", "runInContext", "compileFunction"}
_DNS = {"lookup", "resolve", "resolve4", "resolve6", "resolveTxt", "resolveAny", "resolveCname"}
_EXEC_SHELL = {"exec", "execSync"}
_EXEC_FILE = {"execFile", "execFileSync", "spawn", "spawnSync", "fork"}
_KEEP_TEXT = {"toString", "trim", "trimStart", "trimEnd", "valueOf", "normalize"}
_HOME = {"process.env.HOME", "process.env.USERPROFILE"}
_MISSING = object()


def _rewrite(code):
    """Syntax newer than esprima 4 rewritten to an equivalent it parses,
    keeping every line where it was."""
    if code.startswith("#!"):
        code = "//" + code[2:]
    code = re.sub(r"\?\?=|\|\|=|&&=", "=", code)
    code = re.sub(r"\?\.(?=[\[(])", "", code)
    code = re.sub(r"\?\.(?!\d)", ".", code)
    code = code.replace("??", "||")
    code = re.sub(r"\bcatch\s*\{", "catch (_e) {", code)
    return code


_IMPORT = re.compile(r"^([ \t]*)import\s+([\w$]+\s*,\s*)?(\*\s+as\s+[\w$]+|\{[^}]*\}|[\w$]+)?\s*(?:from\s*)?(['\"][^'\"\n]+['\"])\s*;?",
                     re.MULTILINE)


def _as_require(m):
    """`import d, {a as b} from "m"` -> `const d = require("m"), {a: b} = require("m");` on the same line."""
    indent, default, rest, mod = m.groups()
    req = f"require({mod})"
    binds = []
    for part in ((default or "").strip(" ,"), (rest or "").strip()):
        if not part:
            continue
        if part.startswith("*"):
            binds.append(f"{part.split()[-1]} = {req}")
        elif part.startswith("{"):
            inner = re.sub(r"([\w$]+)\s+as\s+([\w$]+)", r"\1: \2", part)
            binds.append(f"{inner} = {req}")
        else:
            binds.append(f"{part} = {req}")
    return f"{indent}const {', '.join(binds)};" if binds else f"{indent}{req};"


def _unmodule(code):
    """Module syntax as script syntax, so the code can sit inside the async
    wrapper that top-level await needs."""
    code = _IMPORT.sub(_as_require, code)
    return re.sub(r"^([ \t]*)export\s+(?:default\s+)?(?=(?:async\s+)?function|class|const|let|var)", r"\1", code,
                  flags=re.MULTILINE)


def _parse(code):
    """(tree, line offset) or (None, 0). Tries the source rewritten for
    esprima, TypeScript-stripped, and wrapped in an async function (top-level
    await) - strictly first: tolerant parsing misreads top-level `await f()`
    as two arguments, so it is the last resort."""
    if esprima is None or len(code) > MAX_SOURCE:
        return None, 0
    from ..js_taint_analysis import _strip_ts  # noqa: PLC0415 - shared TS stripping, imported lazily
    plain = _rewrite(code)
    attempts = []
    for variant in (plain, _strip_ts(plain)):
        attempts += [(variant, 0), ("async function __husk__() {\n" + _unmodule(variant) + "\n}", 1)]
    for tolerant in (False, True):
        for text, offset in attempts:
            for parse in (esprima.parseModule, esprima.parseScript):
                try:
                    return parse(text, {"loc": True, "tolerant": tolerant}), offset
                except Exception:  # noqa: BLE001,S112 - esprima raises its own error types; try the next variant
                    continue
    return None, 0


def _is(node, *types):
    return node is not None and getattr(node, "type", None) in types


def _children(node):
    for key, child in vars(node).items():
        if key in ("type", "loc", "range"):
            continue
        if isinstance(child, list):
            for c in child:
                if hasattr(c, "type"):
                    yield c
        elif hasattr(child, "type"):
            yield child


def _prop_name(prop):
    key = getattr(prop, "key", None)
    if _is(key, "Identifier") and not prop.computed:
        return key.name
    if _is(key, "Literal") and isinstance(key.value, str):
        return key.value
    return None


def _module_name(text):
    name = text[5:] if text.startswith("node:") else text
    return _MODULE_ALIASES.get(name, name)


class _Analyzer:
    def __init__(self, ctx, base_line, offset, depth):
        self.ctx = ctx
        self.base = base_line - 1 - offset
        self.depth = depth
        self.env = {}
        self.aliases = {}     # local name -> canonical dotted name ("child_process.exec")
        self.objects = {}     # local name -> its object-literal node (request options)
        self.handles = {}     # local name -> what it sends over ("an http request")
        self.streams = {}     # local name -> path of the fs write stream it holds
        self.files = {}
        self.returns = {}
        self.scopes = [{}]    # per function: name -> value it shadowed (_MISSING if none)
        self.ret_stack = []
        self._n = 0

    def line(self, node):
        loc = getattr(node, "loc", None)
        return self.base + (loc.start.line if loc else 1)

    def flow(self, value, sink, node, text):
        if value.labels:
            self.ctx.flows.append(Flow(value, sink, Step(self.line(node), text), "javascript"))

    # -- names -------------------------------------------------------------------

    def dotted(self, node):
        if _is(node, "Identifier"):
            return self.aliases.get(node.name, node.name)
        if _is(node, "ThisExpression"):
            return "this"
        if _is(node, "MemberExpression"):
            base = self.dotted(node.object)
            prop = node.property
            if not node.computed and _is(prop, "Identifier"):
                name = prop.name
            elif _is(prop, "Literal") and isinstance(prop.value, str):
                name = prop.value
            else:
                return ""
            return f"{base}.{name}" if base else ""
        if _is(node, "CallExpression") and _is(node.callee, "Identifier") and node.callee.name == "require" \
                and node.arguments and _is(node.arguments[0], "Literal") and isinstance(node.arguments[0].value, str):
            return _module_name(node.arguments[0].value)
        if _is(node, "AwaitExpression"):
            return self.dotted(node.argument)
        return ""

    def declare(self, name, value):
        if len(self.scopes) > 1 and name not in self.scopes[-1]:
            self.scopes[-1][name] = self.env.get(name, _MISSING)
        self.env[name] = value

    # -- expressions -------------------------------------------------------------

    def val(self, node):  # noqa: PLR0911, PLR0912 - one branch per node type
        if node is None:
            return EMPTY
        t = node.type
        if t == "Literal":
            if isinstance(node.value, str):
                return Value(hosts=frozenset(hosts_in(node.value)), text=node.value)
            return EMPTY if node.value is None or isinstance(node.value, bool) else Value(text=str(node.value))
        if t == "Identifier":
            return self.env.get(node.name, EMPTY)
        if t == "TemplateLiteral":
            parts, text = [], ""
            for i, q in enumerate(node.quasis):
                text = None if text is None else text + (q.value.cooked or "")
                if i < len(node.expressions):
                    v = self.val(node.expressions[i])
                    parts.append(v)
                    text = None if text is None or v.text is None else text + v.text
            return union(parts).as_text(text) | Value(hosts=frozenset(hosts_in("".join(q.value.cooked or "" for q in node.quasis))))
        if t == "BinaryExpression":
            a, b = self.val(node.left), self.val(node.right)
            text = a.text + b.text if node.operator == "+" and a.text is not None and b.text is not None else None
            return (a | b).as_text(text) if node.operator == "+" else EMPTY
        if t == "MemberExpression":
            path = self.dotted(node)
            if path == "process.env":
                return Value(frozenset({"secret"}), (Step(self.line(node), "takes the whole environment"),))
            if path in _HOME:
                return Value(text="~")
            if path.startswith("process.env.") or self.dotted(node.object) == "process.env":
                if node.computed:
                    self.val(node.property)
                return EMPTY  # one variable (process.env.KEY, process.env[name]): an API key sent to its own API
            if path and path in self.env:
                return self.env[path]
            if node.computed:
                self.val(node.property)
            return self.val(node.object).as_text(None)
        if t in ("CallExpression", "NewExpression"):
            return self.call(node, new=t == "NewExpression")
        if t in ("AwaitExpression", "SpreadElement", "RestElement"):
            return self.val(node.argument)
        if t in ("ArrayExpression",):
            return union(self.val(e) for e in node.elements if e is not None).as_text(None)
        if t == "ObjectExpression":
            out = []
            for p in node.properties:
                if _is(p, "SpreadElement"):
                    out.append(self.val(p.argument))
                elif p.computed:
                    self.val(p.key)
                    out.append(self.val(p.value))
                else:
                    out.append(self.val(p.value))
            return union(out).as_text(None)
        if t == "ConditionalExpression":
            self.val(node.test)
            return self.val(node.consequent) | self.val(node.alternate)
        if t == "LogicalExpression":
            return self.val(node.left) | self.val(node.right)
        if t == "SequenceExpression":
            vals = [self.val(e) for e in node.expressions]
            return vals[-1] if vals else EMPTY
        if t == "AssignmentExpression":
            v = self.val(node.right)
            if node.operator == "+=":
                v = self.val(node.left) | v
            self.assign(node.left, v, node.right)
            return v
        if t in ("ArrowFunctionExpression", "FunctionExpression"):
            self.function(node)
            return EMPTY
        if t == "TaggedTemplateExpression":
            self.val(node.tag)
            return self.val(node.quasi)
        if t == "ClassExpression":
            self.visit(node.body)
            return EMPTY
        for c in _children(node):  # Unary, Update, Yield, ...: still look inside
            self.visit(c)
        return EMPTY

    def visit(self, node):
        """Statements and anything else: evaluate, looking for sinks."""
        if node is None:
            return
        t = node.type
        if t.endswith("Expression") or t in ("Identifier", "Literal", "TemplateLiteral", "SpreadElement"):
            self.val(node)
        elif t == "VariableDeclaration":
            for d in node.declarations:
                if _is(d.init, "ArrowFunctionExpression", "FunctionExpression") and _is(d.id, "Identifier"):
                    ret = self.function(d.init)  # const load = async () => { ... }
                    if ret.labels:
                        self.returns[d.id.name] = ret.as_text(None)
                    self.declare(d.id.name, EMPTY)
                    continue
                v = self.val(d.init)
                self.bind(d.id, v, d.init)
        elif t == "FunctionDeclaration":
            ret = self.function(node)
            if node.id is not None and ret.labels:
                self.returns[node.id.name] = ret.as_text(None)
        elif t == "ReturnStatement":
            v = self.val(node.argument)
            if self.ret_stack:
                self.ret_stack[-1].append(v)
        elif t == "ImportDeclaration":
            mod = _module_name(node.source.value)
            for s in node.specifiers:
                if s.type == "ImportSpecifier":
                    self.aliases[s.local.name] = f"{mod}.{s.imported.name}"
                else:
                    self.aliases[s.local.name] = mod
        elif t in ("ForOfStatement", "ForInStatement"):
            v = self.val(node.right)
            target = node.left.declarations[0].id if _is(node.left, "VariableDeclaration") else node.left
            self.bind(target, v.as_text(None), None)
            self.visit(node.body)
        elif t == "MethodDefinition":
            ret = self.function(node.value)
            name = _prop_name(node)
            if name and ret.labels:
                self.returns[name] = ret.as_text(None)
        else:
            for c in _children(node):
                self.visit(c)

    # -- binding -----------------------------------------------------------------

    def bind(self, target, value, init):
        """A declaration: names are local to the enclosing function."""
        if _is(target, "Identifier"):
            self.declare(target.name, value)
            self.note(target.name, init)
        elif _is(target, "ObjectPattern"):
            src = self.dotted(init) if init is not None else ""
            for p in target.properties:
                if _is(p, "RestElement"):
                    self.bind(p.argument, value.as_text(None), None)
                    continue
                if src == "process.env":
                    # const { API_URL, API_KEY } = process.env: single variables, not the environment
                    tgt = p.value.left if _is(p.value, "AssignmentPattern") else p.value
                    self.bind(tgt, EMPTY, None)
                    continue
                key = _prop_name(p)
                tgt = p.value.left if _is(p.value, "AssignmentPattern") else p.value
                if src and key and _is(tgt, "Identifier"):
                    # const {exec: run} = require("child_process")
                    self.aliases[tgt.name] = f"{src}.{key}"
                self.bind(tgt, value.as_text(None), None)
        elif _is(target, "ArrayPattern"):
            for e in target.elements:
                if e is not None:
                    self.bind(e, value.as_text(None), None)
        elif _is(target, "AssignmentPattern"):
            self.bind(target.left, value | self.val(target.right), None)
        elif _is(target, "RestElement"):
            self.bind(target.argument, value, None)

    def assign(self, target, value, init):
        if _is(target, "Identifier"):
            self.env[target.name] = value
            self.note(target.name, init)
        elif _is(target, "MemberExpression"):
            path = self.dotted(target)
            if path:
                self.env[path] = value
            base = target.object
            while _is(base, "MemberExpression"):
                base = base.object
            if _is(base, "Identifier"):
                self.env[base.name] = self.env.get(base.name, EMPTY) | value.as_text(None)
        elif _is(target, "ObjectPattern", "ArrayPattern"):
            self.bind(target, value, init)

    def note(self, name, init):
        """What a name holds besides data: a module, a client, options, a handle."""
        if init is None:
            return
        node = init.argument if _is(init, "AwaitExpression") else init
        if _is(node, "ObjectExpression"):
            self.objects[name] = node
            return
        path = self.dotted(node)
        if path and path not in self.env and path != name and not path.startswith("process.env"):
            self.aliases[name] = path  # const cp = require("child_process"); const ex = cp.exec
            return
        if _is(node, "CallExpression", "NewExpression"):
            callee = self.dotted(node.callee)
            short = callee.rsplit(".", 1)[-1]
            if short in ("create", "extend") and callee.split(".", 1)[0] in _FETCH_ROOTS:
                self.aliases[name] = callee.split(".", 1)[0]  # const api = axios.create(...)
            elif short == "promisify" and node.arguments:
                p = self.dotted(node.arguments[0])
                if p:
                    self.aliases[name] = p
            elif _HANDLE_FACTORIES.match(callee):
                self.handles[name] = callee
            elif short == "createWriteStream" and node.arguments:
                path_text = self.val(node.arguments[0]).text
                if path_text:
                    self.streams[name] = path_text

    # -- functions ---------------------------------------------------------------

    def function(self, fn, param_value=EMPTY):
        """Walk a function body with its parameters bound to param_value;
        returns the union of what it returns. Its declarations stay local."""
        self.scopes.append({})
        self.ret_stack.append([])
        try:
            for p in getattr(fn, "params", None) or []:
                self.bind(p, param_value, None)
            body = fn.body
            if _is(body, "BlockStatement"):
                for s in body.body:
                    self.visit(s)
            else:
                self.ret_stack[-1].append(self.val(body))
        finally:
            local = self.scopes.pop()
            rets = self.ret_stack.pop()
        for name, prior in local.items():
            if prior is _MISSING:
                self.env.pop(name, None)
            else:
                self.env[name] = prior
        return union(rets)

    def callbacks(self, node, value):
        """Function arguments run with what the call produces (a response, a
        chunk, a file's content); returns what they return."""
        out = EMPTY
        for a in node.arguments:
            if _is(a, "ArrowFunctionExpression", "FunctionExpression"):
                out = out | self.function(a, value)
        return out

    # -- calls -------------------------------------------------------------------

    def call(self, node, new=False):  # noqa: PLR0911, PLR0912 - one branch per API family
        name = self.dotted(node.callee)
        short = name.rsplit(".", 1)[-1]
        root = name.split(".", 1)[0]
        line = self.line(node)
        fn_args = [a for a in node.arguments if _is(a, "ArrowFunctionExpression", "FunctionExpression")]
        args = [EMPTY if a in fn_args else self.val(a) for a in node.arguments]
        everything = union(args)
        receiver = self.val(node.callee.object) if _is(node.callee, "MemberExpression") else EMPTY

        # sources
        if self._is_fetch(name, root, short):
            result = self.fetch(node, name, short, args, line)
            return result | self.callbacks(node, result)
        if root == "fs" and short in _FS_READ and args:
            path = args[0].text
            if path and path in self.files:
                result = self.files[path]
            elif path and CRED_PATH.search(path):
                result = Value(frozenset({"secret"}), (Step(line, f"reads {_short(path)}"),))
            else:
                result = EMPTY
            return result | self.callbacks(node, result)
        if name in ("os.homedir",):
            return Value(text="~")
        if root == "path" and short in ("join", "resolve", "normalize", "posix", "win32"):
            texts = [a.text for a in args]
            return everything.as_text("/".join(texts) if texts and all(x is not None for x in texts) else None)
        if name == "Buffer.from" and len(args) > 1 and args[1].text in ("base64", "hex", "base64url"):
            kind = "hex" if args[1].text == "hex" else "base64"
            return self.decoded(args[0], f"Buffer.from(..., '{args[1].text}')", kind, line)
        if name in ("atob", "window.atob", "globalThis.atob", "Base64.decode", "base64.decode"):
            return self.decoded(args[0] if args else EMPTY, "atob", "base64", line)
        if name == "String.fromCharCode" and node.arguments:
            codes = self._char_codes(node.arguments)
            text = "".join(chr(c) for c in codes) if codes is not None else None
            v = Value(frozenset({"decoded"}), (Step(line, "decodes it (String.fromCharCode)"),), text=text)
            if text and self.depth < MAX_DEPTH:
                self.payload(text, line, "js")
            return v
        if root == "zlib" and short.endswith(("Sync",)) and short.startswith(("inflate", "gunzip", "unzip", "brotliDecompress")):
            return (args[0] if args else EMPTY).with_label("decoded", Step(line, f"decompresses it ({short})")).as_text(None)
        if short in _KEEP_TEXT and _is(node.callee, "MemberExpression"):
            return receiver
        if short == "decode" and args:  # new TextDecoder().decode(buf)
            return args[0] | receiver
        if name in ("Object.keys", "Object.getOwnPropertyNames"):
            return EMPTY  # names, not values

        # sinks
        if name in ("eval", "window.eval", "globalThis.eval", "global.eval"):
            v = args[0] if args else EMPTY
            self.flow(v, self._code_sink(node.arguments[0] if node.arguments else None), node, "evaluates it with eval()")
            self.payload(v.text, line, "js")
            return EMPTY
        if name in ("Function", "window.Function", "globalThis.Function"):
            body = args[-1] if args else EMPTY
            self.flow(body, self._code_sink(node.arguments[-1] if node.arguments else None), node,
                      "compiles it with new Function()" if new else "compiles it with Function()")
            self.payload(body.text, line, "js")
            return EMPTY
        if (root == "vm" and (short in _VM_RUN or (new and short == "Script"))) or short == "_compile":
            v = args[0] if args else EMPTY
            self.flow(v, "exec", node, f"runs it with {name}()")
            self.payload(v.text, line, "js")
            return EMPTY
        if name in ("setTimeout", "setInterval", "setImmediate") and args and not fn_args and node.arguments \
                and not _is(node.arguments[0], "Identifier", "MemberExpression"):
            self.flow(args[0], "exec", node, f"runs it as code with {name}()")
            return EMPTY
        if new and short == "Worker" and len(node.arguments) > 1 and _is(node.arguments[1], "ObjectExpression") \
                and any(_prop_name(p) == "eval" for p in node.arguments[1].properties):
            self.flow(args[0], "exec", node, "runs it in a Worker (eval: true)")
            return EMPTY
        if name in ("require", "import") and args and args[0].text in self.files:
            self.flow(self.files[args[0].text], "exec", node, f"loads {_short(args[0].text)} with {name}()")
            return EMPTY
        if root == "child_process" and short in _EXEC_SHELL | _EXEC_FILE:
            self.child_process(node, name, short, args, line)
            self.callbacks(node, EMPTY)
            return EMPTY
        if root == "fs" and short in _FS_WRITE and len(args) > 1:
            if args[0].text:
                self.write_file(args[0].text, args[1], node)
            return EMPTY
        if short == "pipe" and node.arguments:
            path = self._stream_path(node.arguments[0])
            if path:
                self.write_file(path, receiver, node)
            return receiver
        if short in ("write", "end") and _is(node.callee, "MemberExpression"):
            obj = self.dotted(node.callee.object)
            if obj in self.streams and args:
                self.write_file(self.streams[obj], everything, node)
                return EMPTY
        if short in ("write", "end", "send") and _is(node.callee, "MemberExpression") \
                and self.dotted(node.callee.object) in self.handles:
            via = self.handles[self.dotted(node.callee.object)]
            self.flow(everything, "send", node, f"sends it over {via}")
            return EMPTY
        if root == "dns" and short in _DNS and args and "secret" in args[0].labels:
            self.flow(args[0], "send", node, "sends it in a DNS lookup")
            return EMPTY
        if short == "sendBeacon":
            self.flow(union(args[1:]) | (args[0] if args and "secret" in args[0].labels else EMPTY), "send", node,
                      f"sends it to {_short(args[0].text or 'a URL') if args else 'a URL'} with sendBeacon")
            return EMPTY
        if short == "sendMail":
            self.flow(everything, "send", node, "sends it by email (sendMail)")
            return EMPTY

        # user functions, promise chains, everything else
        if _is(node.callee, "Identifier") and node.callee.name in self.returns:
            return self.returns[node.callee.name] | everything.as_text(None)
        if _is(node.callee, "MemberExpression") and _is(node.callee.object, "ThisExpression") and short in self.returns:
            return self.returns[short] | everything.as_text(None)
        if _is(node.callee, "ArrowFunctionExpression", "FunctionExpression"):
            return self.function(node.callee, everything)  # an IIFE
        if not _is(node.callee, "MemberExpression"):
            self.val(node.callee)
        result = (receiver | everything).as_text(None)
        return result | self.callbacks(node, result)

    def _is_fetch(self, name, root, short):
        if name in ("fetch", "window.fetch", "globalThis.fetch", "global.fetch") or (root == "undici" and short in ("fetch", "request")):
            return True
        if root in _FETCH_ROOTS:
            return short not in _NOT_FETCH and name.count(".") <= 1
        return root in ("http", "https") and short in ("get", "request") and name.count(".") == 1

    def fetch(self, node, name, short, args, line):
        """A network request: returns the response; records a send when it
        carries a body or a secret in its URL."""
        nodes = node.arguments
        url, data, body_seen = EMPTY, EMPTY, False
        first = self._object(nodes[0]) if nodes else None
        if first is not None:  # axios({url, method, data}), request({url, form}), http.request({host, path})
            for p in first.properties:
                key = _prop_name(p)
                if key in ("url", "uri", "href", "host", "hostname"):
                    url = url | self.val(p.value)
                elif key in _BODY_KEYS:
                    data, body_seen = data | self.val(p.value), True
        elif args:
            url = args[0]
        for n, v in zip(nodes[1:], args[1:]):
            opts = self._object(n)
            if short in _SEND_METHODS and n is nodes[1] and not _is(n, "ArrowFunctionExpression", "FunctionExpression"):
                data, body_seen = data | v, True  # axios.post(url, data) / needle.post(url, data)
            elif opts is not None:
                for p in opts.properties:
                    if _prop_name(p) in _BODY_KEYS:
                        data, body_seen = data | self.val(p.value), True
        target = _short(url.text or name + "()")
        if body_seen or short in _SEND_METHODS or "secret" in url.labels:
            self.flow(data | (url if "secret" in url.labels else EMPTY), "send", node, f"sends it to {target}")
        return Value(frozenset({"remote"}), (Step(line, f"fetches {target}"),), url.hosts)

    def _object(self, n):
        if _is(n, "ObjectExpression"):
            return n
        if _is(n, "Identifier"):
            return self.objects.get(n.name)
        return None

    def _stream_path(self, n):
        if _is(n, "Identifier"):
            return self.streams.get(n.name)
        if _is(n, "CallExpression") and self.dotted(n.callee).rsplit(".", 1)[-1] == "createWriteStream" and n.arguments:
            return self.val(n.arguments[0]).text
        return None

    def _char_codes(self, nodes):
        out = []
        for n in nodes:
            if _is(n, "SpreadElement") and _is(n.argument, "ArrayExpression"):
                sub = self._char_codes(n.argument.elements)
                if sub is None:
                    return None
                out += sub
            elif _is(n, "Literal") and isinstance(n.value, (int, float)) and 0 <= n.value < 0x110000:
                out.append(int(n.value))
            else:
                return None
        return out

    def decoded(self, src, what, kind, line):
        text = _decode_text(kind, src.text)
        if text and self.depth < MAX_DEPTH:
            self.payload(text, line, None)
        return src.with_label("decoded", Step(line, f"decodes it ({what})")).as_text(text)

    def _code_sink(self, n):
        """Fetched data spliced into a mostly fixed program is injection;
        fetched data that is the program is remote code execution."""
        lit = 0
        stack = [n]
        while stack:
            x = stack.pop()
            if _is(x, "TemplateLiteral"):
                lit += sum(len((q.value.cooked or "").strip()) for q in x.quasis)
            elif _is(x, "BinaryExpression") and x.operator == "+":
                stack += [x.left, x.right]
            elif _is(x, "Literal") and isinstance(x.value, str):
                lit += len(x.value.strip())
        return "inject" if lit >= 20 else "exec"

    # -- child_process: hand the command line to the shell front end ----------------

    def child_process(self, node, name, short, args, line):
        shell_vars = {}
        nodes = node.arguments
        if not nodes:
            return
        opts = next((self._object(n) for n in nodes[1:] if self._object(n) is not None), None)
        shell_opt = opts is not None and any(_prop_name(p) == "shell" and not (_is(p.value, "Literal") and p.value.value is False)
                                             for p in opts.properties)
        if short in _EXEC_SHELL:
            cmd = self.shell_text(nodes[0], shell_vars)
            head = args[0]
        else:
            words = [self.shell_word(nodes[0], shell_vars, quote=not shell_opt)]
            arr = nodes[1] if len(nodes) > 1 and _is(nodes[1], "ArrayExpression") else None
            for e in (arr.elements if arr is not None else []):
                if e is not None:
                    words.append(self.shell_word(e, shell_vars, quote=not shell_opt))
            if short == "fork":
                words.insert(0, "node")
            cmd = " ".join(words)
            head = args[0]
        # A command that is itself downloaded or decoded data is run outright.
        if head.labels and cmd.lstrip(" \"'").startswith("${__hj"):
            self.flow(head, "exec", node, f"runs it with {name}()")
        if self.depth < MAX_DEPTH:
            state = SimpleNamespace(vars=shell_vars, files=self.files)
            analyze_shell(cmd, self.ctx, line, self.depth + 1, state=state)

    def _placeholder(self, value, shell_vars):
        self._n += 1
        name = f"__hj{self._n}"
        shell_vars[name] = value
        return "${" + name + "}"

    def shell_text(self, n, shell_vars):
        """A JavaScript string expression as shell source: literal parts as
        they are, anything labelled or unknown as a shell variable bound to
        its JavaScript value."""
        if _is(n, "Literal") and isinstance(n.value, str):
            return n.value
        if _is(n, "TemplateLiteral"):
            out = []
            for i, q in enumerate(n.quasis):
                out.append(q.value.cooked or "")
                if i < len(n.expressions):
                    out.append(self.shell_text(n.expressions[i], shell_vars))
            return "".join(out)
        if _is(n, "BinaryExpression") and n.operator == "+":
            return self.shell_text(n.left, shell_vars) + self.shell_text(n.right, shell_vars)
        v = self.val(n)
        if v.text is not None and not v.labels:
            return v.text
        return self._placeholder(v, shell_vars)

    def shell_word(self, n, shell_vars, quote=True):
        text = self.shell_text(n, shell_vars)
        if not quote or (_is(n, "Literal") and re.fullmatch(r"[\w./:@%+=,-]+", text or "")):
            return text
        if "${__hj" in text:
            return '"' + text.replace('"', '\\"') + '"'
        return "'" + text.replace("'", "'\\''") + "'"

    # -- files and payloads --------------------------------------------------------

    def write_file(self, path, value, node):
        if value.labels:
            value = value.then(Step(self.line(node), f"saves it to {_short(path)}"))
        self.files[path] = value
        if PERSIST_PATH.search(path):
            self.flow(value, "persist", node, f"writes it to {_short(path)}")

    def payload(self, text, line, lang):
        """Decoded or literal code that will run: analyze it too."""
        if not text or self.depth >= MAX_DEPTH:
            return
        if lang in (None, "js"):
            tree, offset = _parse(text)
            if tree is not None and tree.body:
                _run(tree, self.ctx, line, offset, self.depth + 1, flatten=True)
                return
            if lang == "js":
                return
        analyze_shell(text, self.ctx, line, self.depth + 1)


def _run(tree, ctx, base_line, offset, depth, *, flatten=False):  # noqa: PLR0913 - flatten is keyword-only
    a = _Analyzer(ctx, base_line, offset, depth)
    if flatten:
        a.line = lambda node: base_line  # payload code: every step is on the decoding line
    start = len(ctx.flows)
    try:
        for s in tree.body:
            a.visit(s)
        if a.returns:
            # Second pass: call sites earlier in the file see what functions return.
            del ctx.flows[start:]
            a.env, a.files, a.objects, a.handles, a.streams = {}, {}, {}, {}, {}
            for s in tree.body:
                a.visit(s)
    except RecursionError:
        pass
    return a


def analyze_js(src, ctx, base_line=1, depth=0):
    tree, offset = _parse(src)
    if tree is None:
        return None
    return _run(tree, ctx, base_line, offset, depth)
