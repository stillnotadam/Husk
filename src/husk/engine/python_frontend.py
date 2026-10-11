"""Python front end: label propagation over the AST.

Values are tracked through assignments, attribute access, subscripts,
f-strings, `with ... as`, for-loops, function return values and files
written to disk, and checked at sinks:
  exec     exec/eval/compile, os.system/os.popen, subprocess with
           shell=True or an interpreter's -c, running a downloaded file,
           pickle/marshal/dill loads
  send     requests/httpx post/put/patch, urlopen(Request(data=...)),
           socket send, smtplib sendmail
  persist  writing to a shell startup file, cron, launchd, systemd
It is deliberately an over-approximation inside one file: a value built
from a labelled value keeps the label. Precision comes from the sinks,
which are narrow (code execution, not "any subprocess").
"""
import ast
import re

from .model import EMPTY, Flow, Step, Value, union
from .shell import CRED_PATH, MAX_DEPTH, PERSIST_PATH, _decode_text, _short, analyze_shell, hosts_in

_FETCH = re.compile(r"(?:^|\.)(?:urlopen|urlretrieve|get|request)$")
_FETCH_MODULES = ("requests", "httpx", "urllib", "urllib3", "aiohttp", "http")
_CLIENT_FACTORIES = re.compile(r"(?:^|\.)(?:Session|Client|AsyncClient|PoolManager|ClientSession)$")
_SEND_METHODS = {"post", "put", "patch"}
_DECODERS = {"b64decode", "standard_b64decode", "urlsafe_b64decode", "b32decode", "b16decode", "a85decode",
             "b85decode", "decodebytes", "unhexlify", "fromhex", "decompress", "a2b_base64", "a2b_hex"}
_DESERIALIZE = {"pickle.loads", "pickle.load", "marshal.loads", "dill.loads", "cloudpickle.loads",
                "_pickle.loads", "cPickle.loads"}
_SHELL_RUNNERS = {"os.system", "os.popen", "commands.getoutput", "subprocess.getoutput", "subprocess.getstatusoutput"}
_SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
               "subprocess.Popen", "os.execv", "os.execvp", "os.execl", "os.execlp", "os.spawnv", "os.spawnl"}
_INTERPRETERS = re.compile(r"^(?:.*/)?(?:ba|z|da|k)?sh$|^(?:.*/)?(?:python[\d.]*|perl|ruby|node|php|pwsh|powershell)$")
_PATH_KEEPERS = {"expanduser", "expandvars", "abspath", "realpath", "normpath", "Path", "PurePath",
                 "PosixPath", "str", "fspath", "join"}


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        base = dotted(node.func)
        return f"{base}()" if base else ""
    return ""


class _Analyzer:
    def __init__(self, ctx, base_line, depth):
        self.ctx = ctx
        self.base = base_line - 1
        self.depth = depth
        self.env = {}
        self.files = {}
        self.file_handles = {}
        self.returns = {}
        self.clients = set()

    def line(self, node):
        return self.base + getattr(node, "lineno", 1)

    def flow(self, value, sink, node, text):
        if value.labels:
            self.ctx.flows.append(Flow(value, sink, Step(self.line(node), text), "python"))

    # -- expressions -------------------------------------------------------------

    def val(self, node):
        if node is None:
            return EMPTY
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, bytes)):
                text = node.value if isinstance(node.value, str) else node.value.decode("latin-1")
                return Value(hosts=frozenset(hosts_in(text)), text=text)
            return EMPTY
        if isinstance(node, ast.Name):
            return self.env.get(node.id, EMPTY)
        if isinstance(node, ast.JoinedStr):
            parts = [self.val(v.value if isinstance(v, ast.FormattedValue) else v) for v in node.values]
            text = "".join(p.text if p.text is not None else "{}" for p in parts)
            return union(parts).as_text(text)
        if isinstance(node, ast.BinOp):
            a, b = self.val(node.left), self.val(node.right)
            text = None
            if a.text is not None and b.text is not None:
                if isinstance(node.op, ast.Add):
                    text = a.text + b.text
                elif isinstance(node.op, ast.Div):  # pathlib: Path.home() / ".ssh" / "id_rsa"
                    text = a.text.rstrip("/") + "/" + b.text
            return (a | b).as_text(text)
        if isinstance(node, ast.Attribute):
            if dotted(node) == "os.environ":
                return Value(frozenset({"secret"}), (Step(self.line(node), "takes the whole environment"),))
            return self.val(node.value).as_text(None)
        if isinstance(node, ast.Subscript):
            if dotted(node.value) == "os.environ":
                return EMPTY  # one variable, typically an API key sent to its own API
            return self.val(node.value).as_text(None)
        if isinstance(node, ast.Call):
            return self.call(node)
        if isinstance(node, ast.Await):
            return self.val(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return union(self.val(e) for e in node.elts).as_text(None)
        if isinstance(node, ast.Dict):
            return union(self.val(v) for v in node.values).as_text(None)
        if isinstance(node, ast.IfExp):
            return self.val(node.body) | self.val(node.orelse)
        if isinstance(node, ast.BoolOp):
            return union(self.val(v) for v in node.values)
        return EMPTY

    def call(self, node):
        name = dotted(node.func)
        short = name.rsplit(".", 1)[-1]
        args = [self.val(a) for a in node.args]
        kwargs = {k.arg: self.val(k.value) for k in node.keywords if k.arg}
        everything = union(args + list(kwargs.values()))
        line = self.line(node)

        # sources
        if name.startswith("os.environ."):
            if short in ("copy", "items", "keys", "values"):
                return Value(frozenset({"secret"}), (Step(line, "takes the whole environment"),))
            return EMPTY  # os.environ.get("ONE_KEY"): typically sent to its own API
        if self._is_fetch(name, node):
            url = args[0] if args else kwargs.get("url", EMPTY)
            if short in _SEND_METHODS or (short == "request" and args and (args[0].text or "").upper() in ("POST", "PUT", "PATCH")):
                data = union(v for k, v in kwargs.items() if k in ("data", "json", "files", "params", "body"))
                if len(args) > 1:
                    data = data | union(args[1:])
                self.flow(data | (url if "secret" in url.labels else EMPTY), "send", node,
                          f"sends it to {_short(url.text or name)}")
            if short == "urlretrieve" and len(args) > 1 and args[1].text:
                fetched = Value(frozenset({"remote"}), (Step(line, f"fetches {_short(url.text or '')}"),), url.hosts)
                self.write_file(args[1].text, fetched, node)
                return EMPTY
            data_arg = kwargs.get("data")
            if short == "urlopen" and data_arg is not None and data_arg.labels:
                self.flow(data_arg, "send", node, "sends it with urlopen")
            if short == "urlopen" and args and "secret" in args[0].labels:
                self.flow(args[0], "send", node, "sends it with urlopen")
            return Value(frozenset({"remote"}), (Step(line, f"fetches {_short(url.text or name + '()')}"),),
                         url.hosts | everything.hosts) | everything.as_text(None)
        if name in ("Request", "urllib.request.Request") and "data" in kwargs:
            return everything
        if name in ("open", "io.open", "codecs.open") or short in ("read_text", "read_bytes"):
            path = args[0].text if args else None
            if short in ("read_text", "read_bytes"):
                path = self.val(node.func.value).text if isinstance(node.func, ast.Attribute) else None
                inner = node.func.value if isinstance(node.func, ast.Attribute) else None
                if isinstance(inner, ast.Call) and inner.args:
                    path = self.val(inner.args[0]).text
            if path and path in self.files:
                return self.files[path]
            if path and CRED_PATH.search(path):
                return Value(frozenset({"secret"}), (Step(line, f"reads {_short(path)}"),))
            return everything.as_text(None)
        if name in ("os.environ.copy", "dict") and node.args and dotted(node.args[0]) == "os.environ" or name == "os.environ.copy":
            return Value(frozenset({"secret"}), (Step(line, "takes the whole environment"),))
        if short in _DECODERS:
            src = args[0] if args else (self.val(node.func.value) if isinstance(node.func, ast.Attribute) else EMPTY)
            if short == "fromhex" and not args:
                src = EMPTY
            text = _decode_text("hex" if short in ("unhexlify", "fromhex", "b16decode", "a2b_hex") else "base64",
                                src.text) if short not in ("decompress",) else None
            out = src.with_label("decoded", Step(line, f"decodes it ({short})")).as_text(text)
            if text and self.depth < MAX_DEPTH:
                self.analyze_payload(text, line)
            return out
        if short == "decode" and isinstance(node.func, ast.Attribute):
            return self.val(node.func.value)

        # sinks
        if name in ("exec", "builtins.exec") or (name == "compile" and args):
            self.flow(args[0] if args else EMPTY, "exec", node, f"runs it with {name}()")
            return EMPTY
        if name in ("eval", "builtins.eval"):
            # eval() of fetched text is usually lazy parsing (a vulnerability);
            # of decoded text, hiding code.
            v = args[0] if args else EMPTY
            self.flow(v, "exec" if "decoded" in v.labels else "inject", node, f"evaluates it with {name}()")
            return EMPTY
        if name in _DESERIALIZE:
            self.flow(args[0] if args else EMPTY, "exec", node, f"deserializes it with {name}()")
            return EMPTY
        if name in _SHELL_RUNNERS:
            v = args[0] if args else EMPTY
            self.flow(v, "exec", node, f"runs it with {name}()")
            self.analyze_payload(v.text, line, lang="shell")
            return EMPTY
        if name in _SUBPROCESS or short in ("create_subprocess_shell", "create_subprocess_exec"):
            self.subprocess(node, name, args, kwargs)
            return EMPTY
        if short in ("send", "sendall", "sendto") and isinstance(node.func, ast.Attribute):
            self.flow(everything, "send", node, f"sends it with .{short}()")
            return EMPTY
        if short in ("sendmail", "send_message"):
            self.flow(everything, "send", node, f"sends it with .{short}()")
            return EMPTY
        if short in ("write", "writelines") and isinstance(node.func, ast.Attribute):
            target = node.func.value
            path = None
            if isinstance(target, ast.Name):
                path = self.file_handles.get(target.id)
            elif isinstance(target, ast.Call) and dotted(target.func) in ("open", "io.open") and target.args:
                path = self.val(target.args[0]).text
            if path:
                self.write_file(path, everything, node)
            return EMPTY
        if short in ("write_text", "write_bytes") and isinstance(node.func, ast.Attribute):
            inner = node.func.value
            path = self.val(inner).text
            if isinstance(inner, ast.Call) and inner.args:
                path = self.val(inner.args[0]).text
            if path:
                self.write_file(path, everything, node)
            return EMPTY
        # Path helpers keep the path text: open(os.path.expanduser("~/.ssh/id_rsa"))
        if short in _PATH_KEEPERS and args:
            if short == "join":
                recv = node.func.value if isinstance(node.func, ast.Attribute) else None
                if isinstance(recv, ast.Constant) and isinstance(recv.value, str):
                    # "".join(chunks): payload reassembly - keep the text if the chunks are known
                    first = node.args[0]
                    if isinstance(first, (ast.List, ast.Tuple)):
                        texts = [self.val(e).text for e in first.elts]
                        joined = recv.value.join(texts) if all(t is not None for t in texts) else None
                        return everything.as_text(joined)
                    return everything.as_text(None)
                texts = [a.text for a in args]
                return everything.as_text("/".join(texts) if all(t is not None for t in texts) else None)
            return args[0]
        if name in ("Path.home", "pathlib.Path.home"):
            return Value(text="~")
        if short in self.returns and isinstance(node.func, ast.Name):
            return self.returns[short] | everything.as_text(None)
        # anything else: the result is derived from its inputs (method calls
        # on a fetched response included: r.read(), r.json(), r.text)
        receiver = self.val(node.func.value) if isinstance(node.func, ast.Attribute) else EMPTY
        return (receiver | everything).as_text(None)

    def _is_fetch(self, name, node):
        if not _FETCH.search(name) and not name.endswith(("post", "put", "patch")):
            return False
        root = name.split(".", 1)[0].lower()
        if name in ("urlopen", "urlretrieve") or root in _FETCH_MODULES:
            return True
        # session.get(...) / client.post(...) on a requests/httpx/aiohttp client
        return isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)             and node.func.value.id in self.clients

    def subprocess(self, node, name, args, kwargs):
        shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value for k in node.keywords)
        first = node.args[0] if node.args else None
        if shell or name.endswith("create_subprocess_shell"):
            v = args[0] if args else EMPTY
            self.flow(v, "exec", node, f"runs it with {name}(shell=True)")
            self.analyze_payload(v.text, self.line(node), lang="shell")
            return
        if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
            elts = [self.val(e) for e in first.elts]
        elif name.endswith("create_subprocess_exec"):
            elts = args
        else:
            return
        prog = elts[0].text or ""
        if _INTERPRETERS.search(prog):
            for k, e in enumerate(elts[1:], 1):
                if e.text in ("-c", "-e") and k + 1 < len(elts):
                    self.flow(elts[k + 1], "exec", node, f"runs it with {prog} {e.text}")
                    self.analyze_payload(elts[k + 1].text, self.line(node), lang="shell" if prog.endswith("sh") else "python")
                    return
                if e.text and not e.text.startswith("-"):
                    v = self.files.get(e.text, EMPTY)
                    self.flow(v, "exec", node, f"runs {_short(e.text)} with {prog}")
                    return
            stdin = kwargs.get("input", EMPTY)
            self.flow(stdin, "exec", node, f"runs it with {prog}")
            return
        v = self.files.get(prog, EMPTY)
        self.flow(v, "exec", node, f"runs {_short(prog)}")

    def write_file(self, path, value, node):
        line = self.line(node)
        if value.labels:
            value = value.then(Step(line, f"saves it to {_short(path)}"))
        self.files[path] = value
        if PERSIST_PATH.search(path):
            self.flow(value, "persist", node, f"writes it to {_short(path)}")

    def analyze_payload(self, text, line, lang=None):
        """Decoded or literal code that will run: analyze it as well, so
        what it does shows up in the findings."""
        if not text or self.depth >= MAX_DEPTH:
            return
        if lang in (None, "python"):
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                tree = None
            if tree is not None:
                analyze_python(text, self.ctx, line, self.depth + 1, tree=tree, flatten_lines=True)
                return
        if lang in (None, "shell"):
            analyze_shell(text, self.ctx, line, self.depth + 1)

    # -- statements --------------------------------------------------------------

    def note_client(self, target, value_node):
        if isinstance(target, ast.Name) and isinstance(value_node, ast.Call)                 and _CLIENT_FACTORIES.search(dotted(value_node.func)):
            self.clients.add(target.id)

    def assign(self, target, value):
        if isinstance(target, ast.Name):
            self.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self.assign(t, value.as_text(None))
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = target.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name):
                self.env[base.id] = self.env.get(base.id, EMPTY) | value.as_text(None)

    def block(self, stmts):
        for s in stmts:
            self.stmt(s)

    def stmt(self, s):
        if isinstance(s, ast.Assign):
            v = self.val(s.value)
            for t in s.targets:
                self.assign(t, v)
                self.note_client(t, s.value)
        elif isinstance(s, (ast.AnnAssign, ast.AugAssign)) and s.value is not None:
            v = self.val(s.value)
            if isinstance(s, ast.AugAssign) and isinstance(s.target, ast.Name):
                v = self.env.get(s.target.id, EMPTY) | v
            self.assign(s.target, v)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                v = self.val(item.context_expr)
                ce = item.context_expr
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, v)
                    self.note_client(item.optional_vars, ce)
                    if isinstance(ce, ast.Call) and dotted(ce.func) in ("open", "io.open") and ce.args \
                            and isinstance(item.optional_vars, ast.Name):
                        path = self.val(ce.args[0]).text
                        if path:
                            self.file_handles[item.optional_vars.id] = path
            self.block(s.body)
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            self.assign(s.target, self.val(s.iter))
            self.block(s.body)
            self.block(s.orelse)
        elif isinstance(s, (ast.If, ast.While)):
            self.val(s.test)
            self.block(s.body)
            self.block(s.orelse)
        elif isinstance(s, ast.Try) or s.__class__.__name__ == "TryStar":
            self.block(s.body)
            for h in s.handlers:
                self.block(h.body)
            self.block(s.orelse)
            self.block(s.finalbody)
        elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
            saved = dict(self.env)
            self.block(s.body)
            ret = union(self.val(r.value) for r in ast.walk(s) if isinstance(r, ast.Return) and r.value is not None)
            if ret.labels:
                self.returns[s.name] = ret.as_text(None)
            self.env = {**saved, **{k: v for k, v in self.env.items() if k not in saved and k.isupper()}}
        elif isinstance(s, ast.ClassDef):
            self.block(s.body)
        elif isinstance(s, (ast.Expr, ast.Return)):
            self.val(s.value)


def analyze_python(src, ctx, base_line=1, depth=0, *, tree=None, flatten_lines=False):  # noqa: PLR0913 - two are keyword-only internals for payload re-analysis
    if tree is None:
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            return None
    a = _Analyzer(ctx, base_line, depth)
    if flatten_lines:
        for node in ast.walk(tree):
            if hasattr(node, "lineno"):
                node.lineno = 1
    try:
        # Two passes: the first learns which functions return labelled data,
        # so call sites earlier in the file see it on the second.
        start = len(ctx.flows)
        a.block(tree.body)
        if a.returns:
            del ctx.flows[start:]
            a.env, a.files, a.file_handles = {}, {}, {}
            a.block(tree.body)
    except RecursionError:
        return a
    return a
