"""Shell front end: a small lexer and an abstract evaluator for POSIX/bash
command lines.

The evaluator does not run anything. It walks the commands in order and
tracks what each value is (fetched, decoded, a credential file) through
pipes, command substitution, process substitution, here-strings,
heredocs, variables and files written to disk, and records a Flow whenever
such a value reaches a sink: an interpreter, eval, a network send, or a
shell startup file. One rule ("remote data reaches exec") then covers
`curl | bash`, `bash <(curl)`, `sh -c "$(curl)"`, `eval "$(curl)"`,
`bash <<< "$(wget)"`, `U=...; curl $U > /tmp/x; sh /tmp/x` and their
combinations, instead of one regex per shape.
"""
import base64
import binascii
import posixpath
import re
from dataclasses import dataclass, field
from typing import Optional

from .model import EMPTY, Flow, Step, Value, union

MAX_SCRIPT_CHARS = 200_000
MAX_DEPTH = 3

# --- lexer ------------------------------------------------------------------


@dataclass
class Word:
    parts: list  # ("lit", str) | ("var", name) | ("cmd", src, kind, line)
    line: int
    raw: str = ""


@dataclass
class Redir:
    op: str
    target: Optional[Word]
    line: int
    body: Optional[str] = None
    body_quoted: bool = False
    body_line: int = 0


@dataclass
class Command:
    words: list = field(default_factory=list)
    redirs: list = field(default_factory=list)
    line: int = 0


_OPERATORS = ("&&", "||", ";;", "|&", "|", "&", ";", "(", ")")
_VAR_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-]")


def _match_paren(s, i):
    """s[i] is just past an opening '(' - return the index of its matching
    ')', honouring quotes and nesting; len(s) if unterminated."""
    depth, n = 1, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            j = s.find("'", i + 1)
            i = n if j == -1 else j + 1
            continue
        if c == '"':
            i += 1
            while i < n and s[i] != '"':
                i += 2 if s[i] == "\\" else 1
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _dollar(s, i, line, parts):
    """s[i] == '$'. Appends the part it starts and returns the new index."""
    n = len(s)
    if s.startswith("$((", i):
        end = _match_paren(s, i + 3)
        parts.append(("lit", "0"))
        return min(n, end + 2)
    if s.startswith("$(", i):
        end = _match_paren(s, i + 2)
        parts.append(("cmd", s[i + 2:end], "$(", line))
        return end + 1
    if s.startswith("${", i):
        end = s.find("}", i + 2)
        end = n if end == -1 else end
        m = _VAR_RE.match(s, i + 2)
        parts.append(("var", m.group(0) if m else s[i + 2:end]))
        return end + 1
    m = _VAR_RE.match(s, i + 1)
    if m:
        parts.append(("var", m.group(0)))
        return m.end()
    parts.append(("lit", "$"))
    return i + 1


def _backtick(s, i, line, parts):
    j = i + 1
    while j < len(s) and s[j] != "`":
        j += 2 if s[j] == "\\" else 1
    parts.append(("cmd", s[i + 1:j].replace("\\`", "`"), "`", line))
    return j + 1


def parse_double_quoted(s, line):
    """Parts of a double-quoted / heredoc string: literal text with $VAR,
    ${VAR}, $(...) and `...` expanded."""
    parts, buf, i, n = [], [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n and s[i + 1] in '$`"\\\n':
            if s[i + 1] != "\n":  # backslash-newline is a line continuation
                buf.append(s[i + 1])
            i += 2
        elif c == "$":
            if buf:
                parts.append(("lit", "".join(buf)))
                buf = []
            i = _dollar(s, i, line, parts)
        elif c == "`":
            if buf:
                parts.append(("lit", "".join(buf)))
                buf = []
            i = _backtick(s, i, line, parts)
        else:
            buf.append(c)
            i += 1
    if buf:
        parts.append(("lit", "".join(buf)))
    return parts


def lex(src, base_line=1):
    """Tokens: ("word", Word) | ("op", str, line) | ("redir", Redir)."""
    toks, i, n, line = [], 0, len(src), base_line
    pending_heredocs = []
    while i < n:
        c = src[i]
        if c == "\n":
            toks.append(("op", "\n", line))
            line += 1
            i += 1
            for r in pending_heredocs:
                i, line = _read_heredoc(src, i, line, r)
            pending_heredocs = []
            continue
        if c in " \t\r":
            i += 1
            continue
        if c == "\\" and src.startswith(("\\\n", "\\\r\n"), i):  # line continuation
            i += 2 if src[i + 1] == "\n" else 3
            line += 1
            continue
        if c == "#":
            j = src.find("\n", i)
            i = n if j == -1 else j
            continue
        # Documentation placeholders like <skill>/scripts/x.py or <SKILL_DIR> are words, not redirects.
        ph = re.match(r"<[A-Za-z_][\w-]*>", src[i:i + 40]) if c == "<" else None
        if ph:
            word, i = _read_word(src, i + len(ph.group(0)), line)
            toks.append(("word", Word([("lit", ph.group(0))] + (word.parts if word else []), line, ph.group(0))))
            continue
        m = None if src.startswith(("<(", ">("), i) else re.match(r"(\d*)(<<<|<<-|<<|>>|&>>|&>|>&|<&|<>|>\||>|<)", src[i:i + 5])
        if m:
            op = m.group(2)
            i += m.end()
            while i < n and src[i] in " \t":
                i += 1
            if op in (">&", "<&") and i < n and (src[i].isdigit() or src[i] == "-"):
                i += 1
                continue
            word, i = _read_word(src, i, line)
            r = Redir(op, word, line)
            toks.append(("redir", r))
            if op in ("<<", "<<-"):
                pending_heredocs.append(r)
            continue
        op = next((o for o in _OPERATORS if src.startswith(o, i)), None)
        if op:
            toks.append(("op", op, line))
            i += len(op)
            continue
        word, i = _read_word(src, i, line)
        if word is None:
            i += 1
            continue
        toks.append(("word", word))
        line += word.raw.count("\n")
    return toks


def _read_heredoc(src, i, line, redir):
    delim = word_literal(redir.target) or ""
    redir.body_quoted = bool(redir.target and redir.target.raw[:1] in "'\"")
    strip_tabs = redir.op == "<<-"
    body, start_line = [], line
    while i < len(src):
        j = src.find("\n", i)
        j = len(src) if j == -1 else j
        text = src[i:j]
        i, line = j + 1, line + 1
        if (text.lstrip("\t") if strip_tabs else text).rstrip("\r") == delim:
            break
        body.append(text.lstrip("\t") if strip_tabs else text)
    redir.body = "\n".join(body)
    redir.body_line = start_line
    return min(i, len(src)), line


def _read_word(s, i, line):
    parts, buf, start, n = [], [], i, len(s)

    def flush():
        if buf:
            parts.append(("lit", "".join(buf)))
            buf.clear()

    if s.startswith(("<(", ">("), i):
        end = _match_paren(s, i + 2)
        parts.append(("cmd", s[i + 2:end], s[i] + "(", line))
        i = end + 1
    while i < n:
        c = s[i]
        if c in " \t\r\n;&|()<>":
            break
        if c == "\\":
            if i + 1 < n and s[i + 1] not in "\r\n":  # backslash-newline joins lines, adds nothing
                buf.append(s[i + 1])
            i += 3 if s.startswith("\\\r\n", i) else 2
        elif c == "'":
            j = s.find("'", i + 1)
            j = n if j == -1 else j
            buf.append(s[i + 1:j])
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            flush()
            parts.extend(parse_double_quoted(s[i + 1:j], line))
            i = j + 1
        elif c == "$":
            flush()
            i = _dollar(s, i, line, parts)
        elif c == "`":
            flush()
            i = _backtick(s, i, line, parts)
        else:
            buf.append(c)
            i += 1
    flush()
    if i == start:
        return None, i
    return Word(parts, line, s[start:i]), i


def word_literal(word):
    """The word's text if it has no expansions, else None."""
    if word is None or any(p[0] != "lit" for p in word.parts):
        return None
    return "".join(p[1] for p in word.parts)


def parse(src, base_line=1):
    """List of pipelines; each pipeline is a list of Commands."""
    pipelines, pipe, cmd = [], [], Command(line=base_line)
    for tok in lex(src, base_line):
        if tok[0] == "word":
            if not cmd.words and not cmd.redirs:
                cmd.line = tok[1].line
            cmd.words.append(tok[1])
        elif tok[0] == "redir":
            if not cmd.words and not cmd.redirs:
                cmd.line = tok[1].line
            cmd.redirs.append(tok[1])
        elif tok[1] in ("|", "|&"):
            pipe.append(cmd)
            cmd = Command(line=tok[2])
        else:
            if cmd.words or cmd.redirs:
                pipe.append(cmd)
            if pipe:
                pipelines.append(pipe)
            pipe, cmd = [], Command(line=tok[2])
    if cmd.words or cmd.redirs:
        pipe.append(cmd)
    if pipe:
        pipelines.append(pipe)
    return pipelines


# --- what commands mean -------------------------------------------------------

FETCHERS = {"curl", "wget", "fetch", "aria2c", "http", "https", "xh", "curlie", "lwp-download", "GET"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "rbash"}
INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua",
                "pwsh", "powershell", "deno", "bun", "osascript", "Rscript", "tclsh"}
_INLINE_CODE_FLAGS = {"-c", "-e", "-E", "-r", "--eval", "-p", "-Command", "-command", "-C"}
_DECODERS = {"base64", "base32", "basenc", "xxd", "uudecode", "openssl"}
_PASSTHROUGH = {"tee", "sed", "awk", "gawk", "tr", "cut", "grep", "egrep", "jq", "sort", "uniq", "dd", "rev",
                "gunzip", "zcat", "gzip", "bzip2", "bunzip2", "xz", "unxz", "zstd", "iconv", "fold", "head",
                "tail", "cat", "tac", "less", "more", "strings", "sponge"}
_SENDERS = {"nc", "ncat", "netcat", "socat", "telnet"}
_WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "command", "builtin", "exec", "nice", "timeout",
             "stdbuf", "chroot", "then", "do", "else", "elif", "if", "while", "until", "!", "{", "(", "unbuffer"}
_IGNORE = {"fi", "done", "esac", "}", ")", "case", "function"}
_ASSIGN_BUILTINS = {"export", "local", "declare", "readonly", "typeset"}

_DATA_FILE = re.compile(r"\.(?:png|jpe?g|gif|webp|svg|bmp|ico|mp[34]|wav|ogg|webm|mov|pdf|json|csv|txt|md|html?|xml|ya?ml|log)$", re.IGNORECASE)
_URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s'\"<>|;)]+")
_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+?=")

CRED_PATH = re.compile(
    r"\.ssh/(?:id_[a-z0-9_]+|[^/\s]*_key|identity)\b|\.aws/credentials|\.netrc\b|\.npmrc\b|\.pypirc\b"
    r"|\.git-credentials|\.docker/config\.json|\.kube/config|\.config/gcloud/|\.azure/|/etc/shadow\b"
    # Not .env: skills read their own .env for their own API key, which they then
    # send to that API (three such benign skills on the 2026-10 benchmark).
    r"|\.gnupg/|Keychains/|\.config/gh/hosts\.yml|wallet\.dat|Login Data",
    re.IGNORECASE)
PERSIST_PATH = re.compile(
    r"(?:^|/)\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|zlogin|kshrc)$"
    r"|config\.fish$|/etc/(?:profile|bash\.bashrc|zsh/|cron|rc\.local|systemd/|init\.d/)|/var/spool/cron"
    r"|LaunchAgents/|LaunchDaemons/|\.config/autostart/|\.config/systemd/user/|authorized_keys$",
    re.IGNORECASE)


def hosts_in(text):
    """Locations ("host/path") of the URLs in text. The path is kept because
    trust can depend on it (raw.githubusercontent.com/Homebrew/... is an
    official installer; the rest of raw.githubusercontent.com is not)."""
    out = set()
    for m in _URL_RE.finditer(text or ""):
        rest = m.group(0).split("://", 1)[1]
        host, _, path = rest.partition("/")
        host = host.rsplit("@", 1)[-1].split(":", 1)[0].lower()
        out.add(host + "/" + path.split("?", 1)[0])
    return out


def _short(text, n=70):
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[:n - 3] + "..."


def _decode_text(kind, text):
    if text is None:
        return None
    try:
        if kind == "hex":
            raw = binascii.unhexlify(re.sub(r"\s+", "", text))
        else:
            t = re.sub(r"\s+", "", text)
            raw = base64.b64decode(t + "=" * (-len(t) % 4))
        out = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return out if out.isprintable() or "\n" in out else None


def _literal_len(parts):
    return sum(len(p[1].strip()) for p in parts if p[0] == "lit")


def _code_sink(literal_chars):
    """Fetched data inside a mostly fixed program (a JSON response spliced into
    `python3 -c '...'` or a heredoc) is an injection risk; fetched data that
    is the program is remote code execution."""
    return "inject" if literal_chars >= 20 else "exec"


class ShellEvaluator:
    """Evaluates one shell script (or a series of snippets from one file,
    sharing variables and files) and appends Flows to ctx.flows."""

    def __init__(self, ctx, depth=0, state=None):
        self.ctx = ctx
        self.depth = depth
        self.vars = state.vars if state else {}
        self.files = state.files if state else {}
        self._fd = 62

    # -- values of words -------------------------------------------------------

    def value(self, word):
        if word is None:
            return EMPTY
        vals, texts = [], []
        for p in word.parts:
            if p[0] == "lit":
                texts.append(p[1])
                h = hosts_in(p[1])
                if h:
                    vals.append(Value(hosts=frozenset(h)))
            elif p[0] == "var":
                v = self.vars.get(p[1])
                if v is None:
                    texts.append("${" + p[1] + "}")
                else:
                    vals.append(v)
                    texts.append(v.text if v.text is not None else "${" + p[1] + "}")
            else:
                inner = self.run_sub(p[1], word.line)
                if p[2] in ("<(", ">("):
                    self._fd += 1
                    path = f"/dev/fd/{self._fd}"
                    self.files[path] = inner
                    texts.append(path)
                else:
                    vals.append(inner.as_text(None))
                    if inner.text is not None:
                        texts.append(inner.text)
                    else:
                        # Unknown output: a placeholder unique to this
                        # substitution, so two unrelated $(...) never look
                        # like the same file name.
                        self._fd += 1
                        texts.append(f"${{CMD{self._fd}}}")
        return union(vals).as_text("".join(texts))

    def run_sub(self, src, line):
        if self.depth >= MAX_DEPTH:
            return EMPTY
        sub = ShellEvaluator(self.ctx, self.depth + 1, self)
        return sub.run(src, line)

    # -- running ---------------------------------------------------------------

    def run(self, src, base_line=1):
        if len(src) > MAX_SCRIPT_CHARS:
            return EMPTY
        out = EMPTY
        for pipeline in parse(src, base_line):
            out = self.run_pipeline(pipeline)
        return out

    def run_pipeline(self, pipeline):
        data = EMPTY
        for cmd in pipeline:
            data = self.run_command(cmd, data)
        return data

    def flow(self, value, sink, line, text, language="shell"):
        if value.labels:
            self.ctx.flows.append(Flow(value, sink, Step(line, text), language))

    def _run_code(self, value, sink, line, text, lang, code_line):  # noqa: PLR0913, PLR0917
        """Code is about to run: record the flow, and analyze the code itself
        when its text is known (a decoded payload, an inline -c script)."""
        self.flow(value, sink, line, text)
        self._analyze_code(lang, value.text, code_line)

    def run_command(self, cmd, stdin):
        words = list(cmd.words)
        # Assignments before the command name.
        assigned = False
        while words:
            text = word_literal(Word(words[0].parts[:1], 0)) or ""
            m = _ASSIGN_RE.match(text)
            if not m:
                break
            self._assign(words.pop(0), m)
            assigned = True
        self._stdin_literal = 0
        stdin = self._apply_input_redirs(cmd, stdin)
        if not words:
            return EMPTY if assigned else stdin
        words = self._strip_wrappers(words)
        if not words:
            return EMPTY
        name_text = self.value(words[0]).text or ""
        name = posixpath.basename(name_text)
        args = words[1:]
        out = self._dispatch(name, name_text, args, stdin, cmd)
        return self._apply_output_redirs(cmd, out)

    def _assign(self, word, m):
        v = self.value(word)
        text = v.text[m.end():] if v.text is not None else None
        name = m.group(1)
        self.vars[name] = (self.vars.get(name, EMPTY) | v.as_text(text)) if "+=" in m.group(0) else v.as_text(text)

    def _strip_wrappers(self, words):
        while words:
            t = word_literal(words[0])
            if t in _IGNORE:
                return []
            if t == "for":
                rest = [w for w in words[2:] if word_literal(w) not in ("in", "do", ";")]
                if len(words) > 1:
                    self.vars[word_literal(words[1]) or "_"] = union(self.value(w) for w in rest)
                return []
            if t in _ASSIGN_BUILTINS:
                for w in words[1:]:
                    lit = word_literal(Word(w.parts[:1], 0)) or ""
                    m = _ASSIGN_RE.match(lit)
                    if m:
                        self._assign(w, m)
                return []
            if t not in _WRAPPERS or (len(words) == 1 and t in ("env", "command")):
                return words
            words = words[1:]
            while words and t in ("sudo", "doas", "env", "nice", "timeout", "stdbuf", "chroot"):
                nxt = word_literal(words[0]) or ""
                if nxt.startswith("-"):
                    words = words[2:] if nxt in ("-u", "-g", "-n", "-C", "-s", "-k", "--user") else words[1:]
                elif t == "env" and _ASSIGN_RE.match(nxt):
                    self._assign(words[0], _ASSIGN_RE.match(nxt))
                    words = words[1:]
                elif t == "timeout" and re.match(r"^\d", nxt):
                    words = words[1:]
                else:
                    break
        return words

    def _apply_input_redirs(self, cmd, stdin):
        for r in cmd.redirs:
            if r.op == "<":
                stdin = self._read_file(self.value(r.target).text, cmd.line)
            elif r.op == "<<<":
                v = self.value(r.target)
                stdin = v.as_text((v.text or "") + "\n" if v.text is not None else None)
            elif r.op in ("<<", "<<-") and r.body is not None:
                if r.body_quoted:
                    stdin = Value(text=r.body)
                else:
                    stdin = self.value(Word(parse_double_quoted(r.body, r.body_line), r.body_line))
                stdin = Value(stdin.labels, stdin.trail, stdin.hosts, stdin.text)
                self._heredoc_line = r.body_line
                self._stdin_literal = len(r.body.strip()) if r.body_quoted else _literal_len(parse_double_quoted(r.body, 0))
        return stdin

    def _apply_output_redirs(self, cmd, out):
        for r in cmd.redirs:
            if r.op in (">", ">>", ">|", "&>", "&>>"):
                path = self.value(r.target).text or ""
                if path.startswith("/dev/tcp/") or path.startswith("/dev/udp/"):
                    self.flow(out, "send", cmd.line, f"sends it to {_short(path)}")
                elif path not in ("/dev/null", "/dev/stderr", "/dev/stdout"):
                    self._write_file(path, out, cmd.line, append=r.op.endswith(">>"))
                out = EMPTY
        return out

    def _read_file(self, path, line):
        if not path:
            return EMPTY
        if path in self.files:
            return self.files[path]
        if CRED_PATH.search(path):
            return Value(frozenset({"secret"}), (Step(line, f"reads {_short(path)}"),))
        return EMPTY

    def _write_file(self, path, value, line, append=False):
        if not path:
            return
        if value.labels:
            value = value.then(Step(line, f"saves it to {_short(path)}"))
        self.files[path] = (self.files.get(path, EMPTY) | value) if append else value
        if PERSIST_PATH.search(path):
            persisted = value
            # Text written into a startup file is itself code: if it
            # downloads and runs something, that is what gets persisted.
            if value.text and self.depth < MAX_DEPTH:
                inner = _InnerCapture(self.ctx)
                ShellEvaluator(inner, self.depth + 1).run(value.text, line)
                for f in inner.flows:
                    persisted = persisted | f.value
            self.flow(persisted, "persist", line, f"writes it to {_short(path)}")

    # -- commands --------------------------------------------------------------

    def _dispatch(self, name, name_text, args, stdin, cmd):
        line = cmd.line
        if name in FETCHERS:
            return self._fetch(name, args, stdin, line)
        if name in SHELLS or name in INTERPRETERS or re.fullmatch(r"python\d(?:\.\d+)?", name):
            self._interpret(name, args, stdin, line)
            return EMPTY
        if name in ("source", "."):
            if args:
                path = self.value(args[0]).text or ""
                what = "it" if path.startswith("/dev/fd/") else _short(path)
                self.flow(self.files.get(path, EMPTY), "exec", line, f"runs {what} with {name}")
            return EMPTY
        if name == "eval":
            v = union(self.value(a) for a in args)
            self._run_code(v, _code_sink(sum(_literal_len(a.parts) for a in args)), line, "runs it with eval", "shell", line)
            return EMPTY
        if name in ("echo", "printf"):
            vals = [self.value(a) for a in args if not (word_literal(a) or "").startswith("-") or name == "printf"]
            text = " ".join(v.text or "" for v in vals) + "\n"
            return union(vals).as_text(text)
        if name in _DECODERS:
            return self._decode(name, args, stdin, line)
        if name in ("env", "printenv", "set") and not args:
            return Value(frozenset({"secret"}), (Step(line, "dumps the environment"),))
        if name == "security" and args and (word_literal(args[0]) or "").startswith("find-"):
            return Value(frozenset({"secret"}), (Step(line, "reads the macOS keychain"),))
        if name == "read":
            names = [word_literal(a) for a in args if not (word_literal(a) or "-").startswith("-")]
            for nm in names:
                if nm:
                    self.vars[nm] = stdin
            return EMPTY
        if name == "crontab":
            files = [self.value(a).text for a in args if not (word_literal(a) or "").startswith("-")]
            v = stdin if (not files or files == ["-"]) else union(self._read_file(f, line) for f in files)
            self.flow(v, "persist", line, "installs it as a crontab")
            return EMPTY
        if name in _SENDERS:
            self.flow(stdin, "send", line, f"sends it with {name}")
            return EMPTY
        if name in ("scp", "rsync"):
            # Only the files being copied count: `-i ~/.ssh/key` and
            # `-e "ssh -i key"` authenticate, they do not upload the key.
            paths, skip = [], False
            for a in args:
                t = self.value(a).text or ""
                if skip:
                    skip = False
                elif t.startswith("-"):
                    skip = t in ("-i", "-e", "-o", "-P", "-p", "-F", "-J", "-l", "-S", "--rsh", "-c")
                else:
                    paths.append(t)
            if any(re.match(r"^[\w.-]+@?[\w.-]*:", p) for p in paths[1:]):
                self.flow(union(self._read_file(p, line) for p in paths[:-1]), "send", line, f"uploads it with {name}")
            return EMPTY
        if name in _PASSTHROUGH:
            files = [self.value(a).text for a in args if not (word_literal(a) or "-").startswith("-")]
            if name in ("cat", "head", "tail", "tac", "less", "more", "strings") and files:
                return union(self._read_file(f, line) for f in files) or stdin
            if name == "tee":
                for f in files:
                    self._write_file(f, stdin, line, append=any(word_literal(a) == "-a" for a in args))
            return stdin
        # A path run directly: ./x, /tmp/x, "$F" (not an image or a document)
        if ("/" in name_text or name_text in self.files) and not _DATA_FILE.search(name_text):
            v = self.files.get(name_text, EMPTY)
            self.flow(v, "exec", line, f"runs {_short(name_text)}")
        return EMPTY

    def _fetch(self, name, args, stdin, line):
        value_flags = {"-o", "--output", "-d", "--data", "--data-binary", "--data-raw", "--data-urlencode",
                       "--data-ascii", "-F", "--form", "--form-string", "-T", "--upload-file", "-H", "--header",
                       "-X", "--request", "-u", "--user", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie",
                       "-x", "--proxy", "--url", "-w", "--write-out", "-m", "--max-time", "--connect-timeout",
                       "--retry", "-K", "--config", "-c", "--cookie-jar", "-r", "--range", "-C", "-E", "--cert",
                       "--key", "--cacert", "-z", "-O", "--output-document", "-P", "--directory-prefix",
                       "--post-data", "--post-file", "--body-data", "--body-file", "-U", "--password",
                       "--http-user", "--http-password", "-t", "--tries", "--timeout", "-a", "--append-output",
                       "-i", "--input-file", "--method", "--header-file", "-Y", "-y"}
        clustered = set("odFTHXuAebxwmKcrCEzOPUta")
        data_flags = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "-F",
                      "--form", "--form-string", "-T", "--upload-file", "--post-data", "--post-file",
                      "--body-data", "--body-file"}
        targets, outputs, data, remote_name = [], [], [], False
        i = 0
        while i < len(args):
            v = self.value(args[i])
            t = v.text or ""
            flag, val = None, None
            if t.startswith("--"):
                flag, _, inline = t.partition("=")
                if flag in value_flags:
                    val = self.value(args[i + 1]) if not inline and i + 1 < len(args) else v.as_text(inline)
                    i += 0 if inline else 1
                elif flag in ("--remote-name", "--remote-name-all"):
                    remote_name = True
            elif t.startswith("-") and len(t) > 1:
                letters = t[1:]
                for k, ch in enumerate(letters):
                    if ch in clustered:
                        flag = "-" + ch
                        rest = letters[k + 1:]
                        if name == "curl" and ch == "O" and not rest:
                            remote_name, flag = True, None
                        elif name == "wget" and ch == "o":
                            flag = "--log"
                            if not rest:
                                i += 1
                        elif rest:
                            val = v.as_text(rest)
                        elif i + 1 < len(args):
                            val = self.value(args[i + 1])
                            i += 1
                        break
            else:
                targets.append(v)
            if flag in ("-o", "--output") or (flag in ("-O", "--output-document") and name != "curl"):
                outputs.append(val.text if val else None)
            elif flag in ("-P", "--directory-prefix") and val:
                outputs.append((val.text or ".") + "/")
            elif flag in data_flags and val is not None:
                data.append(val)
            i += 1
        # A target must look like something fetchable: `--retry-delay 1` and
        # documentation placeholders ("curl URL | bash", "curl ...") are not.
        targets = [t for t in targets if t.labels or t.hosts or re.search(r"\$\{|[\w-]\.[a-z]{2,}|localhost", t.text or "")]
        if not targets:
            return EMPTY
        url_text = next((t.text for t in targets if t.text and "://" in t.text), targets[0].text or "")
        hosts = set().union(*[set(t.hosts) for t in targets]) | hosts_in(url_text)
        # Sending: data arguments, @file / @- uploads, and secrets put into the URL itself.
        sent = []
        for d in data:
            dt = (d.text or "").lstrip("=")
            dt = dt.split("=", 1)[1] if "=@" in dt else dt
            if dt.startswith("@") or dt.startswith("<"):
                p = dt[1:]
                sent.append(stdin if p == "-" else self._read_file(p, line))
            else:
                sent.append(d)
        sent.extend(t for t in targets if "secret" in t.labels)
        if sent:
            self.flow(union(sent), "send", line, f"sends it to {_short(url_text)} with {name}")
        fetched = Value(frozenset({"remote"}), (Step(line, f"fetches {_short(url_text)}"),), frozenset(hosts))
        if name == "wget" and not outputs:
            outputs.append(None)  # wget saves to a file named after the URL by default
        if remote_name or outputs:
            for requested in outputs or [None]:
                if requested == "-":
                    return fetched
                out = requested
                if out is None or out.endswith("/"):
                    base = posixpath.basename(url_text.split("?", 1)[0].rstrip("/")) or "index.html"
                    out = (out or "") + base
                self._write_file(out, fetched, line)
                # Keep the plain file name too: `curl -O x/run.sh && sh run.sh`
                self.files.setdefault(posixpath.basename(out), self.files[out])
                self.files.setdefault("./" + posixpath.basename(out), self.files[out])
            return EMPTY
        return fetched

    def _interpret(self, name, args, stdin, line):
        lang = "shell" if name in SHELLS else ("python" if name.startswith("python") else name)
        code, script, reads_stdin, code_literal = None, None, True, 0
        i = 0
        while i < len(args):
            t = self.value(args[i]).text or ""
            if t in _INLINE_CODE_FLAGS or (name in SHELLS and re.fullmatch(r"-[a-zA-Z]*c", t)):
                if i + 1 < len(args):
                    code = self.value(args[i + 1])
                    code_literal = _literal_len(args[i + 1].parts)
                reads_stdin = False
                break
            if t in ("-EncodedCommand", "-enc", "-e", "-ec") and name in ("pwsh", "powershell") and i + 1 < len(args):
                code = self._pwsh_encoded(self.value(args[i + 1]), line)
                reads_stdin = False
                break
            if t in ("-m",) and lang == "python":
                return
            if t in ("-", "-s"):
                reads_stdin = True  # what follows are arguments to the stdin script
                break
            if t.startswith("-") and t not in ("-File", "-file", "-f"):
                takes_value = (lang == "shell" and re.fullmatch(r"[-+][a-zA-Z]*[oO]", t)) or \
                    (lang == "python" and t in ("-W", "-X"))
                i += 2 if takes_value else 1
                continue
            if t in ("-File", "-file", "-f") and i + 1 < len(args):
                i += 1
                t = self.value(args[i]).text or ""
            if name in ("deno", "bun") and t in ("run", "x", "eval"):
                i += 1
                continue
            script = t
            reads_stdin = False
            break
        if code is not None:
            self._run_code(code, _code_sink(code_literal), line, f"runs it with {name}", lang, line)
        elif script is not None:
            if "://" in script:
                if name not in ("deno", "bun"):
                    return  # `python tool.py --url https://...`: the URL is an argument, not the script
                v = Value(frozenset({"remote"}), (Step(line, f"fetches {_short(script)}"),), frozenset(hosts_in(script)))
            else:
                v = self.files.get(script, EMPTY)
            what = "it" if script.startswith("/dev/fd/") else _short(script)
            self.flow(v, "exec", line, f"runs {what} with {name}")
        elif reads_stdin:
            self._run_code(stdin, _code_sink(self._stdin_literal), line, f"runs it with {name}", lang,
                           getattr(self, "_heredoc_line", line))

    def _pwsh_encoded(self, v, line):
        try:
            text = base64.b64decode(v.text or "").decode("utf-16-le")
        except (ValueError, UnicodeDecodeError):
            return v
        return v.with_label("decoded", Step(line, "decodes it (-EncodedCommand)")).as_text(text)

    def _decode(self, name, args, stdin, line):
        flags = " ".join(self.value(a).text or "" for a in args)
        if name == "xxd":
            if "-r" not in flags:
                return stdin
            kind = "hex"
        elif name == "openssl":
            if not re.search(r"\b(?:base64|enc)\b", flags) or not re.search(r"(?:^|\s)-d\b", flags):
                return stdin
            kind = "base64" if "base64" in flags or "-a" in flags else "cipher"
        elif name == "uudecode":
            kind = "uu"
        else:
            if not re.search(r"(?:^|\s)(?:-d|-D|--decode)\b|(?:^|\s)-\w*d\b", flags):
                return stdin
            kind = name
        decoded = _decode_text("hex" if kind == "hex" else "base64", stdin.text) if kind in ("hex", "base64") else None
        return stdin.with_label("decoded", Step(line, f"decodes it ({kind})")).as_text(decoded)

    def _analyze_code(self, lang, text, line):
        if not text or self.depth >= MAX_DEPTH:
            return
        if lang == "shell":
            ShellEvaluator(self.ctx, self.depth + 1, self).run(text, line)
        elif lang == "python":
            from .python_frontend import analyze_python  # noqa: PLC0415 - python_frontend imports this module
            analyze_python(text, self.ctx, line, self.depth + 1)


class _InnerCapture:
    """A throwaway context: collects flows of code that is only being
    written somewhere, not run here."""

    def __init__(self, parent):
        self.flows = []
        self.parent = parent


def analyze_shell(src, ctx, base_line=1, depth=0, state=None):
    """Analyze shell source; flows go to ctx.flows. Returns the evaluator,
    whose variables and files can be passed on as `state`."""
    ev = ShellEvaluator(ctx, depth, state)
    ev.run(src, base_line)
    return ev
