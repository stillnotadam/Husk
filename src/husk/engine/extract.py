"""Find the code in a file: the whole file for scripts, fenced and inline
code plus command-looking lines for Markdown and text, `scripts` in
package.json, RUN lines in a Dockerfile, recipe lines in a Makefile.

Each snippet is (language, text, first line). Snippets from one document
are analyzed in order with shared state, so a download in one code block
and its execution in a later one are still connected.
"""
import json
import re

SHELL_EXTS = {".sh", ".bash", ".zsh", ".ksh", ".command", ".fish"}
PYTHON_EXTS = {".py", ".pyw"}
PROSE_EXTS = {".md", ".mdc", ".markdown", ".txt", ".rst", ".mdx", ""}
_SHELL_FENCES = {"bash", "sh", "shell", "zsh", "console", "terminal", "shell-session", "shellsession", "ksh", "fish"}
_PY_FENCES = {"python", "py", "python3"}
_FENCE = re.compile(r"^([ \t]*)(`{3,}|~{3,})[ \t]*([\w+-]*)[^\n]*\n(.*?)^\1\2[ \t]*$", re.MULTILINE | re.DOTALL)
_INLINE = re.compile(r"(?<!`)`([^`\n]{4,400})`(?!`)")
# Command words that start a runnable line in prose. Deliberately the ones
# that matter to the rules (fetching, running, decoding) - "cat the file"
# in a sentence is not worth lexing.
_CMD_START = re.compile(
    r"^(?:sudo\s+)?(?:curl|wget|bash|sh|zsh|eval|source|python[\d.]*|perl|ruby|node|php|pwsh|powershell|"
    r"echo|printf|base64|chmod|crontab|nc|ncat|iwr|irm|deno|bun|export|[A-Z_][A-Z0-9_]*=)\b")
_PROMPT = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+|>\s+)?(?:\$|%|#|PS[^>]*>|❯)?\s*")
# "Run: curl ...", "Then: ...", and a Dockerfile's "RUN curl ..." (Dockerfiles have no extension).
_LABEL_PREFIX = re.compile(r"^(?:(?i:run|execute|install|setup|command|then|and|first|next)\s*:\s*|RUN\s+)")


def _console_lines(text):
    """Strip shell prompts from a console transcript; drop output lines."""
    out = []
    for line in text.split("\n"):
        m = re.match(r"^\s*(?:\$|%|❯|#)\s+(.*)$", line)
        out.append(m.group(1) if m else line)
    return "\n".join(out)


def snippets(text, ext, shebang_shell=False):
    if ext in SHELL_EXTS or shebang_shell:
        return [("shell", text, 1)]
    if ext in PYTHON_EXTS:
        return [("python", text, 1)]
    if ext == ".json":
        return _package_json(text)
    if ext in PROSE_EXTS:
        return _prose(text)
    return []


def _prose(text):
    out, covered = [], []
    for m in _FENCE.finditer(text):
        lang = m.group(3).lower()
        body = m.group(4)
        line = text.count("\n", 0, m.start(4)) + 1
        covered.append((m.start(), m.end()))
        if lang in _SHELL_FENCES or (lang == "" and _looks_like_shell(body)):
            out.append((m.start(), ("shell", _console_lines(body) if lang in ("console", "terminal", "shell-session") else body, line)))
        elif lang in _PY_FENCES:
            out.append((m.start(), ("python", body, line)))
        elif lang in ("dockerfile", "docker"):
            out.extend((m.start(), s) for s in _dockerfile(body, line))
    pos, line_no = 0, 1
    for raw in text.split("\n"):
        start = pos
        pos += len(raw) + 1
        line_no += 1
        if any(a <= start < b for a, b in covered):
            continue
        for im in _INLINE.finditer(raw):
            code = im.group(1).strip()
            if _CMD_START.match(code):
                out.append((start + im.start(), ("shell", code, line_no - 1)))
        line = _LABEL_PREFIX.sub("", _PROMPT.sub("", raw, count=1), count=1)
        if "`" not in raw and _CMD_START.match(line) and _looks_like_shell(line):
            out.append((start, ("shell", line, line_no - 1)))
    return [s for _, s in sorted(out, key=lambda x: x[0])]


def _looks_like_shell(body):
    for raw in body.split("\n"):
        line = _PROMPT.sub("", raw, count=1).strip()
        if line and not line.startswith("#"):
            return bool(_CMD_START.match(line)) and not re.match(r"^\w+\s*[:=]\s*[\[{\"']", line)
    return False


def _package_json(text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    out = []
    for name, cmd in scripts.items():
        if isinstance(cmd, str):
            m = re.search(r'"' + re.escape(str(name)) + r'"\s*:', text)
            out.append(("shell", cmd, text.count("\n", 0, m.start()) + 1 if m else 1))
    return out


def _dockerfile(text, base=1):
    out = []
    # Continuation lines are joined in place (line numbers point at the RUN line).
    for i, line in enumerate(re.sub(r"\\\r?\n", " ", text).split("\n")):
        m = re.match(r"^\s*RUN\s+(.*)$", line, re.IGNORECASE)
        if m:
            out.append(("shell", m.group(1), base + i))
    return out


def makefile(text):
    return [("shell", line.lstrip("\t@-"), i + 1) for i, line in enumerate(text.split("\n")) if line.startswith("\t")]


def dockerfile(text):
    return _dockerfile(text)
