"""The engine's data model: values carry labels with a provenance trail,
and a value reaching a sink becomes a Flow that rules can match.

Labels say where data came from:
  remote   fetched over the network
  secret   a credential store (SSH keys, cloud/registry credentials, the
           keychain, browser logins) or the whole environment. A single
           environment variable is not: sending an API key to its own API
           is what skills normally do.
  decoded  produced by a decoder (base64, hex, ...) - obfuscation
Sinks say what happens to it:
  exec     run as code (shell, interpreter, eval/exec, deserialization)
  inject   spliced into otherwise fixed code, or passed to Python's eval()
  send     sent over the network
  persist  written to a shell startup file, cron, launchd, systemd, ...
"""
import contextvars
import posixpath
from dataclasses import dataclass, field
from typing import Optional

LABELS = ("remote", "secret", "decoded")
SINKS = ("exec", "inject", "send", "persist")

# The file being analysed, when a whole package is (engine.analyze_package).
# Steps record it, so a chain can say which file each step is in.
CURRENT_FILE: contextvars.ContextVar = contextvars.ContextVar("husk_engine_file", default="")


@dataclass(frozen=True)
class Step:
    line: int
    text: str
    file: str = field(default_factory=CURRENT_FILE.get)

    def __str__(self):
        return f"{self.file} line {self.line} {self.text}" if self.file else f"line {self.line} {self.text}"


def norm_path(path):
    """One spelling per path, so a file written as "$HOME/.cache/x" by one
    script and run as "~/.cache/x" by another is the same file."""
    if not path:
        return path
    for home in ("${HOME}", "$HOME"):
        if path == home or path.startswith(home + "/"):
            path = "~" + path[len(home):]
    norm = posixpath.normpath(path)
    return norm[2:] if norm.startswith("./") else norm


def shared_files(ctx):
    """The file table front ends share: the context's, or a private one."""
    files = getattr(ctx, "files", None)
    return files if files is not None else Files()


def module_returns(ctx, kind, module):
    """What functions of another module of the package return (name -> Value)."""
    table = getattr(ctx, "module_returns", None)
    return table.get((kind, module), {}) if table else {}


class Files(dict):
    """Files written so far (path -> Value), keyed by normalised path. One
    instance is shared by every front end analysing a file, or a package.
    `literal` remembers how much fixed text a file was written with (a
    heredoc config with one fetched value in it is not a downloaded script)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.literal = {}

    def __getitem__(self, k):
        return super().__getitem__(norm_path(k))

    def __setitem__(self, k, v):
        super().__setitem__(norm_path(k), v)

    def __contains__(self, k):
        return super().__contains__(norm_path(k))

    def get(self, k, default=None):
        return super().get(norm_path(k), default)


@dataclass(frozen=True)
class Value:
    """What is known about a piece of data. `text` is its literal content
    when the analysis can tell (a quoted string, a decoded blob)."""
    labels: frozenset = frozenset()
    trail: tuple = ()
    hosts: frozenset = frozenset()
    text: Optional[str] = None

    def __or__(self, other):
        if other is None or (not other.labels and not other.hosts and other.text is None):
            return self
        if not self.labels and not self.hosts and self.text is None:
            return other
        trail = self.trail + tuple(s for s in other.trail if s not in self.trail)
        text = self.text + other.text if self.text is not None and other.text is not None else None
        return Value(self.labels | other.labels, trail[-8:], self.hosts | other.hosts, text)

    def with_label(self, label, step, hosts=()):
        return Value(self.labels | {label}, (self.trail + (step,))[-8:], self.hosts | frozenset(hosts), self.text)

    def then(self, step):
        """Same data, one more step in its history."""
        if not self.labels:
            return self
        return Value(self.labels, (self.trail + (step,))[-8:], self.hosts, self.text)

    def as_text(self, text):
        return Value(self.labels, self.trail, self.hosts, text)


EMPTY = Value()


def union(values):
    out = EMPTY
    for v in values:
        out = out | v
    return out


@dataclass(frozen=True)
class Flow:
    """`value` reached `sink` at `step`."""
    value: Value
    sink: str
    step: Step
    language: str = ""
    notes: tuple = field(default=())

    def chain(self):
        steps = [s for s in self.value.trail if s != self.step] + [self.step]
        return " -> ".join(str(s) for s in steps)
