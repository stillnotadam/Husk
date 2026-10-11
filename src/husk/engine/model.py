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
from dataclasses import dataclass, field
from typing import Optional

LABELS = ("remote", "secret", "decoded")
SINKS = ("exec", "inject", "send", "persist")


@dataclass(frozen=True)
class Step:
    line: int
    text: str

    def __str__(self):
        return f"line {self.line} {self.text}"


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
