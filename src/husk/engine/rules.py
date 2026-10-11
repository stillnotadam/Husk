"""Engine rules: which labelled data reaching which sink is a finding.

Rule files use a small, strict subset of YAML so Husk needs no YAML
dependency:

    # comment
    - id: HUSK-RCE-001
      title: Downloaded code is executed
      severity: high            # critical | high | medium | low | info
      from: [remote]            # any of: remote, secret, decoded
      to: exec                  # exec | send | persist
      trusted_installers: info  # optional: severity when every fetched
                                # host is an official installer host
      explain: One line of explanation shown by `husk rules`.

A flow is reported once, by the first rule in file order that matches it,
so put more specific rules first. Anything outside this subset is an
error with a line number, never silently ignored.
"""
import os
import re
from dataclasses import dataclass

from .model import LABELS, SINKS

SEVERITIES = ("critical", "high", "medium", "low", "info")
_KEYS = {"id", "title", "severity", "from", "to", "trusted_installers", "explain"}
_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
CORE_RULES = os.path.join(os.path.dirname(__file__), "rules", "core.yml")


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    labels: frozenset
    sink: str
    trusted_installers: str = ""
    explain: str = ""
    source: str = ""

    def matches(self, flow):
        return flow.sink == self.sink and bool(self.labels & flow.value.labels)


def _scalar(text, where):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        return [_scalar(x, where) for x in text[1:-1].split(",") if x.strip()]
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    if text.startswith(("[", "{", "|", ">", "&", "*", "!")):
        raise RuleError(f"{where}: unsupported YAML syntax {text[:20]!r}")
    return re.sub(r"\s+#.*$", "", text)


def parse_rules(text, source="<rules>"):
    items, cur = [], None
    for n, raw in enumerate(text.split("\n"), 1):
        where = f"{source}:{n}"
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^(-\s+|\s+)([A-Za-z_]+):(?:\s+(.*))?$", line)
        if not m:
            raise RuleError(f"{where}: expected 'key: value' or '- key: value', got {line.strip()[:40]!r}")
        if m.group(1).startswith("-"):
            cur, lines = {}, {}
            items.append((n, cur, lines))
        elif cur is None:
            raise RuleError(f"{where}: rule fields must follow a '- id: ...' line")
        key, value = m.group(2), m.group(3)
        if key not in _KEYS:
            raise RuleError(f"{where}: unknown field {key!r} (allowed: {', '.join(sorted(_KEYS))})")
        if key in cur:
            raise RuleError(f"{where}: duplicate field {key!r}")
        if value is None:
            raise RuleError(f"{where}: field {key!r} has no value")
        cur[key] = _scalar(value, where)
        lines[key] = n
    return [_build(d, source, n, lines) for n, d, lines in items]


def _build(d, source, start, lines):
    """Validate one rule. Errors point at the offending field's line."""
    def at(key):
        return f"{source}:{lines.get(key, start)}"

    for k in ("id", "title", "severity", "from", "to"):
        if k not in d:
            raise RuleError(f"{source}:{start}: rule is missing {k!r}")
    if not _ID_RE.match(d["id"]):
        raise RuleError(f"{at('id')}: id {d['id']!r} must look like HUSK-RCE-001")
    labels = d["from"] if isinstance(d["from"], list) else [d["from"]]
    bad = [x for x in labels if x not in LABELS]
    if bad:
        raise RuleError(f"{at('from')}: unknown label(s) {bad} (known: {', '.join(LABELS)})")
    if d["to"] not in SINKS:
        raise RuleError(f"{at('to')}: unknown sink {d['to']!r} (known: {', '.join(SINKS)})")
    for k in ("severity", "trusted_installers"):
        if k in d and d[k] not in SEVERITIES:
            raise RuleError(f"{at(k)}: {k} must be one of {', '.join(SEVERITIES)}")
    return Rule(d["id"], d["title"], d["severity"], frozenset(labels), d["to"],
                d.get("trusted_installers", ""), d.get("explain", ""), f"{source}:{start}")


_cache: dict = {}  # (core path, *extra paths) -> rules


def load_rules(paths=None):
    """Core rules plus any extra rule files (`paths`, or the HUSK_RULES
    environment variable, os.pathsep-separated). Extra rules are checked
    after the core ones."""
    if paths is None:
        env = os.environ.get("HUSK_RULES", "")
        paths = [p for p in env.split(os.pathsep) if p]
    key = (CORE_RULES, *paths)
    if key not in _cache:
        rules, seen = [], set()
        for p in key:
            with open(p, encoding="utf-8") as fh:
                for r in parse_rules(fh.read(), os.path.basename(p)):
                    if r.id in seen:
                        raise RuleError(f"{r.source}: rule id {r.id} is already defined")
                    seen.add(r.id)
                    rules.append(r)
        _cache[key] = rules
    return _cache[key]
