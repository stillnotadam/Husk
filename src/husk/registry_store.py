"""
Husk trust registry - the data layer.

Phase 2 of the plan: turn one-off scans into a persistent, queryable, public
trust database for agent skills - the "is this skill safe?" lookup that makes
Husk infrastructure rather than a tool. This module is the spine: it ingests
scan results (exactly the rows the ecosystem scanner emits), keeps a verdict
history per skill, and answers lookups. A web frontend sits on top of this
later; the store is deliberately a plain SQLite file so it is trivial to host,
back up, and reason about.

What makes this defensible (and acquirable): it accumulates HISTORY. A single
scan is reproducible by anyone; a continuously-updated record of when each
skill was scanned, what verdict it got, and when a previously-safe skill
turned malicious, is a data asset no one can recreate after the fact. That is
the moat.

Design:
  * content-addressed: each verdict is tied to the skill's content digest, so
    a re-scan of unchanged content is idempotent and a changed skill creates a
    new verdict row (the audit trail).
  * append-only history: verdicts are never overwritten; the latest is a view.
  * no PII, no secrets: only public repo refs, digests, verdicts, findings
    counts. Safe to publish.
"""

import hashlib
import json
import os
import sqlite3
import time

DEFAULT_DB = os.path.join(os.path.expanduser("~"), ".husk", "registry.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS skills (
    ref            TEXT PRIMARY KEY,      -- owner/name
    source         TEXT,                  -- github | clawhub | ...
    url            TEXT,
    stars          INTEGER DEFAULT 0,
    first_seen     REAL,
    last_scanned   REAL,
    latest_digest  TEXT,
    latest_verdict TEXT,                  -- pass | warn | fail
    latest_score   INTEGER DEFAULT 0,
    sec_tool       INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS verdicts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ref        TEXT NOT NULL,
    digest     TEXT NOT NULL,
    scanned_at REAL NOT NULL,
    verdict    TEXT,
    score      INTEGER,
    critical   INTEGER DEFAULT 0,
    high       INTEGER DEFAULT 0,
    medium     INTEGER DEFAULT 0,
    low        INTEGER DEFAULT 0,
    info       INTEGER DEFAULT 0,
    findings   TEXT,                      -- JSON list of finding strings
    husk_version TEXT,
    UNIQUE(ref, digest, husk_version)     -- idempotent per content+ruleset
);
CREATE INDEX IF NOT EXISTS idx_verdicts_ref ON verdicts(ref);
CREATE INDEX IF NOT EXISTS idx_skills_verdict ON skills(latest_verdict);
CREATE INDEX IF NOT EXISTS idx_skills_score ON skills(latest_score);
"""


def _digest_of(row):
    """Rows from the scanner may or may not carry a content digest. If absent,
    derive a stable one from the findings + counts so re-ingesting the same
    result is idempotent."""
    if row.get("digest"):
        return row["digest"]
    basis = json.dumps({"counts": row.get("counts", {}),
                        "blocking": row.get("blocking", [])},
                       sort_keys=True).encode("utf-8")
    return "derived:" + hashlib.sha256(basis).hexdigest()[:32]


def connect(db_path=None):
    path = db_path or DEFAULT_DB
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def ingest_row(conn, row, source="github", husk_version="unknown"):
    """Ingest one scanner result row. Returns 'new' | 'changed' | 'unchanged'.
    Appends a verdict to history and updates the skill's latest view."""
    ref = row["ref"] if "ref" in row else row.get("repo")
    if not ref:
        return "skipped"
    digest = _digest_of(row)
    counts = row.get("counts", {}) or {}
    now = time.time()
    verdict = row.get("decision", "?")
    score = row.get("score", 0)
    findings = row.get("blocking", []) or []

    prior = conn.execute("SELECT latest_digest FROM skills WHERE ref=?", (ref,)).fetchone()
    status = "new" if prior is None else (
        "unchanged" if prior["latest_digest"] == digest else "changed")

    # append to history (idempotent on ref+digest+version)
    conn.execute(
        """INSERT OR IGNORE INTO verdicts
           (ref,digest,scanned_at,verdict,score,critical,high,medium,low,info,findings,husk_version)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ref, digest, now, verdict, score,
         counts.get("critical", 0), counts.get("high", 0), counts.get("medium", 0),
         counts.get("low", 0), counts.get("info", 0),
         json.dumps(findings), husk_version))

    conn.execute(
        """INSERT INTO skills (ref,source,url,stars,first_seen,last_scanned,
                               latest_digest,latest_verdict,latest_score,sec_tool)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(ref) DO UPDATE SET
             url=excluded.url, stars=excluded.stars, last_scanned=excluded.last_scanned,
             latest_digest=excluded.latest_digest, latest_verdict=excluded.latest_verdict,
             latest_score=excluded.latest_score, sec_tool=excluded.sec_tool""",
        (ref, source, row.get("url", ""), row.get("stars", 0), now, now,
         digest, verdict, score, 1 if row.get("sec_tool") else 0))
    conn.commit()
    return status


def ingest_results_file(conn, path, source="github", husk_version="unknown"):
    """Ingest a whole results.jsonl from an ecosystem scan. Returns a summary."""
    summary = {"new": 0, "changed": 0, "unchanged": 0, "skipped": 0}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("error"):
                continue
            summary[ingest_row(conn, row, source, husk_version)] += 1
    return summary


def lookup(conn, ref):
    """The core public query: 'is this skill safe?' Returns the latest verdict
    plus a short history, or None if unknown."""
    skill = conn.execute("SELECT * FROM skills WHERE ref=?", (ref,)).fetchone()
    if skill is None:
        return None
    history = conn.execute(
        """SELECT scanned_at,verdict,score,critical,high,medium,digest,husk_version
           FROM verdicts WHERE ref=? ORDER BY scanned_at DESC LIMIT 20""",
        (ref,)).fetchall()
    return {
        "ref": skill["ref"],
        "url": skill["url"],
        "stars": skill["stars"],
        "verdict": skill["latest_verdict"],
        "score": skill["latest_score"],
        "self_identifies_security_tool": bool(skill["sec_tool"]),
        "last_scanned": skill["last_scanned"],
        "history": [dict(h) for h in history],
        "turned_malicious": _turned_malicious(history),
    }


def _turned_malicious(history):
    """True if this skill was ever 'pass' and later 'fail' - the headline
    'a skill you trusted turned malicious' signal."""
    seq = [h["verdict"] for h in reversed(history)]  # oldest -> newest
    was_safe = False
    for v in seq:
        if v == "pass":
            was_safe = True
        elif v == "fail" and was_safe:
            return True
    return False


def stats(conn):
    """Ecosystem-wide roll-up for the registry landing page."""
    row = conn.execute(
        """SELECT COUNT(*) n,
                  SUM(latest_verdict='fail') fails,
                  SUM(latest_verdict='warn') warns,
                  SUM(latest_verdict='pass') passes,
                  SUM(sec_tool) sec_tools
           FROM skills""").fetchone()
    turned = 0
    for r in conn.execute("SELECT ref FROM skills WHERE latest_verdict='fail'"):
        h = conn.execute("SELECT verdict,scanned_at FROM verdicts WHERE ref=? ORDER BY scanned_at DESC LIMIT 20",
                         (r["ref"],)).fetchall()
        if _turned_malicious(h):
            turned += 1
    return {
        "skills": row["n"] or 0,
        "fail": row["fails"] or 0,
        "warn": row["warns"] or 0,
        "pass": row["passes"] or 0,
        "security_tools": row["sec_tools"] or 0,
        "turned_malicious": turned,
    }


def top_flagged(conn, limit=50, review_first_only=True):
    """The public 'most dangerous skills' list. review_first_only excludes
    self-described security tools (the likely-false-positive bucket)."""
    if review_first_only:
        q = ("SELECT ref,url,stars,latest_verdict,latest_score,sec_tool FROM skills "
             "WHERE latest_score > 0 AND sec_tool = 0 "
             "ORDER BY latest_score DESC LIMIT ?")
    else:
        q = ("SELECT ref,url,stars,latest_verdict,latest_score,sec_tool FROM skills "
             "WHERE latest_score > 0 "
             "ORDER BY latest_score DESC LIMIT ?")
    return [dict(r) for r in conn.execute(q, (limit,)).fetchall()]
