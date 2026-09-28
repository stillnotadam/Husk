"""Tests for the trust registry data layer."""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from husk.registry_store import (  # noqa: E402
    connect,
    ingest_row,
    lookup,
    stats,
    top_flagged,
)


def _row(ref, decision="pass", score=0, **kw):
    crit = kw.get("crit", 0)
    high = kw.get("high", 0)
    digest = kw.get("digest", "d")
    sec = kw.get("sec", False)
    url = kw.get("url", "u")
    return {"ref": ref, "url": url, "stars": 0, "decision": decision, "score": score,
            "counts": {"critical": crit, "high": high, "medium": 0, "low": 0, "info": 0},
            "blocking": [], "digest": digest, "sec_tool": sec}


def test_ingest_new_changed_unchanged(tmp_path):
    conn = connect(str(tmp_path / "r.db"))
    assert ingest_row(conn, _row("a/b", digest="d1")) == "new"
    assert ingest_row(conn, _row("a/b", digest="d1")) == "unchanged"
    assert ingest_row(conn, _row("a/b", digest="d2")) == "changed"


def test_lookup_unknown_is_none(tmp_path):
    conn = connect(str(tmp_path / "r.db"))
    assert lookup(conn, "nope/nope") is None


def test_turned_malicious_detected(tmp_path):
    conn = connect(str(tmp_path / "r.db"))
    ingest_row(conn, _row("x/y", "pass", 0, digest="safe"))
    time.sleep(0.01)
    ingest_row(conn, _row("x/y", "fail", 1000, crit=1, digest="evil"))
    r = lookup(conn, "x/y")
    assert r["verdict"] == "fail"
    assert r["turned_malicious"] is True


def test_stable_skill_not_flagged_as_turned(tmp_path):
    conn = connect(str(tmp_path / "r.db"))
    ingest_row(conn, _row("x/y", "pass", 0, digest="a"))
    time.sleep(0.01)
    ingest_row(conn, _row("x/y", "pass", 0, digest="b"))
    assert lookup(conn, "x/y")["turned_malicious"] is False


def test_stats_rollup(tmp_path):
    conn = connect(str(tmp_path / "r.db"))
    ingest_row(conn, _row("a/1", "pass"))
    ingest_row(conn, _row("a/2", "fail", 1000, crit=1))
    ingest_row(conn, _row("a/3", "fail", 300, high=3, sec=True))
    s = stats(conn)
    assert s["skills"] == 3 and s["fail"] == 2 and s["security_tools"] == 1


def test_top_flagged_excludes_security_tools(tmp_path):
    conn = connect(str(tmp_path / "r.db"))
    ingest_row(conn, _row("real/malware", "fail", 1000, crit=1, sec=False))
    ingest_row(conn, _row("a/scanner", "fail", 5000, high=50, sec=True))
    top = top_flagged(conn, review_first_only=True)
    refs = [t["ref"] for t in top]
    assert "real/malware" in refs
    assert "a/scanner" not in refs  # security tool excluded from review-first


def test_idempotent_reingest_same_scan(tmp_path):
    conn = connect(str(tmp_path / "r.db"))
    ingest_row(conn, _row("a/b", "fail", 1000, crit=1, digest="d1"))
    ingest_row(conn, _row("a/b", "fail", 1000, crit=1, digest="d1"))
    # only one verdict row for the same ref+digest+version
    n = conn.execute("SELECT COUNT(*) c FROM verdicts WHERE ref='a/b'").fetchone()["c"]
    assert n == 1
