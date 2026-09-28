"""Tests for the AST-based JS/TS taint engine."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from husk.js_taint_analysis import analyze_js_taint  # noqa: E402


def test_env_to_exec_flagged():
    fs = analyze_js_taint("const cmd = process.env.CMD;\nexecSync(cmd);")
    assert fs and "environment variable" in fs[0].source_desc
    assert fs[0].source_line == 1 and fs[0].line == 2


def test_bulk_env_to_network_flagged():
    fs = analyze_js_taint("const e = process.env;\naxios.post(u, JSON.stringify(e));")
    assert fs and "entire environment" in fs[0].source_desc


def test_credential_file_read_to_send_flagged():
    fs = analyze_js_taint("const c = fs.readFileSync('/root/.ssh/id_rsa');\naxios.post(u, c);")
    assert fs and "credential file" in fs[0].source_desc


def test_request_input_to_exec_flagged():
    fs = analyze_js_taint("const c = req.body.command;\nexec(c);")
    assert fs


def test_destructured_env_to_exec_flagged():
    fs = analyze_js_taint("const {SHELL_CMD} = process.env;\nexec(SHELL_CMD);")
    assert fs


def test_typescript_annotations_handled():
    fs = analyze_js_taint("const cmd: string = process.env.CMD;\nexecSync(cmd);")
    assert fs


def test_single_env_var_to_its_api_not_flagged():
    # the normal, correct way to use an API key: read one var, send to that API
    assert analyze_js_taint(
        "const key = process.env.API_KEY;\naxios.get(u, {headers:{Authorization: key}});"
    ) == []


def test_literal_exec_not_flagged():
    assert analyze_js_taint("execSync('ls -la');") == []


def test_local_var_exec_not_flagged():
    assert analyze_js_taint("const cmd = 'npm ci';\nexecSync(cmd);") == []


def test_env_logged_not_flagged():
    assert analyze_js_taint("const k = process.env.KEY;\nconsole.log(k);") == []


def test_unparseable_returns_empty():
    # gibberish / non-JS should not raise, just return nothing
    assert analyze_js_taint("this is not <<< valid javascript ]]]") == []


def test_trace_and_dict():
    f = analyze_js_taint("const cmd = process.env.CMD;\nexecSync(cmd);")[0]
    assert len(f.trace()) == 3
    d = f.to_dict()
    assert d["source_line"] == 1 and d["sink_line"] == 2 and d["variable"] == "cmd"
