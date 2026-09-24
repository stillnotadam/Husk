"""
Runs on every OS. Guards against a real bug found on Windows: sandbox.py
imported the Unix-only `resource` module unconditionally, and because
cli.py imports the sandbox at startup, the entire `husk` CLI crashed on
launch on Windows. The sandbox itself is Linux-only by design; these
tests confirm it degrades to an honest "skipped" result elsewhere
instead of crashing.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from husk import sandbox  # noqa: E402


def test_cli_module_imports_on_any_platform():
    from husk import cli  # noqa: F401, PLC0415 - the import itself is the test


def test_sandbox_reports_unsupported_cleanly_instead_of_crashing(monkeypatch):
    monkeypatch.setattr(sandbox, "SANDBOX_SUPPORTED", False)
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write("print('hi')\n")
        path = f.name
    try:
        result = sandbox.sandbox_run_script(path)
    finally:
        os.unlink(path)
    assert result["executed"] is False
    assert any("requires Linux" in finding for finding in result["findings"])
