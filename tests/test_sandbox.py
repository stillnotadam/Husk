"""
Tests for the basic dynamic sandbox. Uses only safe, synthetic fixtures
(tests/sandbox_fixtures/) that demonstrate behavior PATTERNS (a script
that creates an unexpected file, a script that hangs) - never real
malware samples. See sandbox.py's module docstring for the honest scope
of what this basic sandbox does and does not do.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.sandbox import sandbox_run_python_script  # noqa: E402

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "sandbox_fixtures")


def test_detects_file_created_at_runtime():
    """The core value proposition: a script whose static text gives no
    hint of file creation, but which the sandbox observes doing exactly
    that."""
    result = sandbox_run_python_script(os.path.join(FIXTURE_DIR, "creates_unexpected_file.py"))
    assert result["executed"] is True
    assert "unexpected_marker.txt" in result["files_created"]
    assert len(result["findings"]) >= 1


def test_stops_a_hanging_script_via_resource_limits():
    """A script that would hang forever must actually be stopped, not
    left running - this is the safety mechanism, not just a detection
    feature."""
    result = sandbox_run_python_script(os.path.join(FIXTURE_DIR, "hangs_forever.py"))
    assert result["executed"] is True
    # Either the wall-clock timeout or the CPU limit must have stopped it;
    # either way, it must not have run away unbounded.
    assert result["wall_clock_seconds"] < 15


def test_clean_script_produces_no_findings():
    """A normal, well-behaved script must not be flagged - a sandbox
    that cries wolf on ordinary scripts is as useless as one that
    misses real threats."""
    result = sandbox_run_python_script(os.path.join(FIXTURE_DIR, "normal_clean_script.py"))
    assert result["executed"] is True
    assert result["exit_code"] == 0
    assert result["findings"] == []


def test_never_raises_on_a_nonexistent_script():
    """The sandbox must degrade gracefully, never crash the caller."""
    result = sandbox_run_python_script("/nonexistent/path/does_not_exist.py")
    assert isinstance(result, dict)
    assert "findings" in result
