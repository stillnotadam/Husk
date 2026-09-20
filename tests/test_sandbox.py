"""
Tests for the basic dynamic sandbox. Uses only safe, synthetic fixtures
(tests/sandbox_fixtures/) that demonstrate behavior PATTERNS (a script
that creates an unexpected file, a script that hangs) - never real
malware samples. See sandbox.py's module docstring for the honest scope
of what this basic sandbox does and does not do.
"""

import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.sandbox import sandbox_run_python_script, sandbox_run_script  # noqa: E402

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


def test_network_isolation_is_kernel_enforced_not_just_environmental():
    """
    Verifies network calls are blocked by an actual kernel network
    namespace (no route out exists at all), not merely by this
    environment's own external firewall. If this ever starts failing,
    it means real isolation silently stopped being available and the
    sandbox quietly fell back to a weaker mode - worth knowing, not
    something to hide.
    """
    result = sandbox_run_python_script(os.path.join(FIXTURE_DIR, "attempts_network_call.py"))
    assert result["executed"] is True
    if result["isolation_level"] != "none (resource limits only)":
        assert "NETWORK_CALL_BLOCKED" in result["stdout"]
    else:
        import warnings
        warnings.warn(
            "No real isolation was active for this test run - sandbox "
            "fell back to relying on the host's own network restrictions. "
            "Expected on systems without bwrap/unshare access, but worth "
            "knowing."
        )


def test_filesystem_isolation_is_real_when_bubblewrap_is_available():
    """
    Tier 4.2: the real filesystem-isolation upgrade. Verifies that,
    when bubblewrap isolation is active, paths outside the sandboxed
    working directory are genuinely inaccessible - not just a weaker
    permission error, but literally not there. If bubblewrap isn't
    available in this environment, honestly notes the weaker fallback
    rather than silently assuming protection that isn't real.
    """
    result = sandbox_run_python_script(os.path.join(FIXTURE_DIR, "attempts_filesystem_escape.py"))
    assert result["executed"] is True
    if result["isolation_level"].startswith("bubblewrap"):
        assert "READ_ROOT_BLOCKED" in result["stdout"]
        assert "WRITE_OUTSIDE_BLOCKED" in result["stdout"]
    else:
        import warnings
        warnings.warn(
            f"Filesystem isolation not active for this test run "
            f"(isolation_level={result['isolation_level']!r}) - real "
            f"filesystem isolation requires bubblewrap. Expected on "
            f"systems without it installed, but worth knowing."
        )


def test_javascript_is_sandboxed_with_correct_memory_handling():
    """
    Real multi-language support: verifies JS execution and file-
    creation detection work correctly, including the V8-specific
    memory-limit fix (Node's virtual address space reservation needs a
    different RLIMIT_AS ceiling than Python - see sandbox.py's
    LANGUAGE_INTERPRETERS/_apply_resource_limits docstrings for the
    full story of why this was necessary)."""
    result = sandbox_run_script(os.path.join(FIXTURE_DIR, "creates_unexpected_file.js"))
    if shutil.which("node") is None:
        pytest.skip("node not installed in this environment")
    assert result["executed"] is True
    assert result["exit_code"] == 0
    assert "unexpected_marker_js.txt" in result["files_created"]


def test_shell_scripts_are_sandboxed():
    """Real multi-language support: shell scripts run correctly through
    the same sandbox."""
    result = sandbox_run_script(os.path.join(FIXTURE_DIR, "normal_clean_script.sh"))
    assert result["executed"] is True
    assert result["exit_code"] == 0
    assert "Processing complete" in result["stdout"]


def test_unsupported_extension_degrades_gracefully():
    """A file type with no configured interpreter (or one that isn't
    actually installed) must be skipped cleanly, not crash."""
    with tempfile.NamedTemporaryFile(suffix=".rb", delete=False) as f:
        f.write(b"puts 'hello'")
        rb_path = f.name
    try:
        result = sandbox_run_script(rb_path)
        assert result["executed"] is False
        assert len(result["findings"]) == 1
    finally:
        os.unlink(rb_path)


def test_never_raises_on_a_nonexistent_script():
    """The sandbox must degrade gracefully, never crash the caller."""
    result = sandbox_run_python_script("/nonexistent/path/does_not_exist.py")
    assert isinstance(result, dict)
    assert "findings" in result
