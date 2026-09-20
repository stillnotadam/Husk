"""
Tests for the pickle-based model file scanner. Uses real pickle files
constructed with Python's own pickle module - safe, because this
scanner (and these tests) only ever INSPECT the opcode stream via
pickletools.genops, never actually unpickle/execute anything. That's
the entire safety property pickle_scanner.py depends on, and these
tests exercise it directly rather than only via manual testing.
"""

import os
import pickle
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.pickle_scanner import scan_file  # noqa: E402


class _DangerousReduce:
    """A real, classic pickle-exploit shape: __reduce__ tells pickle to
    call os.system with attacker-controlled args on load. Constructing
    this and pickling it is safe - it only WRITES the opcode stream to
    a file, it doesn't execute anything. scan_file never unpickles it
    either, consistent with the module's whole safety property."""

    def __reduce__(self):
        return (os.system, ("echo pwned",))


def _write_pickle(obj):
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        pickle.dump(obj, f)
        return f.name


def test_dangerous_reduce_payload_is_flagged():
    path = _write_pickle(_DangerousReduce())
    try:
        result = scan_file(path)
        assert result["verdict"] == "FLAGGED"
        assert any("os" in f.lower() for f in result["findings"])
    finally:
        os.unlink(path)


def test_ordinary_data_is_safe():
    """A real, ordinary pickle - a plain dict of numbers/strings, the
    shape a genuine model checkpoint's metadata might take - must not
    be flagged."""
    path = _write_pickle({"weights": [1, 2, 3], "name": "test-model", "version": 2})
    try:
        result = scan_file(path)
        assert result["verdict"] == "SAFE"
    finally:
        os.unlink(path)


def test_nonexistent_file_returns_error_not_a_crash():
    result = scan_file("/nonexistent/path/model.pkl")
    assert result["verdict"] == "ERROR"
    assert len(result["findings"]) == 1


def test_malformed_pickle_stream_is_flagged_not_crashed():
    """A file that isn't a valid pickle stream at all - malformed or
    deliberately obfuscated - must be reported as suspicious, not
    crash the scanner."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        f.write(b"this is not a real pickle stream at all, just noise")
        path = f.name
    try:
        result = scan_file(path)
        assert result["verdict"] == "FLAGGED"
    finally:
        os.unlink(path)


def test_subprocess_reference_is_flagged():
    """A different dangerous module than the os.system example above -
    verifies the DANGEROUS_MODULES set is actually checked generally,
    not just for one specific case."""
    class _SubprocessReduce:
        def __reduce__(self):
            return (subprocess.run, (["echo", "test"],))

    path = _write_pickle(_SubprocessReduce())
    try:
        result = scan_file(path)
        assert result["verdict"] == "FLAGGED"
        assert any("subprocess" in f.lower() for f in result["findings"])
    finally:
        os.unlink(path)
