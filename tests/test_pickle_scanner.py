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
from husk.pickle_scanner import main, scan_file  # noqa: E402


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
        # os.system pickles under its real platform module: "posix" on
        # Linux/macOS, "nt" on Windows (found on a real Windows run).
        assert any(m in f.lower() for f in result["findings"] for m in ("'os.", "'posix.", "'nt."))
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


# ---------------------------------------------------------------------
# Real gap found via a coverage run: all existing tests above use
# Python's DEFAULT pickle protocol (5 since Python 3.8), which always
# uses STACK_GLOBAL - the older, combined-string GLOBAL opcode format
# (used by protocols 0-3, and still something a real file could use)
# had literally never been exercised by any test, despite the scanner
# explicitly claiming to handle it and having its own dedicated code
# path for it.
# ---------------------------------------------------------------------

def test_older_protocol_global_opcode_is_actually_detected():
    """Real, live verification, not assumed: protocol 0 genuinely
    produces the older combined-string GLOBAL opcode format (confirmed
    directly via pickletools.genops before writing this test), not
    STACK_GLOBAL - this is the actual code path being tested, not a
    guess at what an older protocol might look like."""
    class _OldStyleReduce:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        pickle.dump(_OldStyleReduce(), f, protocol=0)
        path = f.name
    try:
        result = scan_file(path)
        assert result["verdict"] == "FLAGGED"
        # os.system's real __module__ is "posix" on Linux, not "os" -
        # confirmed directly, the same real finding DANGEROUS_MODULES'
        # own comment already documents.
        assert any(m in f.lower() for f in result["findings"] for m in ("'posix.", "'nt."))
    finally:
        os.unlink(path)


def test_truncated_global_opcode_degrades_gracefully_not_a_crash():
    """Real finding while building this test, worth stating honestly
    rather than hidden: the intended target was the code's own
    `len(parts) < 2` defensive branch (a GLOBAL argument with no
    separator at all) - but pickletools.genops' own GLOBAL parsing
    structurally requires two newline-terminated lines, and always
    consumes whatever follows as the second one; several real,
    deliberately malformed byte sequences were tried and none reached
    that specific branch through genops' actual behavior, so it may
    be genuinely unreachable via this module's own real entry point,
    not merely untested. What IS real and verified here: a truncated,
    incomplete opcode stream must degrade to a clean, non-crashing
    result rather than an unhandled exception - confirmed directly."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        f.write(b"cjustoneword\n.\n")  # incomplete - genops raises "pickle exhausted before seeing STOP"
        path = f.name
    try:
        result = scan_file(path)
        assert result["verdict"] in ("SAFE", "FLAGGED", "ERROR")
    finally:
        os.unlink(path)


def test_stack_global_with_only_one_preceding_string_push_is_skipped_not_crashed():
    """Real, precisely constructed case for the code's own
    `elif len(recent_strings) == 2: ... else: continue` branch: a
    STACK_GLOBAL opcode (protocol 4+) needs exactly two preceding
    string-push opcodes to supply its module and name - this
    constructs a stream with only ONE, confirmed directly via
    pickletools.genops before writing this test to show STACK_GLOBAL's
    own arg really is None here (its real values live in the
    preceding string pushes, not its own argument) and that only one
    string push precedes it. Must be skipped cleanly, not raise, and
    not be treated as a false, empty-module/name match."""
    # PROTO 4 + one SHORT_BINUNICODE("test") push + STACK_GLOBAL + STOP,
    # hand-built at the byte level specifically to control exactly how
    # many string pushes precede STACK_GLOBAL - not producible via
    # pickle.dump() for any real object, since a real STACK_GLOBAL
    # reference always has both its module and name pushed first.
    data = b"\x80\x04" + b"\x8c\x04test" + b"\x93" + b"."
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        result = scan_file(path)
        assert result["verdict"] == "SAFE"  # skipped cleanly - no false match, no crash
    finally:
        os.unlink(path)


def test_main_cli_entry_prints_verdict_and_findings(capsys):
    """pickle_scanner.py's own standalone main() - not the real husk
    CLI (that's cli.py's cmd_model), a legacy dev entry point kept for
    direct module invocation. Low-value but real, previously
    untested."""
    path = _write_pickle({"harmless": True})
    old_argv = sys.argv
    sys.argv = ["scanner.py", path]
    try:
        main()
        captured = capsys.readouterr()
        assert "SAFE" in captured.out
    finally:
        sys.argv = old_argv
        os.unlink(path)


def test_main_cli_wrong_arg_count_exits_with_usage(capsys):
    old_argv = sys.argv
    sys.argv = ["scanner.py"]  # missing the required path argument
    try:
        try:
            main()
            raised = False
        except SystemExit:
            raised = True
        assert raised
        captured = capsys.readouterr()
        assert "Usage" in captured.out
    finally:
        sys.argv = old_argv
