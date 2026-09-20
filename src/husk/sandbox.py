"""
Husk - basic dynamic sandboxed analysis (Tier 2 / Tier 3.F / Tier 4.2).

WHY THIS EXISTS
----------------
Static analysis (skill_scanner.py) and the optional LLM review layer
(llm_review.py) both READ a skill before anything runs. Some real
attacks are specifically designed to defeat that: logic bombs that stay
dormant until a condition is met (a date, an environment variable, a
specific argument), so nothing in the file's text ever reveals the
dangerous behavior. No amount of reading - static or AI-assisted - can
see behavior that only exists at runtime.

This module actually RUNS a skill's script in a restricted, observed
environment and reports what it did, not just what it says.

ISOLATION LEVELS, HONESTLY RANKED
-----------------------------------
This module tries three mechanisms, in order, and uses the strongest
one actually available and verified working in the current environment
- it never assumes a tool works just because it's installed, and every
result reports exactly which level was used via the `isolation_level`
field, rather than silently claiming protection that isn't really there.

1. **bubblewrap ("bwrap")** - real, kernel-enforced isolation of
   network, process visibility, AND filesystem, all three. This is the
   same underlying technology Flatpak uses in production to sandbox
   untrusted applications, not a hand-rolled technique. Verified
   directly during this project's own development: paths not
   explicitly bound are not merely unwritable but genuinely invisible
   (a real `FileNotFoundError`, not a permission error), and writes to
   unbound locations land in an isolated, ephemeral tmpfs that never
   touches the real host at all. This is the real answer to the
   filesystem-isolation gap this module used to have - see
   ROADMAP.md's "Tier 4.2" entry for the earlier attempt that was
   deliberately abandoned (a manual mount-namespace technique that
   broke the actual host filesystem twice) versus this one, a
   purpose-built, battle-tested tool instead of a hand-rolled trick.

2. **`unshare` (network + PID namespaces only)** - the earlier version
   of this module. Used only when bubblewrap isn't available. Real,
   kernel-enforced network and process isolation, but the script can
   still read (and, unlike with bubblewrap, WRITE to) the real host
   filesystem outside the working directory.

3. **Resource limits only** - the fallback when neither tool is
   available. Relies on the host environment's own network egress
   restrictions rather than enforcing isolation itself.

WHAT'S STILL NOT DONE, EVEN AT THE STRONGEST LEVEL
-----------------------------------------------------
- Observation is limited to exit code, stdout/stderr, wall-clock time,
  and a before/after filesystem diff of the *working directory specifically*
  (writes to the ephemeral tmpfs elsewhere aren't diffed, by design -
  they're isolated, not something this module needs to inspect).
  There's no real syscall tracing or network-call content interception.
- Only Python scripts are sandboxed in this version.
- CPU time, memory, and process-count limits are enforced via Python's
  `resource` module regardless of which isolation level is used.

Given all this, treat findings from this module as "here's what
actually happened when we ran it," not "this proves the script is
safe" - a clean run only means nothing bad happened this time, under
these inputs.
"""

import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import warnings


BWRAP_AVAILABLE = shutil.which("bwrap") is not None
UNSHARE_AVAILABLE = shutil.which("unshare") is not None

# Directories bound read-only into the bubblewrap sandbox so the Python
# interpreter itself can actually run. Only directories that exist on
# this system are used - checked once at import time, not assumed.
_CANDIDATE_SYSTEM_DIRS = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/lib32", "/libx32"]
SYSTEM_DIRS_TO_BIND = [d for d in _CANDIDATE_SYSTEM_DIRS if os.path.isdir(d)]

# Conservative limits for a basic sandbox run. These are deliberately
# tight - a legitimate skill script doing normal work should finish
# well within them; a script trying to do something heavy (fork bomb,
# large download, long-running loop) will hit a limit and stop.
CPU_TIME_LIMIT_SECONDS = 5
MEMORY_LIMIT_MB = 256
MAX_PROCESSES = 10
WALL_CLOCK_TIMEOUT_SECONDS = 8


def _apply_resource_limits(memory_limit_mb=MEMORY_LIMIT_MB):
    """
    Runs in the child process (via subprocess's preexec_fn) before the
    sandboxed script starts. Sets hard limits so a runaway or malicious
    script can't consume unbounded CPU, memory, or process slots. Kept
    independent of, and in addition to, whichever namespace isolation
    level is used below.

    memory_limit_mb is the RLIMIT_AS (virtual address space) ceiling -
    parameterized because Node's V8 engine needs a much higher ceiling
    here than Python does (V8 reserves several GB of virtual address
    space upfront regardless of actual usage; Python's virtual and
    actual usage track closely together). This is a generous backstop
    against truly unbounded allocation, not the primary memory control
    for Node specifically - that's --max-old-space-size in
    LANGUAGE_INTERPRETERS, which caps real heap usage.
    """
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_TIME_LIMIT_SECONDS, CPU_TIME_LIMIT_SECONDS))
    mem_bytes = memory_limit_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))


def _snapshot_dir(path):
    """Returns {relative_path: (size, mtime)} for every file under path."""
    snapshot = {}
    for root, _, files in os.walk(path):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, path)
            try:
                st = os.stat(full)
                snapshot[rel] = (st.st_size, st.st_mtime)
            except OSError:
                continue
    return snapshot


def _bwrap_isolation_works():
    """
    Verifies bubblewrap actually provides real isolation in this
    environment, rather than assuming it does because the binary
    exists (bwrap can itself fail to get the namespace permissions it
    needs in some restricted environments). Checks both that it runs
    at all, AND that an unbound path is genuinely invisible (the real
    property this module depends on for filesystem isolation) -
    verified with a real subprocess call, not assumed. Cached after
    the first check.
    """
    if not BWRAP_AVAILABLE:
        return False
    if not hasattr(_bwrap_isolation_works, "_cached"):
        try:
            proc = subprocess.run(
                ["bwrap", "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
                 "--ro-bind", "/lib64", "/lib64", "--ro-bind", "/bin", "/bin",
                 "--unshare-all", "--die-with-parent",
                 "--", "/usr/bin/python3", "-c",
                 "import os; assert not os.path.exists('/etc/hostname_marker_that_should_not_exist_anyway') and not os.path.isdir('/root')"],
                capture_output=True, timeout=5,
            )
            _bwrap_isolation_works._cached = proc.returncode == 0
        except Exception:
            _bwrap_isolation_works._cached = False
    return _bwrap_isolation_works._cached


def _unshare_isolation_works():
    """Same idea as _bwrap_isolation_works, for the network+PID-only
    fallback level. Cached after the first check."""
    if not UNSHARE_AVAILABLE:
        return False
    if not hasattr(_unshare_isolation_works, "_cached"):
        try:
            proc = subprocess.run(
                ["unshare", "--net", "--", "python3", "-c",
                 "import socket; socket.create_connection(('8.8.8.8', 53), timeout=2)"],
                capture_output=True, timeout=5,
            )
            _unshare_isolation_works._cached = proc.returncode != 0
        except Exception:
            _unshare_isolation_works._cached = False
    return _unshare_isolation_works._cached


# Interpreter command for each supported script extension. Node and
# bash/sh are genuinely available in most real environments (verified
# directly here rather than assumed) alongside Python, which already
# had sandbox support. Ruby is listed for completeness but will simply
# fail to execute (handled gracefully, same as any missing interpreter)
# if it isn't installed - this module never assumes an interpreter
# exists without checking.
LANGUAGE_INTERPRETERS = {
    ".py": [sys.executable, "-I"],
    # --max-old-space-size caps Node's actual heap usage in MB - the
    # right mechanism for V8-based runtimes. Found necessary via
    # testing: Node's V8 engine reserves several GB of VIRTUAL address
    # space upfront even for a trivial script (a well-known V8
    # characteristic, unrelated to actual memory use), which immediately
    # crashed with "Fatal process out of memory" under the same
    # RLIMIT_AS (virtual address space) limit that works fine for
    # Python. Real usage stays low; only the upfront virtual
    # reservation is huge, so RLIMIT_AS is the wrong tool for Node
    # specifically - see _apply_resource_limits below for the matching
    # fix on the other side.
    ".js": ["node", "--max-old-space-size=256"],
    ".sh": ["bash"],
    ".rb": ["ruby"],
}


def _interpreter_for(script_abs_path):
    """Returns the interpreter command list for a script's extension,
    or None if the extension isn't one this sandbox supports running."""
    ext = os.path.splitext(script_abs_path)[1].lower()
    return LANGUAGE_INTERPRETERS.get(ext)


def _build_sandbox_command(script_abs_path, workdir):
    """
    Builds the command to run the sandboxed script, using the
    strongest isolation level actually verified available. Returns
    (command_list, isolation_level_string).
    """
    interpreter = _interpreter_for(script_abs_path)
    if interpreter is None:
        # No supported interpreter for this extension - the caller
        # (sandbox_run_script) checks this before ever getting here,
        # this is just a defensive fallback.
        interpreter = [sys.executable, "-I"]

    if _bwrap_isolation_works():
        script_dir = os.path.dirname(script_abs_path)
        cmd = ["bwrap"]
        for d in SYSTEM_DIRS_TO_BIND:
            cmd += ["--ro-bind", d, d]
        cmd += [
            "--bind", workdir, workdir,
            # The script file itself lives outside every other bound
            # directory (e.g. wherever the skill package was extracted
            # to) - without binding its own directory read-only, bwrap
            # can't see it to execute it at all. Found via testing: this
            # was the real cause of every sandboxed run silently
            # producing empty output.
            "--ro-bind", script_dir, script_dir,
            "--unshare-all",
            "--die-with-parent",
            "--chdir", workdir,
            "--",
        ] + interpreter + [script_abs_path]
        return cmd, "bubblewrap (network + process + filesystem isolation)"

    if _unshare_isolation_works():
        return (
            ["unshare", "--net", "--pid", "--mount", "--fork", "--"]
            + interpreter + [script_abs_path],
            "unshare (network + process isolation only)",
        )

    return (interpreter + [script_abs_path], "none (resource limits only)")


def sandbox_run_script(script_path, timeout=WALL_CLOCK_TIMEOUT_SECONDS):
    """
    Runs a single script (Python, JavaScript, or shell - see
    LANGUAGE_INTERPRETERS) in a restricted temp working directory and
    reports what actually happened. This is the general entry point;
    sandbox_run_python_script (below) is kept as a backward-compatible
    alias for the Python-only version used by earlier tests/CLI code.
    """
    return _sandbox_run(script_path, timeout)


def sandbox_run_python_script(script_path, timeout=WALL_CLOCK_TIMEOUT_SECONDS):
    """Backward-compatible alias - Python was the only supported
    language when this name was introduced. Now just calls the general
    multi-language runner; kept as its own name since earlier tests and
    the CLI already reference it."""
    return _sandbox_run(script_path, timeout)


def _sandbox_run(script_path, timeout=WALL_CLOCK_TIMEOUT_SECONDS):
    """
    Runs a single script in a restricted temp working directory and
    reports what actually happened.

    Returns a dict:
    {
        "executed": bool,          # did it run at all (vs. failing to start)
        "timed_out": bool,
        "exit_code": int | None,
        "stdout": str,              # truncated to a reasonable length
        "stderr": str,
        "files_created": list[str],
        "files_modified": list[str],
        "wall_clock_seconds": float,
        "findings": list[str],      # human-readable flags, like the static scanner
        "isolation_level": str,     # exactly which mechanism actually ran, honestly
    }

    Never raises - a script that crashes, hangs, or misbehaves is
    exactly what this function exists to observe, not something that
    should blow up the caller.
    """
    result = {
        "executed": False, "timed_out": False, "exit_code": None,
        "stdout": "", "stderr": "", "files_created": [], "files_modified": [],
        "wall_clock_seconds": 0.0, "findings": [], "isolation_level": "none",
    }

    script_abs_path_check = os.path.abspath(script_path)
    interpreter_check = _interpreter_for(script_abs_path_check)
    if interpreter_check is None:
        result["findings"].append(
            f"Sandbox has no supported interpreter for this file type "
            f"({os.path.splitext(script_path)[1] or 'no extension'}) - "
            f"only Python, JavaScript, and shell scripts are sandboxed "
            f"in this version. Skipped, not an error."
        )
        return result
    if shutil.which(interpreter_check[0]) is None:
        result["findings"].append(
            f"Sandbox requires '{interpreter_check[0]}' to run this "
            f"script type, but it isn't installed in this environment. "
            f"Skipped gracefully rather than failing."
        )
        return result

    with tempfile.TemporaryDirectory(prefix="husk_sandbox_") as workdir:
        before = _snapshot_dir(workdir)
        script_abs_path = os.path.abspath(script_path)
        restricted_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": workdir,
            "TMPDIR": workdir,
        }

        start = time.time()
        try:
            command, isolation_level = _build_sandbox_command(script_abs_path, workdir)
            result["isolation_level"] = isolation_level
            # Node needs a much higher RLIMIT_AS ceiling (V8's upfront
            # virtual reservation) - see _apply_resource_limits' docstring.
            ext = os.path.splitext(script_abs_path)[1].lower()
            as_limit_mb = 4096 if ext == ".js" else MEMORY_LIMIT_MB
            proc = subprocess.run(
                command,
                cwd=workdir,
                env=restricted_env,
                capture_output=True,
                text=True,
                timeout=timeout,
                preexec_fn=lambda: _apply_resource_limits(as_limit_mb),
            )
            result["executed"] = True
            result["exit_code"] = proc.returncode
            result["stdout"] = proc.stdout[:2000]
            result["stderr"] = proc.stderr[:2000]
        except subprocess.TimeoutExpired as e:
            result["executed"] = True
            result["timed_out"] = True
            result["stdout"] = (e.stdout or "")[:2000] if isinstance(e.stdout, str) else ""
            result["findings"].append(
                f"Script did not finish within {timeout}s and was terminated - "
                f"could indicate an intentional long-running/hanging pattern, "
                f"or simply a slow legitimate script. Worth manual review."
            )
        except Exception as e:
            result["findings"].append(f"Sandbox could not execute the script: {e}")
            return result

        result["wall_clock_seconds"] = time.time() - start

        after = _snapshot_dir(workdir)
        for rel_path in after:
            if rel_path not in before:
                result["files_created"].append(rel_path)
            elif after[rel_path] != before[rel_path]:
                result["files_modified"].append(rel_path)

    if result["files_created"]:
        result["findings"].append(
            f"Script created {len(result['files_created'])} file(s) during "
            f"execution that weren't predictable from a static read: "
            f"{', '.join(result['files_created'][:5])}"
        )
    if result["exit_code"] is not None and result["exit_code"] < 0 and not result["timed_out"]:
        result["findings"].append(
            f"Script was terminated by signal {-result['exit_code']} - most "
            f"likely the CPU time or memory limit was hit (SIGKILL), "
            f"consistent with a hanging loop, a fork bomb, or an attempt to "
            f"consume more resources than a normal script should need."
        )
    elif result["exit_code"] not in (0, None) and not result["timed_out"]:
        result["findings"].append(
            f"Script exited with non-zero code {result['exit_code']} - "
            f"may indicate it attempted something the sandbox blocked "
            f"(e.g. a network call, or a read/write to a path outside the "
            f"sandbox), or simply a normal error in the script."
        )

    return result
