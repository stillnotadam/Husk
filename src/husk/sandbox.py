"""
Husk - basic dynamic sandboxed analysis (Tier 2 / Tier 3.F).

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

HONEST SCOPE - READ THIS BEFORE TRUSTING IT
---------------------------------------------
This is a real step up from a "resource limits only" sandbox, but still
not full production-grade OS-level isolation like Docker/gVisor/Firecracker:

- **Network isolation is real and kernel-enforced when available**: on
  Linux with root (or unprivileged user namespaces enabled), this uses
  `unshare --net` to give the sandboxed script its own network
  namespace with NO network devices at all - not even a route to the
  outside world. A network call fails with "Network is unreachable" at
  the OS level, regardless of what firewall or proxy the host
  environment has. This was verified directly, not assumed: see
  tests/test_sandbox.py's network-isolation test. If real namespace
  isolation isn't available in a given environment, this module
  degrades to relying on the host's OWN network restrictions instead -
  and honestly reports which mode was used via the
  `kernel_namespace_isolation` field in every result, rather than
  silently claiming protection it doesn't have.
- **PID isolation is also real**: `unshare --pid --fork` gives the
  script its own process-ID namespace - it cannot see or signal any
  process outside it.
- **Filesystem isolation is still NOT real.** `unshare --mount` gives a
  private mount namespace (mount/unmount operations inside don't leak
  to the host), but without an additional chroot/pivot_root to a
  minimal root filesystem, the script can still READ the actual host
  filesystem it's running on. A script using an absolute path can see
  and potentially modify files outside the temp working directory. This
  remains a real, honest gap - a genuine chroot-based upgrade is a
  reasonable next step, not yet built.
- CPU time, memory, and process-count limits are enforced via Python's
  `resource` module (kernel-tracked `setrlimit`, real and independent
  of the namespace isolation above).
- Observation is limited to: exit code, stdout/stderr, wall-clock time,
  and a before/after filesystem diff of the working directory. It does
  NOT do real syscall tracing or deep process-tree monitoring beyond
  what the PID namespace itself provides.
- Only Python scripts are sandboxed in this version.

Given these real (and now partially closed) limits, this module is a
genuine additional signal - useful specifically for the logic-bomb/
delayed-activation class of attack no read-time review can catch, with
real network-exfiltration protection when namespace isolation is
available. It is still not a claim of full behavioral security coverage
- filesystem isolation in particular remains open. Treat findings from
this module as "here's what actually happened when we ran it," not
"this proves the script is safe."
"""

import os
import resource
import shutil
import subprocess
import sys
import tempfile


UNSHARE_AVAILABLE = shutil.which("unshare") is not None


# Conservative limits for a basic sandbox run. These are deliberately
# tight - a legitimate skill script doing normal work should finish
# well within them; a script trying to do something heavy (fork bomb,
# large download, long-running loop) will hit a limit and stop.
CPU_TIME_LIMIT_SECONDS = 5
MEMORY_LIMIT_MB = 256
MAX_PROCESSES = 10
WALL_CLOCK_TIMEOUT_SECONDS = 8


def _apply_resource_limits():
    """
    Runs in the child process (via subprocess's preexec_fn) before the
    sandboxed script starts. Sets hard limits so a runaway or malicious
    script can't consume unbounded CPU, memory, or process slots.
    """
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_TIME_LIMIT_SECONDS, CPU_TIME_LIMIT_SECONDS))
    mem_bytes = MEMORY_LIMIT_MB * 1024 * 1024
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


def _unshare_isolation_works():
    """
    Verifies real kernel namespace isolation actually works in this
    environment (requires root or unprivileged user namespaces enabled)
    rather than just assuming it does because the `unshare` binary
    exists. Cached after the first check.
    """
    if not UNSHARE_AVAILABLE:
        return False
    if not hasattr(_unshare_isolation_works, "_cached"):
        try:
            proc = subprocess.run(
                ["unshare", "--net", "--", "python3", "-c",
                 "import socket; socket.create_connection(('8.8.8.8', 53), timeout=2)"],
                capture_output=True, timeout=5,
            )
            # A real isolated network namespace has no route out at all;
            # the connection attempt should fail. If it somehow succeeds,
            # isolation isn't actually in effect here and we should not
            # claim it is.
            _unshare_isolation_works._cached = proc.returncode != 0
        except Exception:
            _unshare_isolation_works._cached = False
    return _unshare_isolation_works._cached


def _build_sandbox_command(script_abs_path):
    """
    Builds the command to run the sandboxed script. When real kernel
    namespace isolation is available and verified working, wraps the
    interpreter in `unshare --net --pid --mount --fork` for genuine,
    kernel-enforced isolation:
    - --net: a fresh network namespace with NO network devices at all
      (not even a route to loopback-external) - network calls fail at
      the OS level regardless of any external firewall/proxy. This is
      real isolation, not dependent on the host environment's own
      egress restrictions the way the earlier version was.
    - --pid --fork: a fresh PID namespace - the sandboxed script can't
      see or signal any process outside it.
    - --mount: a fresh mount namespace - mount/unmount operations
      inside don't affect the host (though without an additional
      chroot/pivot_root to a minimal root filesystem, the script can
      still READ the host's existing filesystem tree - see the honest
      scope note in this module's docstring).

    Falls back to the plain interpreter command (relying on resource
    limits and the host's own network restrictions, as in the original
    v1) when namespace isolation isn't available or verified working.
    """
    if _unshare_isolation_works():
        return (
            ["unshare", "--net", "--pid", "--mount", "--fork", "--",
             sys.executable, "-I", script_abs_path],
            True,
        )
    return ([sys.executable, "-I", script_abs_path], False)


def sandbox_run_python_script(script_path, timeout=WALL_CLOCK_TIMEOUT_SECONDS):
    """
    Runs a single Python script in a restricted temp working directory
    and reports what actually happened.

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
    }

    Never raises - a script that crashes, hangs, or misbehaves is
    exactly what this function exists to observe, not something that
    should blow up the caller.
    """
    import time

    result = {
        "executed": False, "timed_out": False, "exit_code": None,
        "stdout": "", "stderr": "", "files_created": [], "files_modified": [],
        "wall_clock_seconds": 0.0, "findings": [], "kernel_namespace_isolation": False,
    }

    with tempfile.TemporaryDirectory(prefix="husk_sandbox_") as workdir:
        before = _snapshot_dir(workdir)
        script_abs_path = os.path.abspath(script_path)
        # Minimal environment - do not pass through the real environment,
        # which could contain credentials or other sensitive values the
        # sandboxed script has no business seeing.
        restricted_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": workdir,
            "TMPDIR": workdir,
        }

        start = time.time()
        try:
            command, isolated = _build_sandbox_command(script_abs_path)
            result["kernel_namespace_isolation"] = isolated
            proc = subprocess.run(
                command,
                cwd=workdir,
                env=restricted_env,
                capture_output=True,
                text=True,
                timeout=timeout,
                preexec_fn=_apply_resource_limits,
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
            f"(e.g. a network call denied by the environment's egress "
            f"restrictions), or simply a normal error in the script."
        )

    return result
