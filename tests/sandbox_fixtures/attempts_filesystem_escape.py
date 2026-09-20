# Simulates an attempt to read/write outside the sandbox's working
# directory - verifies real filesystem isolation (bubblewrap) makes
# these paths genuinely invisible, not just unwritable. No real
# damage attempted, just existence/access checks.
import os

results = []

# Try to read a real, sensitive host path that should not be visible
# at all if filesystem isolation is active.
try:
    os.listdir("/root")
    results.append("READ_ROOT_SUCCEEDED")
except Exception:
    results.append("READ_ROOT_BLOCKED")

try:
    with open("/etc/shadow_marker_escape_test", "w") as f:
        f.write("escape attempt")
    results.append("WRITE_OUTSIDE_SUCCEEDED")
except Exception:
    results.append("WRITE_OUTSIDE_BLOCKED")

print(" ".join(results))
