"""
Husk v1 - a static scanner for pickle-based files.

Core idea: pickle files are instruction lists that Python replays to
rebuild an object. One instruction type, GLOBAL, says "import this
name from this module." If that module is something like `os` or
`subprocess`, loading the file can run arbitrary code.

This scanner reads those instructions as plain data using Python's
own `pickletools` module - it never unpickles (executes) the file.
That's the entire safety property this tool depends on: inspect,
don't run.
"""

import pickletools
import sys

# Modules that have no legitimate reason to appear in a model's
# pickle stream, but are exactly what a malicious payload would need
# to run commands, touch the filesystem, or open a network connection.
DANGEROUS_MODULES = {
    "os",
    # "posix" and "nt" are os.system/os.popen/etc's REAL __module__ on
    # Linux/Windows respectively - os itself just re-exports from
    # these platform modules. Found via testing: a real pickled
    # os.system reference serializes with module name "posix", not
    # "os" - the "os" entry alone missed this entirely.
    "posix",
    "nt",
    "subprocess",
    "sys",
    "socket",
    "shutil",
    "builtins",  # covers eval/exec/__import__ when referenced directly
}

# Specific dangerous names even from otherwise-common modules.
DANGEROUS_NAMES = {
    "eval",
    "exec",
    "system",
    "popen",
    "spawn",
    "__import__",
}


def scan_file(path):
    """
    Returns a dict: {"verdict": "SAFE" | "FLAGGED", "findings": [...]}
    findings is a list of human-readable reasons, one per suspicious
    instruction found.
    """
    findings = []

    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return {"verdict": "ERROR", "findings": [f"Could not read file: {e}"]}

    # String-pushing opcodes that can supply STACK_GLOBAL's module/name
    # (protocol 4+ pushes these as two separate ops onto the pickle
    # VM's stack, THEN STACK_GLOBAL combines them - unlike the older
    # GLOBAL opcode, which encodes "module name" directly as its own
    # arg). Found necessary via testing: STACK_GLOBAL's own `arg` from
    # genops is always None - the real values live in the two preceding
    # string pushes. Missing this meant EVERY pickle using protocol 4+
    # (Python's default since 3.8) was completely invisible to this
    # scanner, regardless of what it referenced.
    STRING_PUSH_OPS = {
        "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
        "SHORT_BINSTRING", "BINSTRING",
    }

    try:
        # genops walks the instruction stream one opcode at a time.
        # We are only ever reading; nothing here executes the pickle.
        recent_strings = []  # last few string-push values, in order
        for opcode, arg, pos in pickletools.genops(data):
            if opcode.name in STRING_PUSH_OPS and arg is not None:
                recent_strings.append(str(arg))
                recent_strings = recent_strings[-2:]

            if opcode.name in ("GLOBAL", "STACK_GLOBAL"):
                if arg is not None:
                    # Older-style GLOBAL: "module name" as one combined
                    # string argument, e.g. "os system".
                    parts = str(arg).replace("\n", " ").split()
                    if len(parts) >= 2:
                        module, name = parts[0], parts[1]
                    else:
                        module, name = parts[0], ""
                elif len(recent_strings) == 2:
                    # STACK_GLOBAL (protocol 4+): module and name were
                    # pushed as the two preceding string opcodes.
                    module, name = recent_strings[0], recent_strings[1]
                else:
                    continue

                if module in DANGEROUS_MODULES or name.lower() in DANGEROUS_NAMES:
                    findings.append(
                        f"Suspicious reference at byte {pos}: "
                        f"'{module}.{name}' - this module/function can "
                        f"execute system-level operations on load."
                    )
    except Exception as e:
        # A malformed or deliberately corrupted pickle stream is itself
        # a signal worth surfacing, not just a crash to hide.
        return {
            "verdict": "FLAGGED",
            "findings": [f"File could not be cleanly parsed as a pickle "
                         f"stream ({e}) - malformed or obfuscated files "
                         f"are themselves a red flag."],
        }

    if findings:
        return {"verdict": "FLAGGED", "findings": findings}
    return {"verdict": "SAFE", "findings": ["No known-dangerous opcodes found."]}


def main():
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <path_to_file>")
        sys.exit(1)

    result = scan_file(sys.argv[1])
    print(f"\nHusk scan result: {result['verdict']}")
    for finding in result["findings"]:
        print(f"  - {finding}")
    print()


if __name__ == "__main__":
    main()
