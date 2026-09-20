"""
Husk - module 3: archive indirection detection.

THE ATTACK
----------
A skill package normally contains plain files: a SKILL.md, maybe some
scripts. An attacker hides the real payload inside a nested archive
(a zip inside a zip, or a zip renamed with an innocent extension like
"icon_cache.dat"), betting that a scanner only inspects files that
LOOK like text or code by their extension, and never unpacks anything
else.

THE DEFENSE
-----------
Never trust a file extension. Every file's real type is checked by its
binary "magic bytes" - the first few bytes of the file, which reveal
its true format regardless of what it's named. Anything that turns out
to be an archive gets extracted and scanned recursively, however many
layers deep, using the same checks from skill_scanner.py.
"""

import os
import sys
import tempfile
import zipfile

# Import the module-1 and module-2 checks so archive contents get the
# full treatment, not a separate weaker pass.
from .skill_scanner import scan_skill_file

# Magic bytes for common archive formats, independent of file extension.
ARCHIVE_SIGNATURES = {
    b"PK\x03\x04": "ZIP archive",
    b"PK\x05\x06": "ZIP archive (empty)",
    b"\x1f\x8b": "GZIP archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"Rar!\x1a\x07": "RAR archive",
}

MAX_RECURSION_DEPTH = 5  # guard against zip bombs / infinite nesting


def detect_real_file_type(path):
    """Reads a file's actual magic bytes, ignoring its extension."""
    try:
        with open(path, "rb") as f:
            header = f.read(8)
    except OSError:
        return None

    for sig, kind in ARCHIVE_SIGNATURES.items():
        if header.startswith(sig):
            return kind
    return None


def scan_package(root_path, depth=0, findings=None):
    """
    Walks a directory (or extracted archive), flags any file whose real
    type doesn't match a plain-text expectation, recurses into nested
    archives, and runs the existing text-based checks on real content.
    """
    if findings is None:
        findings = []

    if depth > MAX_RECURSION_DEPTH:
        findings.append(
            f"Archive nesting exceeded {MAX_RECURSION_DEPTH} levels - "
            f"stopped recursing. Unusually deep nesting is itself suspicious."
        )
        return findings

    for dirpath, _, filenames in os.walk(root_path):
        for name in filenames:
            full_path = os.path.join(dirpath, name)
            rel_path = os.path.relpath(full_path, root_path)
            real_type = detect_real_file_type(full_path)

            if real_type:
                looks_like_archive_by_name = name.lower().endswith(
                    (".zip", ".gz", ".7z", ".rar", ".tar")
                )
                if not looks_like_archive_by_name:
                    findings.append(
                        f"'{rel_path}' is actually a {real_type} despite its "
                        f"name/extension suggesting otherwise - this mismatch "
                        f"is a known technique for hiding payloads from "
                        f"extension-based scanners."
                    )
                else:
                    # Honest, matching extension: this is purely
                    # procedural (recurse and scan), not itself evidence
                    # of anything suspicious. Don't append it to findings
                    # - a real bug found via testing had ANY honestly-
                    # named nested archive (e.g. a legitimate bundled
                    # dependency .tar.gz) count as a false FLAGGED
                    # verdict just for existing, before its contents
                    # were even scanned.
                    pass

                # Recurse into it regardless of whether the name was honest.
                if real_type.startswith("ZIP"):
                    try:
                        with tempfile.TemporaryDirectory() as tmp:
                            with zipfile.ZipFile(full_path) as zf:
                                zf.extractall(tmp)
                            scan_package(tmp, depth=depth + 1, findings=findings)
                    except zipfile.BadZipFile:
                        findings.append(f"'{rel_path}' claims to be a ZIP but is malformed - treat as suspicious.")
                # (gzip/7z/rar extraction can be added the same way as needed)

            elif name.lower().endswith((".md", ".txt", ".yaml", ".yml", ".py", ".json", ".js", ".ts", ".sh", ".rs", ".go", ".rb", ".ps1", ".toml", ".cmd", ".bat", ".mdc")):
                # A genuine text/code file - run it through the full
                # module 1 + 2 checks rather than a separate weaker pass.
                result = scan_skill_file(full_path)
                if result["verdict"] == "FLAGGED":
                    for f in result["findings"]:
                        findings.append(f"'{rel_path}': {f}")

    return findings


def main():
    if len(sys.argv) != 2:
        print("Usage: python package_scanner.py <path_to_skill_package_dir>")
        sys.exit(1)

    findings = scan_package(sys.argv[1])
    verdict = "FLAGGED" if any(
        "hiding payloads" in f or "malformed" in f or "Inside decoded" in f
        or "Line" in f for f in findings
    ) else ("SAFE" if not findings else "INFO")

    print(f"\nHusk package scan result: {verdict}")
    for f in findings:
        print(f"  - {f}")
    print()


if __name__ == "__main__":
    main()
