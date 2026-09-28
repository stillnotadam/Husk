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
import shutil
import sys
import tempfile
import zipfile

from .pdf_extract import extract_pdf_text

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

MAX_ARCHIVE_EXPANDED_BYTES = 50 * 1024 * 1024  # per archive, uncompressed
MAX_ARCHIVE_MEMBERS = 5000
MAX_TOTAL_EXPANDED_BYTES = 150 * 1024 * 1024  # across all nested archives in one scan


class ArchiveTooLarge(Exception):
    """Raised when an archive would expand past the safety limits."""


def _inside(root, target):
    root = os.path.realpath(root)
    return os.path.realpath(target).startswith(root + os.sep)


def safe_extract_zip(zf, dest, max_bytes=MAX_ARCHIVE_EXPANDED_BYTES, max_members=MAX_ARCHIVE_MEMBERS):
    """Extract an untrusted ZIP without letting it exhaust disk or memory.

    Checks the declared uncompressed sizes up front (zipfile never yields
    more bytes than a member declares, so the sum is a hard upper bound),
    caps the member count, and skips any path that would land outside dest.
    """
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > max_members:
        raise ArchiveTooLarge(f"{len(infos)} files (limit {max_members})")
    total = sum(i.file_size for i in infos)
    if total > max_bytes:
        raise ArchiveTooLarge(f"{total // (1024 * 1024)} MB (limit {max_bytes // (1024 * 1024)} MB)")
    for info in infos:
        target = os.path.join(dest, info.filename)
        if not _inside(dest, target):
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)



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


PACKAGE_SCANNABLE_EXTENSIONS = (
    ".md", ".txt", ".yaml", ".yml", ".py", ".json", ".js", ".ts", ".sh",
    ".rs", ".go", ".rb", ".ps1", ".toml", ".cmd", ".bat", ".mdc",
)


def scan_package(root_path, depth=0, findings=None, _budget=None, max_archive_bytes=None):
    """
    Walks a directory (or extracted archive), flags any file whose real
    type doesn't match a plain-text expectation, recurses into nested
    archives, and runs the existing text-based checks on real content.
    """
    if _budget is None:
        _budget = {"bytes": MAX_TOTAL_EXPANDED_BYTES if max_archive_bytes is None else max_archive_bytes}
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
                    (".zip", ".gz", ".7z", ".rar", ".tar", ".tgz")
                )
                # Many legitimate formats ARE zip/gzip containers - Office
                # documents, Java/Android bundles, ebooks, notebooks, packaged
                # skills, fonts. Flagging these as "hidden payloads" was a
                # major false-positive source on real repos (a skill shipping
                # reference .docx files scored in the tens of thousands). Only
                # a container masquerading as a plain text/code/data file is
                # actually deceptive.
                KNOWN_CONTAINER_EXTS = (
                    ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
                    ".odt", ".ods", ".odp", ".epub", ".jar", ".war", ".apk",
                    ".aar", ".ipa", ".whl", ".egg", ".nupkg", ".vsix",
                    ".ipynb", ".skill", ".crx", ".xpi", ".kmz", ".sketch",
                    ".graffle", ".numbers", ".pages", ".key", ".woff", ".woff2",
                )
                is_known_container = name.lower().endswith(KNOWN_CONTAINER_EXTS)
                DECEPTIVE_EXTS = (
                    ".md", ".txt", ".py", ".js", ".ts", ".sh", ".json",
                    ".yaml", ".yml", ".mdc", ".rst", ".cfg", ".ini", ".env",
                    ".rb", ".go", ".rs", ".mjs", ".cjs",
                )
                # Flag when a container hides under any extension that isn't
                # a known archive name and isn't a known container format -
                # that covers both text/code disguises (.md, .py) and opaque
                # ones (.dat, .bin, .cache). DECEPTIVE_EXTS is kept only to
                # document the common text/code cases.
                _ = DECEPTIVE_EXTS
                if not looks_like_archive_by_name and not is_known_container:
                    findings.append(
                        f"'{rel_path}' is actually a {real_type} despite its "
                        f"name/extension suggesting otherwise - a text/code file "
                        f"that is really an archive is a known technique for "
                        f"hiding payloads from extension-based scanners."
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
                                safe_extract_zip(zf, tmp, max_bytes=min(MAX_ARCHIVE_EXPANDED_BYTES, _budget["bytes"]))
                                _budget["bytes"] -= sum(i.file_size for i in zf.infolist())
                            scan_package(tmp, depth=depth + 1, findings=findings, _budget=_budget)
                    except zipfile.BadZipFile:
                        findings.append(f"'{rel_path}' claims to be a ZIP but is malformed - treat as suspicious.")
                    except ArchiveTooLarge as e:
                        findings.append(f"'{rel_path}' is an archive that expands to {e} - "
                                        "a zip-bomb pattern; its contents were not unpacked.")
                # (gzip/7z/rar extraction can be added the same way as needed)

            elif name.lower().endswith(".pdf"):
                # A bundled PDF can carry the skill's real (malicious)
                # instructions where a text-only scanner never looks. Extract
                # its text and run the full checks on it like any document.
                pdf_text, note = extract_pdf_text(full_path)
                if pdf_text:
                    with tempfile.NamedTemporaryFile(
                        "w", suffix=".md", delete=False, encoding="utf-8"
                    ) as tf:
                        tf.write(pdf_text)
                        tmp_md = tf.name
                    try:
                        result = scan_skill_file(tmp_md)
                        if result["verdict"] == "FLAGGED":
                            for f in result["findings"]:
                                findings.append(
                                    f"'{rel_path}' (extracted PDF text): {f}"
                                )
                    finally:
                        os.unlink(tmp_md)

            elif name.lower().endswith(PACKAGE_SCANNABLE_EXTENSIONS):
                # A genuine text/code file - run it through the full
                # module 1 + 2 checks rather than a separate weaker pass.
                result = scan_skill_file(full_path)
                if result["verdict"] == "FLAGGED":
                    for f in result["findings"]:
                        findings.append(f"'{rel_path}': {f}")

    # dedupe identical findings (a rule can match the same line twice)
    seen_findings = set()
    deduped = []
    for f in findings:
        if f not in seen_findings:
            seen_findings.add(f)
            deduped.append(f)
    return deduped


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
