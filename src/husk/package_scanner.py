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

import gzip
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile

from .pdf_extract import extract_pdf_text
from .pickle_scanner import scan_file as scan_pickle_file

try:
    from zlib import error as zlib_error
except ImportError:  # pragma: no cover - zlib is always present in CPython
    zlib_error = OSError  # type: ignore[assignment,misc]

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



def safe_extract_tar(tf, dest, max_bytes=MAX_ARCHIVE_EXPANDED_BYTES, max_members=MAX_ARCHIVE_MEMBERS):
    """Extract an untrusted TAR the same way as safe_extract_zip: regular
    files only (no links or devices), declared sizes capped up front, and no
    path outside dest. Returns the bytes written."""
    members = [m for m in tf.getmembers() if m.isfile()]
    if len(members) > max_members:
        raise ArchiveTooLarge(f"{len(members)} files (limit {max_members})")
    total = sum(m.size for m in members)
    if total > max_bytes:
        raise ArchiveTooLarge(f"{total // (1024 * 1024)} MB (limit {max_bytes // (1024 * 1024)} MB)")
    for m in members:
        target = os.path.join(dest, m.name)
        if not _inside(dest, target):
            continue
        src = tf.extractfile(m)
        if src is None:
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)
    return total


def detect_real_file_type(path):
    """Reads a file's actual magic bytes, ignoring its extension."""
    try:
        with open(path, "rb") as f:
            header = f.read(265)
    except OSError:
        return None

    for sig, kind in ARCHIVE_SIGNATURES.items():
        if header.startswith(sig):
            return kind
    # POSIX tar has no magic at offset 0: "ustar" sits at offset 257.
    if header[257:262] == b"ustar":
        return "TAR archive"
    return None


PACKAGE_SCANNABLE_EXTENSIONS = (
    ".md", ".txt", ".yaml", ".yml", ".py", ".json", ".js", ".ts", ".sh",
    ".rs", ".go", ".rb", ".ps1", ".toml", ".cmd", ".bat", ".mdc",
    # Every other format an agent or a shell will happily run or read.
    # Files with no or an unknown extension are also scanned when their
    # content is text (see _sniff_text).
    ".mjs", ".cjs", ".jsx", ".tsx", ".bash", ".zsh", ".fish", ".ksh",
    ".pl", ".php", ".lua", ".psm1", ".psd1", ".vbs", ".vbe", ".wsf",
    ".html", ".htm", ".cfg", ".ini", ".env", ".rst", ".xml", ".r",
    ".swift", ".kt", ".java", ".cs", ".c", ".h", ".cpp", ".applescript",
)

# Shipped Python bytecode can behave differently from the .py next to it
# (or stand in for source that isn't there) - the PyCache Trap technique,
# arXiv:2610.10612. No skill needs to ship it; registries now reject it.
BYTECODE_EXTENSIONS = (".pyc", ".pyo", ".pyd")
PICKLE_EXTENSIONS = (".pkl", ".pickle", ".pt", ".pth", ".joblib")

# Formats Husk can't unpack: reported, never silently skipped.
UNINSPECTABLE_ARCHIVES = ("7-Zip archive", "RAR archive")

_SHEBANG_KINDS = (("python", ".py"), ("node", ".js"), ("deno", ".ts"), ("bash", ".sh"), ("zsh", ".sh"),
                  ("/sh", ".sh"), ("env sh", ".sh"), ("ruby", ".rb"), ("pwsh", ".ps1"), ("perl", ".pl"))


# Text by content, but base64 or key material by design - never instructions.
_NOT_INSTRUCTION_EXTS = (".sig", ".asc", ".gpg", ".minisig", ".p7s", ".sigstore",
                         ".crt", ".cer", ".pub", ".csr", ".lock", ".sum", ".map")


def _sniff_text(path):
    """For a file whose extension isn't a known text type: returns the
    extension to scan it as ("" for plain text, or one implied by a shebang),
    or None if the content is binary."""
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
    except OSError:
        return None
    if not head:
        return None
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return ""  # UTF-16 text; scan_skill_file decodes it
    if b"\x00" in head:
        return None
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(head) - 4:  # not just a multi-byte char cut off at the end
            return None
    if head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0].decode("utf-8", "replace").lower()
        for needle, kind in _SHEBANG_KINDS:
            if needle in first:
                return kind
    return ""


def _looks_like_pickle(path):
    try:
        with open(path, "rb") as f:
            head = f.read(2)
    except OSError:
        return False
    return len(head) == 2 and head[0] == 0x80 and 2 <= head[1] <= 5


def _scan_one(full_path, rel_path, name, depth, findings, _budget):
    """Scan one file of a package, appending to findings."""
    lower = name.lower()
    if lower.endswith(BYTECODE_EXTENSIONS) or "__pycache__" in rel_path.replace(os.sep, "/").split("/"):
        findings.append(
            f"'{rel_path}' is compiled Python bytecode shipped inside the skill - it can run "
            f"different code from the .py source a reviewer reads (the PyCache Trap technique). "
            f"Skills have no reason to ship bytecode."
        )
        return

    real_type = detect_real_file_type(full_path)
    if real_type:
        _scan_archive(full_path, rel_path, lower, real_type, depth, findings, _budget)
        return

    if lower.endswith(PICKLE_EXTENSIONS) or _looks_like_pickle(full_path):
        result = scan_pickle_file(full_path)
        if result["verdict"] == "FLAGGED":
            for f in result["findings"]:
                findings.append(f"'{rel_path}' (pickle): {f}")
        return

    if lower.endswith(".pdf"):
        # A bundled PDF can carry the skill's real (malicious)
        # instructions where a text-only scanner never looks. Extract
        # its text and run the full checks on it like any document.
        pdf_text, note = extract_pdf_text(full_path)
        if note and not note.startswith(("no extractable text", "pypdf not available")):
            findings.append(f"'{rel_path}' was not fully inspected: {note}.")
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
        return

    if lower.endswith(PACKAGE_SCANNABLE_EXTENSIONS):
        kind = None
    elif lower.endswith(_NOT_INSTRUCTION_EXTS):
        return
    else:
        kind = _sniff_text(full_path)
        if kind is None:
            return  # binary data with no known container format
    # A genuine text/code file - run it through the full
    # module 1 + 2 checks rather than a separate weaker pass.
    result = scan_skill_file(full_path, kind=kind)
    if result["verdict"] == "FLAGGED":
        for f in result["findings"]:
            findings.append(f"'{rel_path}': {f}")
    elif result["verdict"] == "ERROR":
        findings.append(f"'{rel_path}' could not be read: {result['findings'][0]}")


# Many legitimate formats ARE zip/gzip containers - Office documents,
# Java/Android bundles, ebooks, notebooks, packaged skills, fonts. Flagging
# these as "hidden payloads" was a major false-positive source on real repos
# (a skill shipping reference .docx files scored in the tens of thousands).
# Only a container masquerading as a plain text/code/data file is deceptive.
KNOWN_CONTAINER_EXTS = (
    ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
    ".odt", ".ods", ".odp", ".epub", ".jar", ".war", ".apk",
    ".aar", ".ipa", ".whl", ".egg", ".nupkg", ".vsix",
    ".ipynb", ".skill", ".crx", ".xpi", ".kmz", ".sketch",
    ".graffle", ".numbers", ".pages", ".key", ".woff", ".woff2",
)
ARCHIVE_NAME_EXTS = (".zip", ".gz", ".7z", ".rar", ".tar", ".tgz", ".tbz2", ".txz")


def _scan_archive(full_path, rel_path, lower, real_type, depth, findings, _budget):  # noqa: PLR0913, PLR0917 - internal helper of scan_package
    looks_like_archive_by_name = lower.endswith(ARCHIVE_NAME_EXTS)
    is_known_container = lower.endswith(KNOWN_CONTAINER_EXTS)
    # Flag when a container hides under any extension that isn't a known
    # archive name and isn't a known container format - that covers both
    # text/code disguises (.md, .py) and opaque ones (.dat, .bin, .cache).
    # An honestly named archive is purely procedural (recurse and scan) -
    # a legitimate bundled dependency .tar.gz must not count as a finding
    # just for existing.
    if not looks_like_archive_by_name and not is_known_container:
        findings.append(
            f"'{rel_path}' is actually a {real_type} despite its "
            f"name/extension suggesting otherwise - a text/code file "
            f"that is really an archive is a known technique for "
            f"hiding payloads from extension-based scanners."
        )

    if real_type in UNINSPECTABLE_ARCHIVES:
        findings.append(
            f"'{rel_path}' is a {real_type}, which Husk cannot unpack - its contents "
            f"were not inspected. Review it by hand before installing."
        )
        return

    try:
        with tempfile.TemporaryDirectory() as tmp:
            budget = min(MAX_ARCHIVE_EXPANDED_BYTES, _budget["bytes"])
            if real_type.startswith("ZIP"):
                with zipfile.ZipFile(full_path) as zf:
                    if any(i.flag_bits & 0x1 for i in zf.infolist()):
                        findings.append(
                            f"'{rel_path}' is a password-protected archive - its contents "
                            f"can't be inspected. Encrypted archives are a common way to "
                            f"smuggle droppers past scanners."
                        )
                        return
                    safe_extract_zip(zf, tmp, max_bytes=budget)
                    _budget["bytes"] -= sum(i.file_size for i in zf.infolist())
            elif real_type == "TAR archive" or _is_tar_gz(full_path):
                with tarfile.open(full_path, mode="r:*") as tf:
                    _budget["bytes"] -= safe_extract_tar(tf, tmp, max_bytes=budget)
            else:  # a single gzip-compressed file
                with gzip.open(full_path, "rb") as gz:
                    data = gz.read(budget + 1)
                if len(data) > budget:
                    raise ArchiveTooLarge(f"over {budget // (1024 * 1024)} MB")
                _budget["bytes"] -= len(data)
                inner = os.path.basename(lower[:-3] if lower.endswith(".gz") else lower) or "content"
                with open(os.path.join(tmp, inner), "wb") as out:
                    out.write(data)
            scan_package(tmp, depth=depth + 1, findings=findings, _budget=_budget)
    except ArchiveTooLarge as e:
        findings.append(f"'{rel_path}' is an archive that expands to {e} - "
                        "a zip-bomb pattern; its contents were not unpacked.")
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, zlib_error) as e:
        findings.append(f"'{rel_path}' claims to be a {real_type} but is malformed ({type(e).__name__}) - "
                        f"its contents were not inspected; treat as suspicious.")


def _is_tar_gz(path):
    """True if a gzip file holds a tar archive (checked without extracting)."""
    try:
        with gzip.open(path, "rb") as gz:
            head = gz.read(265)
    except (OSError, EOFError, zlib_error):
        return False
    return head[257:262] == b"ustar"


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
            try:
                _scan_one(full_path, rel_path, name, depth, findings, _budget)
            except Exception as exc:  # noqa: BLE001 - one hostile file must not abort the scan
                # Fail closed: a file that crashes the scanner is reported,
                # not skipped. A crafted archive used to raise out of
                # scan_package, and callers that catch errors then treated
                # the whole skill as "no opinion".
                findings.append(
                    f"'{rel_path}' could not be inspected ({type(exc).__name__}: {str(exc)[:120]}) - "
                    f"its contents were not scanned. Files built to crash scanners are a known evasion."
                )

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
