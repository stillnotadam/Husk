"""
PDF text extraction.

Attackers hide a skill's real instructions in a bundled "reference document"
- a PDF the SKILL.md tells the agent to open and follow - precisely because a
scanner that only reads text and code files never sees them. This module
extracts the text from a PDF so Husk's full detection suite (including the
prose prompt-injection checks) runs on it like any other document.

It is deliberately defensive: a huge, encrypted, malformed, or image-only PDF
yields an empty (or truncated) result and a note, never a crash and never an
unbounded read. pypdf is a declared dependency; if it is somehow unavailable,
PDF extraction is skipped with a clear signal rather than failing the scan.
"""

import os

try:
    import pypdf
    _HAVE_PYPDF = True
except ImportError:  # pragma: no cover - pypdf is a declared dependency
    _HAVE_PYPDF = False

# Guard rails: a skill's reference PDF is small. Anything past these is either
# not a document worth scanning as prose or a resource-exhaustion attempt.
_MAX_PDF_BYTES = 25 * 1024 * 1024      # 25 MB file cap
_MAX_PAGES = 300                       # stop after this many pages
_MAX_TEXT_CHARS = 2 * 1024 * 1024      # 2 MB of extracted text cap


def extract_pdf_text(path):
    """
    Extract text from a PDF. Returns (text, note):
      * text: the extracted text (possibly ""), capped at _MAX_TEXT_CHARS.
      * note: None on a clean full extraction, or a short human-readable
        reason it was partial/empty (encrypted, too large, image-only,
        malformed, pypdf missing). Never raises.
    """
    if not _HAVE_PYPDF:
        return "", "pypdf not available - PDF not scanned"
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return "", f"could not stat PDF ({exc})"
    if size > _MAX_PDF_BYTES:
        return "", f"PDF is {size // (1024 * 1024)}MB, over the {_MAX_PDF_BYTES // (1024 * 1024)}MB scan cap"

    try:
        reader = pypdf.PdfReader(path)
    except Exception as exc:  # noqa: BLE001 - any parse failure is reported, not raised
        return "", f"could not open PDF ({type(exc).__name__})"

    if getattr(reader, "is_encrypted", False):
        # try the common empty-password case, then give up cleanly
        try:
            if reader.decrypt("") == 0:
                return "", "PDF is encrypted - text not extracted"
        except Exception:  # noqa: BLE001
            return "", "PDF is encrypted - text not extracted"

    parts = []
    total = 0
    pages = reader.pages
    for i, page in enumerate(pages):
        if i >= _MAX_PAGES:
            parts.append(f"\n[... truncated at {_MAX_PAGES} pages ...]")
            break
        try:
            txt = page.extract_text() or ""
        except Exception:  # noqa: BLE001,S112 - a bad page doesn't sink the rest
            continue
        parts.append(txt)
        total += len(txt)
        if total > _MAX_TEXT_CHARS:
            parts.append("\n[... truncated ...]")
            break

    text = "\n".join(parts)
    if not text.strip():
        return "", "no extractable text (image-only or empty PDF)"
    return text[:_MAX_TEXT_CHARS], None
