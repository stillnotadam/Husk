"""
Husk badge - the trust primitive (Phase 3).

A registry people check is useful. A badge skills compete to *display* is a
standard - and owning the standard is what turns Husk from a tool into the
trust layer of a category. This module generates the badge.

Two things make a Husk badge meaningful rather than a sticker anyone can paste:

  1. It is LIVE. The badge image is served by the registry and reflects the
     skill's *current* verdict. A skill that passes today and ships a malicious
     update tomorrow has its badge flip to FAIL automatically - the author
     cannot freeze a green badge over rotten code.

  2. It is VERIFIABLE. The badge links to the skill's registry page, which
     carries the content digest and the full scan history. Anyone can confirm
     the badge describes the exact skill in front of them, not a different
     version.

`husk badge owner/name` prints the Markdown/HTML snippet an author drops in
their README. The image itself is produced by badge_svg() (served by the
registry backend at /api/registry/badge). Offline, deterministic, no tracking.
"""

import html

# Shields-style colors, kept in-house so the badge has no external dependency
# and cannot be spoofed by pointing at a third-party badge service.
_COLORS = {
    "pass": "#3fb950",
    "warn": "#d29922",
    "fail": "#f85149",
    "security-tool": "#6e7681",
    "unknown": "#8b95a3",
}
_LABELS = {
    "pass": "passing",
    "warn": "warnings",
    "fail": "FAILED",
    "security-tool": "security tool",
    "unknown": "not scanned",
}


def _text_width(s):
    """Rough width in the 11px verdana the shields format uses."""
    return int(len(s) * 6.5) + 10


def badge_svg(verdict, sec_tool=False):
    """Return an SVG string for a Husk badge. Self-contained, no external
    fetches, so it can be served straight from the registry."""
    state = "security-tool" if sec_tool else (verdict if verdict in _COLORS else "unknown")
    label = "husk"
    value = _LABELS[state]
    color = _COLORS[state]
    lw = _text_width(label)
    vw = _text_width(value)
    total = lw + vw
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{html.escape(label)}: {html.escape(value)}">'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<rect rx="3" width="{total}" height="20" fill="#555"/>'
        f'<rect rx="3" x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        f'<rect rx="3" width="{total}" height="20" fill="url(#s)"/>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw / 2}" y="14">{html.escape(label)}</text>'
        f'<text x="{lw + vw / 2}" y="14">{html.escape(value)}</text>'
        f'</g></svg>'
    )


def badge_markdown(ref, registry_base="https://husk.zone"):
    """The snippet an author pastes into their README. The image points at the
    LIVE badge endpoint (reflects the current verdict); the link points at the
    skill's registry page (the verifiable record)."""
    img = f"{registry_base}/api/registry/badge?ref={ref}"
    page = f"{registry_base}/registry?ref={ref}"
    return f"[![Husk security]({img})]({page})"


def badge_html(ref, registry_base="https://husk.zone"):
    img = f"{registry_base}/api/registry/badge?ref={ref}"
    page = f"{registry_base}/registry?ref={ref}"
    return (f'<a href="{html.escape(page)}"><img '
            f'src="{html.escape(img)}" alt="Husk security status"></a>')
