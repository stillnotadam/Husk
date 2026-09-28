"""Tests for the Husk trust badge."""
import os
import subprocess
import sys
import xml.dom.minidom

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from husk.badge import badge_html, badge_markdown, badge_svg  # noqa: E402


def test_badge_svg_is_valid_xml_for_each_state():
    for verdict in ("pass", "warn", "fail", "unknown"):
        svg = badge_svg(verdict, False)
        xml.dom.minidom.parseString(svg)  # noqa: S318 - parsing our own generated SVG
        assert svg.startswith("<svg") and svg.endswith("</svg>")


def test_security_tool_badge_distinct():
    assert "security tool" in badge_svg("fail", True)
    assert "FAILED" not in badge_svg("fail", True)  # sec-tool overrides verdict label


def test_pass_badge_green_fail_red():
    assert "#3fb950" in badge_svg("pass", False)
    assert "#f85149" in badge_svg("fail", False)


def test_markdown_snippet_links_image_and_page():
    md = badge_markdown("owner/skill", "https://husk.zone")
    assert "/api/registry/badge?ref=owner/skill" in md
    assert "/registry?ref=owner/skill" in md
    assert md.startswith("[![")


def test_html_snippet_escaped():
    h = badge_html("owner/skill")
    assert "<a href=" in h and "<img" in h


def test_cli_badge():
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
    r = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "husk.cli", "badge", "me/mine", "--quiet"],
        capture_output=True, text=True, env=env, check=False)
    assert r.returncode == 0
    assert "me/mine" in r.stdout and r.stdout.strip().startswith("[![")
