"""
Tests for the optional LLM review layer. These use mocked API responses -
no real ANTHROPIC_API_KEY is needed or used in CI. They verify the code
path's structure (request building, response parsing, graceful failure)
is correct, NOT that the LLM's actual judgment is good - that would
require a real, paid, live evaluation, tracked separately (see
ROADMAP.md Tier 2).
"""

import json
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.llm_review import review_skill_with_llm  # noqa: E402


def test_skips_gracefully_with_no_api_key():
    result = review_skill_with_llm("some skill content", api_key=None)
    assert result["available"] is False
    assert result["verdict"] is None
    assert "not set" in result["error"]


def test_parses_a_real_shaped_api_response():
    fake_body = json.dumps({
        "content": [{"type": "text", "text": json.dumps({
            "verdict": "SUSPICIOUS",
            "confidence": "high",
            "reasoning": "Test reasoning.",
        })}]
    }).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_body

    with patch("urllib.request.urlopen", return_value=FakeResponse()):
        result = review_skill_with_llm("content", api_key="fake-key")

    assert result["available"] is True
    assert result["verdict"] == "SUSPICIOUS"
    assert result["confidence"] == "high"


def test_degrades_gracefully_on_api_failure():
    with patch("urllib.request.urlopen", side_effect=Exception("simulated failure")):
        result = review_skill_with_llm("content", api_key="fake-key")

    assert result["available"] is False
    assert "Static scan result above is unaffected" in result["error"]


def _fake_response(text):
    fake_body = json.dumps({"content": [{"type": "text", "text": text}]}).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_body

    return FakeResponse()


def test_recovers_json_from_surrounding_prose():
    """Real failure found via live testing (Tier 4.4): occasional stray
    text around an otherwise-valid JSON object despite instructions.
    The regex-based fallback extraction should recover this cleanly."""
    text = (
        'Here is my analysis:\n'
        '{"verdict": "SAFE", "confidence": "medium", "reasoning": "Looks fine."}\n'
        'Let me know if you need more detail.'
    )
    with patch("urllib.request.urlopen", return_value=_fake_response(text)):
        result = review_skill_with_llm("content", api_key="fake-key")

    assert result["available"] is True
    assert result["verdict"] == "SAFE"


def test_truncated_json_with_no_closing_brace_fails_honestly():
    """A response truncated mid-object (no closing '}' anywhere) is NOT
    recoverable by the fallback - must surface as a clear, honest
    error, never a wrong guess at the verdict."""
    text = '{"verdict": "SUSPICIOUS", "confidence": "high", "reasoning": "The scr'
    with patch("urllib.request.urlopen", return_value=_fake_response(text)):
        result = review_skill_with_llm("content", api_key="fake-key")

    assert result["available"] is False
    assert result["verdict"] is None


def test_empty_response_text_fails_with_a_clear_error():
    """A real failure found via live testing: an API response with no
    text-type content block at all. Must be a clear, specific error,
    not the confusing raw 'Expecting value: line 1 column 1' message."""
    with patch("urllib.request.urlopen", return_value=_fake_response("")):
        result = review_skill_with_llm("content", api_key="fake-key")

    assert result["available"] is False
    assert "no text content" in result["error"]
