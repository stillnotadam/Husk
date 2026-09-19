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
