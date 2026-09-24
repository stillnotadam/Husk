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
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.llm_review import (  # noqa: E402
    review_package_with_llm,
    review_skill_with_llm,
    review_with_consensus,
)


def test_skips_gracefully_with_no_api_key():
    result = review_skill_with_llm("some skill content", api_key=None, use_cache=False)
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
        result = review_skill_with_llm("content", api_key="fake-key", use_cache=False)

    assert result["available"] is True
    assert result["verdict"] == "SUSPICIOUS"
    assert result["confidence"] == "high"


def test_degrades_gracefully_on_api_failure():
    with patch("urllib.request.urlopen", side_effect=Exception("simulated failure")):
        result = review_skill_with_llm("content", api_key="fake-key", use_cache=False)

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
        result = review_skill_with_llm("content", api_key="fake-key", use_cache=False)

    assert result["available"] is True
    assert result["verdict"] == "SAFE"


def test_truncated_json_with_no_closing_brace_fails_honestly():
    """A response truncated mid-object (no closing '}' anywhere) is NOT
    recoverable by the fallback - must surface as a clear, honest
    error, never a wrong guess at the verdict."""
    text = '{"verdict": "SUSPICIOUS", "confidence": "high", "reasoning": "The scr'
    with patch("urllib.request.urlopen", return_value=_fake_response(text)):
        result = review_skill_with_llm("content", api_key="fake-key", use_cache=False)

    assert result["available"] is False
    assert result["verdict"] is None


def test_empty_response_text_fails_with_a_clear_error():
    """A real failure found via live testing: an API response with no
    text-type content block at all. Must be a clear, specific error,
    not the confusing raw 'Expecting value: line 1 column 1' message."""
    with patch("urllib.request.urlopen", return_value=_fake_response("")):
        result = review_skill_with_llm("content", api_key="fake-key", use_cache=False)

    assert result["available"] is False
    assert "no text content" in result["error"]


def _fake_openai_compatible_response(text):
    """Response shape for Gemini/DeepSeek/Grok/Kimi - all four confirmed
    to use the standard OpenAI chat completions format, distinct from
    Anthropic's own content-blocks format above."""
    fake_body = json.dumps({
        "choices": [{"message": {"content": text}}]
    }).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_body

    return FakeResponse()


def test_openai_compatible_provider_parses_a_real_shaped_response():
    """Covers the shared code path used by gemini/deepseek/grok/kimi -
    verified via each provider's own docs to use this exact response
    shape, distinct from Anthropic's native format tested above."""
    text = json.dumps({
        "verdict": "SUSPICIOUS", "confidence": "high", "reasoning": "Test reasoning.",
    })
    with patch("urllib.request.urlopen", return_value=_fake_openai_compatible_response(text)):
        result = review_skill_with_llm("content", api_key="fake-key", provider="deepseek", use_cache=False)

    assert result["available"] is True
    assert result["verdict"] == "SUSPICIOUS"
    assert result["confidence"] == "high"


def test_each_openai_compatible_provider_uses_its_own_env_var():
    """gemini/deepseek/grok/kimi each look for their own environment
    variable when no key is passed explicitly, same pattern as
    ANTHROPIC_API_KEY - never falls back to a different provider's key."""
    expected_env_vars = {
        "gemini": "GEMINI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
        "grok": "XAI_API_KEY", "kimi": "MOONSHOT_API_KEY",
    }
    for provider, env_var in expected_env_vars.items():
        result = review_skill_with_llm("content", api_key=None, provider=provider, use_cache=False)
        assert result["available"] is False
        assert env_var in result["error"]


def test_unknown_provider_fails_with_a_clear_error_not_a_crash():
    result = review_skill_with_llm("content", api_key="fake-key", provider="not-a-real-provider", use_cache=False)
    assert result["available"] is False
    assert "Unknown provider" in result["error"]


def test_openai_compatible_provider_degrades_gracefully_on_api_failure():
    with patch("urllib.request.urlopen", side_effect=Exception("simulated failure")):
        result = review_skill_with_llm("content", api_key="fake-key", provider="grok", use_cache=False)

    assert result["available"] is False
    assert "Static scan result above is unaffected" in result["error"]


# ---------------------------------------------------------------------
# Package-level review
# ---------------------------------------------------------------------

def _fake_verdict_response(verdict="SAFE", confidence="high", reasoning="ok"):
    fake_body = json.dumps({
        "content": [{"type": "text", "text": json.dumps({
            "verdict": verdict, "confidence": confidence, "reasoning": reasoning,
        })}]
    }).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_body

    return FakeResponse()


def _fake_openai_verdict_response(verdict="SAFE", confidence="high", reasoning="ok"):
    """Same idea as _fake_verdict_response, but shaped the way the
    OpenAI-compatible providers (grok/gemini/deepseek/kimi) actually
    respond - genuinely different from Anthropic's own response shape,
    real bug found via testing: a consensus test using the same single
    mocked response for both an anthropic and a grok call worked for
    anthropic and silently failed for grok with a KeyError, since
    Anthropic's {"content": [...]} shape isn't what
    _review_with_openai_compatible reads from at all."""
    fake_body = json.dumps({
        "choices": [{"message": {"content": json.dumps({
            "verdict": verdict, "confidence": confidence, "reasoning": reasoning,
        })}}]
    }).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_body

    return FakeResponse()


def _mock_urlopen_by_provider(responses_by_provider):
    """A side_effect function for patch("urllib.request.urlopen", ...)
    that inspects the request URL to decide which provider's fake
    response to return - needed because a consensus call genuinely
    hits different providers' different URLs in one test, and each
    needs its own correctly-shaped response, not one mock reused for
    both regardless of shape."""
    def _side_effect(req, timeout=30):
        url = req.full_url
        if "anthropic.com" in url:
            return responses_by_provider["anthropic"]
        if "x.ai" in url:
            return responses_by_provider["grok"]
        raise ValueError(f"no fake response configured for URL: {url}")
    return _side_effect


def test_package_review_covers_every_scannable_file(tmp_path):
    (tmp_path / "SKILL.md").write_text("main content")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "helper.py").write_text("helper content")
    (tmp_path / "notes.txt").write_text("plain text")
    (tmp_path / "image.png").write_bytes(b"\x89PNG")  # not scannable, must be skipped

    with patch("urllib.request.urlopen", return_value=_fake_verdict_response()):
        result = review_package_with_llm(str(tmp_path), api_key="fake-key", use_cache=False)

    assert result["files_reviewed"] == 3  # SKILL.md, helper.py, notes.txt - not image.png
    assert set(result["per_file"].keys()) == {"SKILL.md", os.path.join("scripts", "helper.py"), "notes.txt"}


def test_package_review_verdict_is_suspicious_if_any_file_is(tmp_path):
    (tmp_path / "clean.md").write_text("harmless")
    (tmp_path / "bad.md").write_text("suspicious content")

    responses = [_fake_verdict_response("SAFE"), _fake_verdict_response("SUSPICIOUS")]

    with patch("urllib.request.urlopen", side_effect=responses):
        result = review_package_with_llm(str(tmp_path), api_key="fake-key", use_cache=False)

    assert result["verdict"] == "SUSPICIOUS"


def test_package_review_all_safe_gives_safe_verdict(tmp_path):
    (tmp_path / "a.md").write_text("harmless one")
    (tmp_path / "b.md").write_text("harmless two")

    with patch("urllib.request.urlopen", return_value=_fake_verdict_response("SAFE")):
        result = review_package_with_llm(str(tmp_path), api_key="fake-key", use_cache=False)

    assert result["verdict"] == "SAFE"
    assert result["available"] is True


def test_package_review_with_no_key_reports_unavailable_not_crash(tmp_path):
    (tmp_path / "a.md").write_text("content")

    result = review_package_with_llm(str(tmp_path), api_key=None, use_cache=False)

    assert result["available"] is False
    assert result["files_skipped"] == 1


# ---------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------

def test_successful_review_is_cached_and_reused(tmp_path):
    cache_file = str(tmp_path / "cache.json")
    with patch("urllib.request.urlopen", return_value=_fake_verdict_response("SUSPICIOUS")) as mock_urlopen:
        r1 = review_skill_with_llm("some content", api_key="fake-key", use_cache=True, cache_path=cache_file)
        assert mock_urlopen.call_count == 1
        assert r1["cached"] is False

        r2 = review_skill_with_llm("some content", api_key="fake-key", use_cache=True, cache_path=cache_file)
        assert mock_urlopen.call_count == 1  # not called again - served from cache
        assert r2["cached"] is True
        assert r2["verdict"] == "SUSPICIOUS"


def test_different_content_is_not_served_from_the_same_cache_entry(tmp_path):
    cache_file = str(tmp_path / "cache.json")
    with patch("urllib.request.urlopen", return_value=_fake_verdict_response("SAFE")) as mock_urlopen:
        review_skill_with_llm("content A", api_key="fake-key", use_cache=True, cache_path=cache_file)
        review_skill_with_llm("content B", api_key="fake-key", use_cache=True, cache_path=cache_file)
        assert mock_urlopen.call_count == 2


def test_failed_review_is_never_cached(tmp_path):
    cache_file = str(tmp_path / "cache.json")
    with patch("urllib.request.urlopen", side_effect=Exception("boom")) as mock_urlopen:
        review_skill_with_llm("content", api_key="fake-key", use_cache=True, cache_path=cache_file)
        review_skill_with_llm("content", api_key="fake-key", use_cache=True, cache_path=cache_file)
        assert mock_urlopen.call_count == 2  # retried both times, never "remembered" as a skip


def test_use_cache_false_never_touches_the_cache_file(tmp_path):
    cache_file = str(tmp_path / "cache.json")
    with patch("urllib.request.urlopen", return_value=_fake_verdict_response("SAFE")):
        review_skill_with_llm("content", api_key="fake-key", use_cache=False, cache_path=cache_file)
    assert not os.path.exists(cache_file)


# ---------------------------------------------------------------------
# Retry with backoff
# ---------------------------------------------------------------------

def test_retries_on_429_and_succeeds_on_second_attempt():
    call_count = {"n": 0}

    def side_effect(req, timeout=30):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise urllib.error.HTTPError("url", 429, "Too Many Requests", {}, None)
        return _fake_verdict_response("SAFE")

    with patch("urllib.request.urlopen", side_effect=side_effect), patch("time.sleep"):
        result = review_skill_with_llm("content", api_key="fake-key", use_cache=False)

    assert call_count["n"] == 2
    assert result["available"] is True


def test_does_not_retry_on_401_unauthorized():
    call_count = {"n": 0}

    def side_effect(req, timeout=30):
        call_count["n"] += 1
        raise urllib.error.HTTPError("url", 401, "Unauthorized", {}, None)

    with patch("urllib.request.urlopen", side_effect=side_effect), patch("time.sleep"):
        result = review_skill_with_llm("content", api_key="fake-key", use_cache=False)

    assert call_count["n"] == 1  # no retry - a bad key won't fix itself on attempt 2
    assert result["available"] is False


def test_gives_up_after_max_retries_and_degrades_gracefully():
    def side_effect(req, timeout=30):
        raise urllib.error.HTTPError("url", 503, "Service Unavailable", {}, None)

    with patch("urllib.request.urlopen", side_effect=side_effect), patch("time.sleep"):
        result = review_skill_with_llm("content", api_key="fake-key", use_cache=False)

    assert result["available"] is False
    assert "Static scan result above is unaffected" in result["error"]


# ---------------------------------------------------------------------
# Multi-provider consensus
# ---------------------------------------------------------------------

def test_consensus_unanimous_when_all_providers_agree():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k1", "XAI_API_KEY": "k2"}):
        mock_fn = _mock_urlopen_by_provider({
            "anthropic": _fake_verdict_response("SUSPICIOUS"),
            "grok": _fake_openai_verdict_response("SUSPICIOUS"),
        })
        with patch("urllib.request.urlopen", side_effect=mock_fn):
            result = review_with_consensus("content", providers=["anthropic", "grok"], use_cache=False)

    assert result["verdict"] == "SUSPICIOUS"
    assert result["agreement"] == "unanimous"
    assert result["votes"] == {"SAFE": 0, "SUSPICIOUS": 2}


def test_consensus_reports_split_when_providers_disagree():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k1", "XAI_API_KEY": "k2"}):
        mock_fn = _mock_urlopen_by_provider({
            "anthropic": _fake_verdict_response("SAFE"),
            "grok": _fake_openai_verdict_response("SUSPICIOUS"),
        })
        with patch("urllib.request.urlopen", side_effect=mock_fn):
            result = review_with_consensus("content", providers=["anthropic", "grok"], use_cache=False)

    assert result["verdict"] == "SUSPICIOUS"  # any SUSPICIOUS vote wins, doesn't get averaged away
    assert result["agreement"] == "split"
    assert result["votes"] == {"SAFE": 1, "SUSPICIOUS": 1}


def test_consensus_defaults_to_only_providers_with_a_key_present():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k1"}, clear=True), \
         patch("urllib.request.urlopen", return_value=_fake_verdict_response("SAFE")):
        result = review_with_consensus("content", use_cache=False)

    assert result["providers_queried"] == ["anthropic"]


def test_consensus_with_no_keys_at_all_is_unavailable():
    with patch.dict(os.environ, {}, clear=True):
        result = review_with_consensus("content", use_cache=False)

    assert result["available"] is False
    assert result["providers_queried"] == []

