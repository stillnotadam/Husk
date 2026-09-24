"""
Tests for the optional VirusTotal signature-check layer. These use
mocked API responses - no real VIRUSTOTAL_API_KEY is needed or used in
CI. They verify the code path's structure (hashing, request building,
response parsing, graceful failure) is correct, NOT that VirusTotal's
actual database coverage is good - that would require a real, live
lookup.
"""

import hashlib
import json
import os
import sys
import urllib.error
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.virustotal_check import (  # noqa: E402
    _sha256_of_file,
    check_file_against_virustotal,
    check_package_against_virustotal,
)


def test_sha256_matches_python_hashlib_directly(tmp_path):
    content = b"arbitrary test content for hashing"
    f = tmp_path / "sample.txt"
    f.write_bytes(content)
    assert _sha256_of_file(str(f)) == hashlib.sha256(content).hexdigest()


def test_skips_gracefully_with_no_api_key(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("hello")
    result = check_file_against_virustotal(str(f), api_key=None)
    assert result["available"] is False
    assert "VIRUSTOTAL_API_KEY" in result["error"]


def _fake_vt_response(malicious_count, total):
    fake_body = json.dumps({
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious_count,
                    "suspicious": 0,
                    "harmless": total - malicious_count,
                    "undetected": 0,
                }
            }
        }
    }).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_body

    return FakeResponse()


def test_flags_a_real_shaped_malicious_response(tmp_path):
    f = tmp_path / "sample.exe"
    f.write_bytes(b"fake binary content")
    with patch("urllib.request.urlopen", return_value=_fake_vt_response(45, 70)):
        result = check_file_against_virustotal(str(f), api_key="fake-key")
    assert result["available"] is True
    assert result["malicious"] is True
    assert result["positives"] == 45


def test_clean_response_is_not_flagged(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"ordinary content")
    with patch("urllib.request.urlopen", return_value=_fake_vt_response(0, 70)):
        result = check_file_against_virustotal(str(f), api_key="fake-key")
    assert result["available"] is True
    assert result["malicious"] is False


def test_404_hash_not_found_is_a_clean_result_not_an_error(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"a file VirusTotal has never seen")
    with patch(
        "urllib.request.urlopen",
        side_effect=urllib.error.HTTPError("url", 404, "Not Found", {}, None),
    ):
        result = check_file_against_virustotal(str(f), api_key="fake-key")
    assert result["available"] is True
    assert result["malicious"] is False
    assert result["error"] is None


def test_degrades_gracefully_on_api_failure(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"content")
    with patch("urllib.request.urlopen", side_effect=Exception("network down")):
        result = check_file_against_virustotal(str(f), api_key="fake-key")
    assert result["available"] is False
    assert "Static scan result above is unaffected" in result["error"]


def test_package_check_aggregates_findings_across_files(tmp_path):
    (tmp_path / "clean.txt").write_bytes(b"clean content")
    (tmp_path / "bad.exe").write_bytes(b"malicious-shaped content")

    def side_effect(req, timeout=15):
        # Distinguish by content hash via the request URL itself
        if req.full_url.endswith(_sha256_of_file(str(tmp_path / "bad.exe"))):
            return _fake_vt_response(12, 70)
        return _fake_vt_response(0, 70)

    with patch("urllib.request.urlopen", side_effect=side_effect):
        findings, results = check_package_against_virustotal(str(tmp_path), api_key="fake-key")

    assert len(findings) == 1
    assert "bad.exe" in findings[0]
    assert len(results) == 2
