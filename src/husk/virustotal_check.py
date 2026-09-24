"""
Husk - optional VirusTotal malware-signature lookup.

WHY THIS EXISTS
----------------
Static analysis reads a skill's own text and code, it has no way to
recognize a known-malware BINARY sitting in the package by signature.
Found via testing against cisco-ai-defense/skill-scanner's real labeled
corpus: a fixture bundling the EICAR standard antivirus test file,
explicitly labeled malicious, that Husk's static checks correctly have
no way to catch (there's no dangerous code or language pattern in a
signature-based test file at all - it's not that kind of threat).

This module is a narrow, honest answer to exactly that gap: it hashes
each file in a package and checks the hash against VirusTotal's public
database. It does NOT read, understand, or judge a skill's actual
instructions - that's static analysis's job, and the LLM review layer's
job for the plain-language cases neither can catch. This is purely
"is this exact file a byte-for-byte match for something already known
to be malware."

THE TRADEOFF - STATED UP FRONT, NOT BURIED
--------------------------------------------
This is NOT run by default, and NOT required:
- Needs your own free VirusTotal API key (the public tier is free, no
  card required, rate-limited to 4 requests/minute and 500/day)
- Only the SHA-256 hash of each file is sent, never the file's actual
  content - VirusTotal's hash-lookup endpoint doesn't require an
  upload, so nothing about the skill's own text or logic ever leaves
  your machine through this module
- Depends on VirusTotal being available and free the way it is today

Same posture as the LLM review layer: opt-in, never silent, never a
hidden dependency. The static scanner remains Husk's free, local,
private default.
"""

import hashlib
import json
import os
import urllib.error
import urllib.request

VT_HASH_LOOKUP_URL = "https://www.virustotal.com/api/v3/files/{hash}"


def _sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_file_against_virustotal(path, api_key=None):
    """
    Hashes a single file and checks that hash against VirusTotal's
    public database. Returns a dict:
    {"available": bool, "malicious": bool|None, "positives": int|None,
     "total": int|None, "error": str|None}

    Never raises on a missing key, network failure, or a hash
    VirusTotal has never seen (a clean "not found" result, not an
    error) - this is a best-effort signature check, not a required
    step, and the caller should always be able to fall back to the
    static-only result.
    """
    api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {
            "available": False, "malicious": None, "positives": None,
            "total": None,
            "error": "VIRUSTOTAL_API_KEY not set - signature check "
                     "skipped. This is expected if you haven't opted "
                     "in; the static scan result above is unaffected.",
        }

    try:
        file_hash = _sha256_of_file(path)
        req = urllib.request.Request(  # noqa: S310 - fixed URL, not user input
            VT_HASH_LOOKUP_URL.format(hash=file_hash),
            headers={"x-apikey": api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - fixed URL, not user input
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # A clean, honest "VirusTotal has never seen this file"
                # result - not the same as "confirmed safe," just no
                # signature match, which is the expected, common case
                # for a skill's own original files.
                return {
                    "available": True, "malicious": False, "positives": 0,
                    "total": 0, "error": None,
                }
            raise

        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        return {
            "available": True,
            "malicious": positives > 0,
            "positives": positives,
            "total": total,
            "error": None,
        }

    except Exception as e:
        return {
            "available": False, "malicious": None, "positives": None,
            "total": None,
            "error": f"VirusTotal check failed ({type(e).__name__}: {e}). "
                     f"Static scan result above is unaffected.",
        }


def check_package_against_virustotal(root_path, api_key=None):
    """
    Runs check_file_against_virustotal across every file in a package
    directory. Returns a list of findings (empty if nothing flagged or
    the check wasn't available) plus the raw per-file results.
    """
    findings = []
    results = []
    for dirpath, _, filenames in os.walk(root_path):
        for name in filenames:
            full_path = os.path.join(dirpath, name)
            rel_path = os.path.relpath(full_path, root_path)
            result = check_file_against_virustotal(full_path, api_key=api_key)
            result["file"] = rel_path
            results.append(result)
            if result["available"] and result["malicious"]:
                findings.append(
                    f"'{rel_path}': VirusTotal flags this exact file as "
                    f"malicious ({result['positives']}/{result['total']} "
                    f"engines) - a known malware signature match, not a "
                    f"static-analysis judgment."
                )
    return findings, results
