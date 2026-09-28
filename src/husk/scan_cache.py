"""
Content-addressed scan cache.

Husk's scan is deterministic: the same skill content always produces the same
findings. So a skill's result can be cached by its content digest (the same
SHA-256 `husk attest` computes) and never recomputed until the content
actually changes. This is what turns the lifecycle features from demos into
infrastructure:

  * `husk watch` re-checks installed skills on a schedule; with the cache,
    an unchanged skill costs a single hash instead of a full re-scan.
  * scanning a whole registry (thousands of skills) becomes incremental -
    only new or changed skills are scanned, so a nightly registry sweep is
    minutes of work, not hours.

The cache is a plain JSON file the user owns (default ~/.husk/scan-cache.json),
keyed by content digest, storing the findings and the ruleset digest that
produced them. If the ruleset changes (a Husk upgrade with new rules), the
ruleset digest changes and every entry is transparently recomputed - a stale
cache can never hide a finding a newer Husk would raise.
"""

import json
import os
import time

from .attestation import compute_ruleset_digest, compute_subject_digest
from .package_scanner import scan_package

DEFAULT_CACHE = os.path.join(os.path.expanduser("~"), ".husk", "scan-cache.json")
_CACHE_VERSION = 1


def load_cache(path=None):
    """Load the cache; returns a dict with 'ruleset' and 'entries'. A cache
    written by a different ruleset is discarded so results are never stale."""
    path = path or DEFAULT_CACHE
    current_ruleset = compute_ruleset_digest()
    empty = {"version": _CACHE_VERSION, "ruleset": current_ruleset, "entries": {}}
    if not os.path.isfile(path):
        return empty
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return empty
    if (not isinstance(data, dict)
            or data.get("version") != _CACHE_VERSION
            or data.get("ruleset") != current_ruleset):
        # ruleset changed (Husk upgraded) -> old results may be wrong, drop them
        return empty
    if not isinstance(data.get("entries"), dict):
        data["entries"] = {}
    return data


def save_cache(cache, path=None):
    """Write the cache atomically. Returns (ok, error)."""
    path = path or DEFAULT_CACHE
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, separators=(",", ":"))
        os.replace(tmp, path)
        return True, None
    except OSError as exc:
        return False, str(exc)


def scan_package_cached(package_path, cache=None, cache_path=None, save=True):
    """
    Scan a package, using the content-addressed cache. Returns
    (findings, hit) where `hit` is True if the result came from cache.

    A cache miss runs the full scan and records the result under the
    package's content digest. A hit returns the stored findings without
    touching the scanner. Either way the findings are exactly what a plain
    `scan_package` would return for that content.
    """
    own_cache = cache is None
    if own_cache:
        cache = load_cache(cache_path)

    digest, _ = compute_subject_digest(package_path)
    entry = cache["entries"].get(digest)
    if entry is not None:
        return list(entry["findings"]), True

    findings = scan_package(package_path)
    cache["entries"][digest] = {
        "findings": findings,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if own_cache and save:
        save_cache(cache, cache_path)
    return findings, False


def scan_many(package_paths, cache_path=None, progress=None):
    """
    Scan many packages incrementally against one shared cache, writing it
    once at the end. Returns a dict:
      {path: {"findings": [...], "cached": bool}}

    This is the registry-scale entry point: on a repeat sweep, only changed
    or new skills are actually scanned. `progress` is an optional callable
    (done, total, path, cached) for a progress bar.
    """
    cache = load_cache(cache_path)
    results = {}
    total = len(package_paths)
    for i, path in enumerate(package_paths, 1):
        if not os.path.isdir(path):
            continue
        findings, hit = scan_package_cached(path, cache=cache, save=False)
        results[path] = {"findings": findings, "cached": hit}
        if progress:
            progress(i, total, path, hit)
    save_cache(cache, cache_path)
    return results
