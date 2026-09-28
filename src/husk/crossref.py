"""
Cross-marketplace verification: Husk as the neutral layer above any single
registry.

A marketplace can only see itself. It cannot tell you that the skill named
`owner/foo` on its registry has *different content* than the `owner/foo`
published on another registry - but that divergence is exactly a supply-chain
substitution attack: a skill that is benign on the registry a reviewer checked
and malicious on the one a victim installs from. Husk sits above the
marketplaces, so it can fetch the same reference from each, hash the content,
scan it, and report:

  * whether the marketplaces serve byte-identical content (same digest), and
  * whether Husk's verdict is the same everywhere, or a registry is serving a
    version that fails where another passes.

This is a capability no single marketplace can offer (they only see
themselves) and no AI review can offer (it isn't deterministic or
content-bound). It reuses the same canonical content digest as `husk attest`,
so a cross-marketplace result and an attestation speak about the exact same
artifact identity.
"""

import os
import tempfile

from .aggregator import MARKETPLACE_RESOLVERS
from .attestation import compute_subject_digest
from .package_scanner import scan_package


def _resolve_one(marketplace, skill_ref, workdir):
    """Resolve a skill's content from one marketplace into workdir. Returns
    (path_or_None, error_or_None). Never raises: a resolver may return a bare
    path, a (path, error) tuple, or None."""
    resolver = MARKETPLACE_RESOLVERS.get(marketplace)
    if resolver is None:
        return None, f"unknown marketplace '{marketplace}'"
    try:
        out = resolver(skill_ref, workdir)
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        return None, f"{type(exc).__name__}: {exc}"
    if isinstance(out, tuple):
        return out
    return out, (None if out else "resolver returned no content")


def crossref_skill(skill_ref, marketplaces=None):
    """
    Fetch `skill_ref` from each marketplace, digest and scan each, and compare.

    Returns a dict:
      {
        "skill": skill_ref,
        "marketplaces": {
            "<name>": {
                "available": bool,
                "error": str | None,
                "content_digest": str | None,   # sha256 of canonical content
                "verdict": "SAFE"|"FLAGGED" | None,
                "finding_count": int,
            }, ...
        },
        "content_agreement": "identical" | "divergent" | "single" | "none",
        "verdict_agreement": "agree" | "disagree" | "single" | "none",
        "alerts": [ ... human-readable, the security-relevant conclusions ],
      }

    The two agreement fields and the alerts are the point: they surface a
    registry serving different or more-dangerous content under the same name.
    """
    marketplaces = marketplaces or list(MARKETPLACE_RESOLVERS.keys())
    per = {}
    for name in marketplaces:
        with tempfile.TemporaryDirectory(prefix=f"husk_xref_{name}_") as wd:
            path, error = _resolve_one(name, skill_ref, wd)
            if not path or not os.path.exists(path):
                per[name] = {"available": False, "error": error or "unavailable",
                             "content_digest": None, "verdict": None, "finding_count": 0}
                continue
            digest, _ = compute_subject_digest(path)
            findings = scan_package(path)
            per[name] = {
                "available": True,
                "error": None,
                "content_digest": digest,
                "verdict": "FLAGGED" if findings else "SAFE",
                "finding_count": len(findings),
            }

    available = {n: r for n, r in per.items() if r["available"]}
    digests = {r["content_digest"] for r in available.values()}
    verdicts = {r["verdict"] for r in available.values()}

    if len(available) == 0:
        content_agreement = verdict_agreement = "none"
    elif len(available) == 1:
        content_agreement = verdict_agreement = "single"
    else:
        content_agreement = "identical" if len(digests) == 1 else "divergent"
        verdict_agreement = "agree" if len(verdicts) == 1 else "disagree"

    alerts = []
    if content_agreement == "divergent":
        alerts.append(
            "SUPPLY-CHAIN ALERT: the same skill reference serves DIFFERENT content "
            "on different marketplaces. A reviewer checking one registry is not "
            "seeing what a user installs from another. Digests: "
            + ", ".join(f"{n}={r['content_digest'][:12]}" for n, r in available.items())
        )
    if verdict_agreement == "disagree":
        flagged = [n for n, r in available.items() if r["verdict"] == "FLAGGED"]
        safe = [n for n, r in available.items() if r["verdict"] == "SAFE"]
        alerts.append(
            f"VERDICT DIVERGENCE: Husk FLAGS the copy on {', '.join(flagged)} but "
            f"clears the copy on {', '.join(safe)} - install only from a registry "
            f"whose copy passes."
        )
    if content_agreement == "identical" and len(available) > 1:
        alerts.append(
            "All marketplaces serve byte-identical content for this skill "
            f"(sha256 {next(iter(digests))[:16]}...); no substitution across registries."
        )

    return {
        "skill": skill_ref,
        "marketplaces": per,
        "content_agreement": content_agreement,
        "verdict_agreement": verdict_agreement,
        "alerts": alerts,
    }
