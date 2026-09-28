"""
Repository context classification for triage.

A hard lesson from this project's own benchmark: a genuine security tool and a
piece of malware disguised AS a security tool are nearly indistinguishable by
self-description (38 of 500 malicious samples self-identify as security tools).
So Husk NEVER auto-suppresses findings just because a repo looks like a
scanner - that is exactly how disguised malware would slip through.

What is safe, and useful, is to LABEL a repo's likely context so a human
triaging a large scan can sort candidates into buckets:

  * a repo that self-identifies as a security/scanning/pentest tool is a
    likely-false-positive bucket (its attack strings are probably data), but
    still shown, still flagged - a reviewer looks at these SECOND.
  * a repo that does NOT claim to be a security tool but is still flagged is
    the bucket where real malware hides - a reviewer looks at these FIRST.

This never changes a verdict or hides a finding. It only adds a context tag.
"""

import os
import re

_SECURITY_TOOL = re.compile(
    r"(?i)\b("
    r"security scanner|vulnerability scanner|malware (?:scanner|detect|analy)|"
    r"threat (?:detect|scan|hunt)|penetration test|pentest|security audit(?:or)?|"
    r"detect(?:s|ing)? (?:malicious|attacks?|threats?|vulnerabilit|injection)|"
    r"scans? (?:for )?(?:malicious|vulnerabilit|threats?|secrets?|injection)|"
    r"security (?:review|analysis|assessment|hardening)|red[- ]?team|"
    r"exploit (?:development|framework)|SAST|DAST|static analysis|"
    r"this (?:skill|tool|repo) (?:detects|scans|identifies|flags|analyzes|audits)|"
    r"CTF|capture the flag|honeypot|deception|forensic"
    r")\b"
)

_DOC_FILES = ("skill.md", "readme.md", "readme", "description.md")


def classify_repo_context(package_path):
    """Return a dict of context tags for triage. Reads only doc files, cheaply.

    {
      "self_identifies_security_tool": bool,   # claims to be a scanner/pentest/etc
      "triage_bucket": "likely-false-positive" | "review-first",
    }
    """
    is_sec_tool = False
    for dirpath, _dirs, filenames in os.walk(package_path):
        depth = dirpath[len(package_path):].count(os.sep)
        if depth > 3:
            continue
        for name in filenames:
            low = name.lower()
            if low in _DOC_FILES or (low.endswith(".md") and depth <= 1):
                try:
                    with open(os.path.join(dirpath, name), encoding="utf-8", errors="replace") as fh:
                        text = fh.read(6000)
                except OSError:
                    continue
                if _SECURITY_TOOL.search(text):
                    is_sec_tool = True
                    break
        if is_sec_tool:
            break

    return {
        "self_identifies_security_tool": is_sec_tool,
        # a flagged repo that does NOT claim to be a security tool is where
        # real malware hides - review those first.
        "triage_bucket": "likely-false-positive" if is_sec_tool else "review-first",
    }
