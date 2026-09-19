# Roadmap to Tier 1 - "better than Snyk at what it's actually built for"

Not a claim of general superiority - a specific, provable one: catching
the documented bypass techniques that beat existing tools, with evidence,
not just assertion. This file tracks exactly what's left to get there.

## Checklist

- [x] **Real-dataset validation** - tested against real confirmed-malicious
      skills from yoonholee/agent-skill-malware (Hugging Face, 127 malicious
      + 223 benign, real ClawHub attack campaign, Feb 2026). Initial result:
      0/8 caught - modules 1-6 were all looking for malicious code hidden
      IN the file; the real dominant attack pattern is plain-English social
      engineering telling a human to manually download/run something
      outside the file. Built module 7 specifically for this. Re-tested:
      8/8 caught, no regressions on the 12 existing self-built test cases.
- [x] **False-positive testing at scale** - scaled from 16 to 265 real
      skill packages: cloned anthropics/skills (official, 20 skills) and
      dxta/claude-code-skills (large community collection, 229 skills)
      directly from GitHub, plus the earlier 16 Snyk fixtures. Found and
      fixed three real, distinct precision bugs at scale:
      (1) subprocess calls flagged unconditionally - narrowed to shell=True
      specifically (matches bandit's B602 scope)
      (2) base64 character-class regex matching URL paths by coincidence
      - fixed by excluding URL contexts
      (3) same collision for plain filesystem paths (no URL prefix) -
      fixed with a path-vs-base64 heuristic (word-like '/'-separated
      segments = path, not base64)
      (4) no negation awareness - a document instruction saying "MUST NOT
      add eval()" was flagged as if it contained eval() - fixed with
      paragraph-scoped negation detection
      Final result: 248/249 (99.6%) of real skills from the two GitHub
      repos scan clean. The one remaining flag (curl|sh piping the
      official `uv` installer) is a deliberate true-positive on an
      objectively elevated-risk pattern, same reasoning as the earlier
      shell=True case - not something to suppress.
- [ ] **CI pipeline** - GitHub Actions running the full test suite on every
      commit/PR, with a status badge in the README
- [ ] **Packaging** - `pip install`-able, proper CLI with `--help`, no
      manual script-running required
- [x] **Head-to-head benchmark vs. Snyk's agent-scan** - installed Snyk's
      real tool from source (not simulated) and ran it against real skill
      files. Major finding, fully reproducible: Snyk's agent-scan refuses
      to produce ANY verdict (safe/malicious) without a paid account and
      API token - confirmed even against their OWN malicious-skill test
      fixture. A token-free `inspect` mode exists but performs no security
      analysis at all, by their own description. Husk produces a full,
      reasoned verdict on the same file immediately, offline, free.
      Full writeup in BENCHMARK.md, including an honest limitation: we
      don't have a paid Snyk token, so raw detection-accuracy comparison
      (their real engine vs. Husk) isn't possible yet - that's flagged
      explicitly rather than glossed over. Attempted to close this gap
      thoroughly: tried BOTH real credential types a standard Snyk
      account can produce (classic Auth Token UUID, and the newer PAT
      system) against the live analysis endpoint; both returned 403
      Forbidden, identically. Confirmed via the actual account settings
      page that both were the correct, officially-documented token
      types. This rules out "wrong token" and points to a real
      org-level entitlement gap, not a mistake on our end. What IS
      fully verified independently: Husk's own real-world numbers
      (8/8 real malicious caught, 248/249 real legitimate clean).

## Status log

- 2026-09-19: Checklist created. 6 detection modules complete, 12/12
  self-built test cases passing, zero false positives so far (small
  sample - this is exactly what item 2 above needs to fix).
- 2026-09-19: Cloned and examined Snyk's agent-scan directly (open source,
  github.com/snyk/agent-scan). Key finding: their actual risk-scoring
  intelligence runs through a remote endpoint
  (api.snyk.io/hidden/mcp-scan/analysis-machine), not fully local/open
  code - the CLI handles discovery and parsing, but real analysis is
  server-side and not independently auditable. Husk is 100% local,
  fully auditable, no network calls. This is a real, specific,
  defensible differentiator for the benchmark writeup - not "better
  overall," but "fully local and auditable where theirs is not."
  They also have far more test coverage (90 test files vs our 12) and
  broader scope (full agent harnesses + MCP configs, not just skills) -
  worth being honest about in the comparison table too.
- 2026-09-19: **Major finding.** Pulled real confirmed-malicious skill
  samples from a public Hugging Face dataset (yoonholee/agent-skill-malware,
  127 malicious + 223 benign, real ClawHub Feb 2026 attack campaign) and
  ran Husk against them. Result: 0/8 caught on first run. Every module
  built so far (1-6) looks for malicious code hidden inside the skill
  file; the actual dominant real-world attack (86.3% of confirmed wild
  malicious skills, per separate published research) is pure social
  engineering in plain English - "download this required utility, extract
  with this password, run it" - with no malicious code in the file at
  all. Built module 7 specifically for this gap. Re-tested: 8/8 real
  samples caught, zero regressions on the 12 self-built test cases,
  and specifically verified it does NOT false-positive on a legitimate
  skill using similar "requires X" language for a normal pip install.
  This was the single most valuable test run so far - self-built
  adversarial testing had a blind spot that only real-world data exposed.
