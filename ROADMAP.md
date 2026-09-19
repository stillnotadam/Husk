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
- [ ] **False-positive testing at scale** - validated against 16 real skill
      packages (Snyk's own open-source test fixtures: canvas-design,
      slack-gif-creator, mcp-builder, skill-creator, webapp-testing,
      docx, xlsx, pptx, pdf, and others, plus their own malicious-skill
      fixture). Found and fixed two real precision bugs: (1) flagging
      any subprocess call instead of only shell=True, which broke on
      legitimate docx/xlsx/pptx skills that shell out normally - fixed
      to match bandit's own B602 scope; (2) URL paths matching the
      base64 character class by coincidence - fixed by excluding
      matches inside URLs. Result: 14/16 clean, 1 correctly-caught
      known-malicious fixture, 1 legitimate true-positive on shell=True
      (an objectively elevated-risk pattern, same as bandit would flag,
      used safely here - expected scanner behavior, not a bug). Still
      want a larger sample (hundreds) before calling this item done.
- [ ] **CI pipeline** - GitHub Actions running the full test suite on every
      commit/PR, with a status badge in the README
- [ ] **Packaging** - `pip install`-able, proper CLI with `--help`, no
      manual script-running required
- [ ] **Head-to-head benchmark vs. Snyk's agent-scan** - same test set, both
      tools, published results table with real numbers, not a claim

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
