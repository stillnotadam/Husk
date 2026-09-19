# Roadmap to Tier 1 - "better than Snyk at what it's actually built for"

Not a claim of general superiority - a specific, provable one: catching
the documented bypass techniques that beat existing tools, with evidence,
not just assertion. This file tracks exactly what's left to get there.

## Checklist

- [ ] **Real-dataset validation** - test against actual confirmed-malicious
      skills from published research (not just self-built samples), if the
      dataset is publicly released
- [ ] **False-positive testing at scale** - run against hundreds of real,
      legitimate public skills; target near-zero false positive rate,
      published with real numbers
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
