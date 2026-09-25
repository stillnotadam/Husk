# Changelog

All notable changes to Husk are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); versioning
follows [Semantic Versioning](https://semver.org/).

## [1.1.1] - 2026-09-24

### Fixed
- `husk` crashed on launch on Windows: the Unix-only `resource` module was
  imported unconditionally. The dynamic sandbox (Linux-only by design) now
  reports "requires Linux" elsewhere; the static scanner works everywhere.
- ClawHub lookups never worked in production. The integration shelled out
  to `npx clawhub` with a command that does not return stored verdicts, and
  depended on Node.js being installed. Rebuilt on ClawHub's documented public
  REST API (`/api/v1/download`, `/api/v1/skills/{slug}`,
  `/api/v1/skills/-/security-verdicts`). No Node.js required.

### Detection
- Five new checks from a held-out re-benchmark (see BENCHMARK.md, "v1.1.1"):
  covert trigger -> script execution, instruction-supersede overrides, role
  hijack, download-then-execute / plain-HTTP script downloads, and targeted
  shell-startup persistence.
- Recall: MalSkillBench 63.9% -> 64.6%, ASB 61.9% -> 63.5% (held-out halves
  63.7% / 63.8%), with no new false positives on the 4,000 benign or 249
  curated skills.

### Changed
- `husk aggregate` now scans the whole downloaded package, not only
  `SKILL.md`, so malicious code in bundled scripts is caught.
- Lookup failures now explain themselves (unknown skill, rate limit,
  unreachable) instead of a generic "did not succeed".
- Results link back to the canonical ClawHub listing, as ClawHub's API terms ask.
- Accepts `slug`, `owner/slug`, `@owner/slug` or a clawhub.ai URL.
- The unbuilt Socket adapter is no longer shown as a checked source.

## [1.1.0] - 2026-09-23

### Added
- SARIF 2.1.0 output (`husk package <path> --output report.sarif`),
  for GitHub Code Scanning and other SARIF-consuming CI tools -
  findings show up in a PR's own Files Changed view and the repo's
  Security tab, not just a terminal log.
- `.huskignore` finding suppression, same convention as `.gitignore`.
- Official GitHub Action (`ctrl-adam/Husk/action@main`) wrapping scan
  and SARIF upload in one step.
- Package-level LLM semantic review (`husk package --llm-review`) -
  previously only scanned a single file; now covers every file in a
  multi-file package.
- Multi-provider LLM consensus review (`--llm-consensus`) - queries
  every configured provider and reports real agreement
  (unanimous/majority/split), not just one model's opinion.
- LLM review response caching and retry-with-backoff on transient API
  failures.
- VirusTotal signature check (`husk package --virustotal`) for the one
  gap static/semantic analysis can't close: a known-malware binary
  bundled in a package, checked by hash only.
- AST-based taint tracking now follows multi-hop parameter reassignment
  within a called function, not just a single direct use - closing a
  real gap found via testing against actual credential-harvesting
  samples.
- 8 new detection modules found and hardened against
  `cisco-ai-defense/skill-scanner`'s independently-labeled corpus
  (hardcoded secret literals, dynamic code compilation, untrusted
  package installs, unconstrained path reads, CPU-bound resource
  exhaustion, tunnel-service exfiltration endpoints, and more).
- Detection for the SkillCloak evasion technique (arXiv:2607.02357) -
  self-extracting payloads staged in `.git/`.
- `husk aggregate <skill_ref> --marketplace {clawhub,skillssh,agentskillsh}` -
  combines Husk's own verdict on an already-published skill with
  whatever other independent auditors have already said about it.
  ClawHub's resolver and native-audit lookup are fully real, verified
  against ClawHub's own official CLI; the other marketplaces are
  registered with an honestly-stated TODO, not a guessed-at scraper.

### Changed
- Relicensed MIT -> AGPL-3.0-or-later. See README.md's own License
  section for the reasoning.
- Confidence tiering: some findings (e.g. an ambiguous credential-file
  mention with no other signal) now report at INFO rather than
  FLAGGED, reducing false positives - inspired directly by comparing
  against SecureAI-Scan's own PROVEN/LIKELY/HEURISTIC evidence tiers.
  See BENCHMARK.md for the full, honest tradeoff this made (a real
  precision gain at a real, measured recall cost).
- Real-world recall: 63.9% (MalSkillBench) / 61.3% (ASB-derived),
  full datasets. Benign false-positive rate: 9.2%. See BENCHMARK.md
  for complete methodology and every competitor comparison.

### Fixed
- Several real false positives found via testing against the full
  4,000-sample MalSkillBench benign set: security tools describing
  their own detection patterns in comments or list literals (matched
  as if they were real calls), legitimate `urllib.request.urlopen()`
  fetches misread as exfiltration sends, and more - each with a
  permanent regression fixture added. Full account in BENCHMARK.md.

## [1.0.1] and earlier

See git history and BENCHMARK.md for the full, detailed account of
this project's development - every benchmark run, every competitor
comparison, every bug found and fixed, documented as it happened
rather than summarized after the fact.
