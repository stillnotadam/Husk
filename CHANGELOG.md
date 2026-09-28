# Changelog

All notable changes to Husk are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); versioning
follows [Semantic Versioning](https://semver.org/).

## [1.3.2] - 2026-09-28

### Fixed
- agentskill.sh skill lookup: the install API URL was %2F-encoded and 404'd on
  their live router; now uses the documented raw-slash path
  (/api/agent/skills/<owner>/<skill>/install), matching their real API exactly.

## [1.3.1] - 2026-09-28

Marketplace lookup actually works for all three registries, plus each
marketplace's own audit verdict.

### Fixed
- skills.sh and agentskill.sh skill lookup now resolve real content (was
  "unavailable"). Both marketplaces index GitHub-hosted skills, so Husk fetches
  the skill straight from its GitHub source; agentskill.sh also falls back to
  this if its own API is unreachable. Verified end-to-end on a real live skill.

### Added
- skills.sh and agentskill.sh native audit verdicts: alongside Husk's own scan,
  the aggregate now shows each marketplace's own published security verdict
  (skills.sh's Socket/Snyk/Trust-Hub Pass/Warn/Fail, agentskill.sh's 0-100
  score). Parsers verified against the real live audit pages.

## [1.3.0] - 2026-09-27

Multi-language depth, PDF coverage, and the false-positive fixes that a real
ecosystem scan of live GitHub skills exposed.

### Added
- **AST-based JS/TS taint engine** (esprima): real source->assignment->sink
  data-flow analysis for JavaScript and TypeScript, the same as Python. Powers
  `husk explain` for JS/TS. Single-env-var-to-its-own-API stays clean; only
  whole-env / credential / exec-eval flows flag.
- **PDF text extraction**: bundled PDFs are extracted and run through the full
  detection suite, catching payloads hidden in "reference documents". Defensive
  against huge/encrypted/malformed/image-only PDFs.
- **Ecosystem research harnesses** (benchmarks/): mass-scan live marketplace
  and GitHub skills, rank by severity, produce a triage shortlist.

### Fixed (found by scanning real live skills)
- Office/container formats (.docx, .xlsx, .pptx, .jar, .whl, .ipynb, fonts...)
  are legitimate ZIP containers, no longer flagged as hidden payloads - this
  alone had inflated one real repo's score by ~12,000.
- A bare http(s):// URL no longer counts as a data-movement "action" in the
  secrecy rule, which had fired all over ordinary changelog prose.
- The newest attack types (reverse shells, OAST/exfil beacons, bulk env
  exfiltration, cloud-metadata SSRF, Discord/Telegram C2, JS/TS taint) now rank
  critical/high in the gate instead of defaulting to medium.
- Duplicate findings are deduped in scan_package.

## [1.2.0] - 2026-09-27

Husk becomes a lifecycle security layer, not just a scanner. Three new
capabilities, each doing something a point-in-time / server-side AI review
structurally cannot.

### Added
- **`husk attest` / `husk verify-attestation`** - deterministic, content-bound
  attestations in the standard in-toto Statement v1 / SLSA verification-summary
  format. Binds a SHA-256 of the skill's exact content to Husk's verdict and
  the exact ruleset digest. Reproducible (byte-identical on rerun),
  offline-verifiable, tamper-evident. Optional Sigstore keyless signing via the
  `[sign]` extra. GitHub Action gains an `attest` input.
- **`husk crossref`** - cross-marketplace verification. Fetches the same skill
  from every registry, compares content digests and verdicts, and flags a
  registry serving different or more-dangerous content under the same name (a
  supply-chain substitution attack). The neutral layer no single marketplace
  can be.
- **`husk watch`** - re-scans installed skills against a local baseline and
  alerts when one that was SAFE turns FLAGGED after a content change (a
  malicious update). Auto-discovers skills under the common agent install
  roots. The time dimension no point-in-time scan covers.
- **`husk explain`** - explainable data-flow: the exact source -> variable ->
  sink trace behind each taint finding, human-readable or JSON. The auditable
  "why" a security reviewer trusts over a verdict, and something an LLM review
  cannot produce deterministically. The taint engine now records the source
  line, not just the sink.
- **`husk registry`** + content-addressed scan cache - scan many skills (a
  whole registry, an install dir) incrementally: a skill's result is keyed by
  its content digest, so unchanged skills are never re-scanned. `husk watch`
  uses it too. A repeat sweep of thousands of skills becomes minutes, not
  hours. A ruleset change (Husk upgrade) transparently invalidates the cache.
- **Real AST-based JS/TS taint engine** (esprima) - Husk now follows data flow
  (source -> assignment -> sink) in JavaScript and TypeScript, the same as
  Python, not just regex. Powers `husk explain` for JS/TS too. Zero false
  positives; single-env-var-to-its-own-API stays clean, only whole-env /
  credential / exec-eval flows are flagged.
- **PDF text extraction** - bundled PDFs are extracted and run through the full
  detection suite, catching payloads (prose injection, curl|bash, persistence)
  hidden in "reference documents" where a text-only scanner never looks. +6
  real catches on the benchmark, 0 false positives. Defensive against huge /
  encrypted / malformed / image-only PDFs.
- Detection: two no-code prose prompt-injection classes now caught
  deterministically - system-prompt exfiltration and jailbreak / safety-bypass
  instructions - the attacks usually assumed to require an LLM reviewer.
  +60 real catches, zero false positives on 4,249 benign skills. Recall
  MalSkillBench -> 65.6%, ASB -> 63.7%.

### Changed (detection - all measured on the 15,474-sample benchmark, zero new false positives)
- New rules from a systematic miss analysis: out-of-band exfil-testbed callback
  domains (oast.fun, Beeceptor, Pipedream, Burp Collaborator...), staged /
  obfuscated code execution (payload-as-string, exec(base64...),
  getattr(__import__), exec(compile)), concrete C2/exfil sinks (real
  Discord/Telegram webhooks, reverse-shell I/O redirection), and cloud
  instance-metadata SSRF. Recall: MalSkillBench 63.9% -> 64.8%, ASB 61.3% ->
  63.3%, while benign clearance rose to 95.4% and curated real skills to 99.6%.

## [1.1.4] - 2026-09-27

Focus: precision (making Husk trustworthy on real skills) and adoption
(making it something a registry can actually drop into CI).

### Added
- `husk gate <package>`: a deterministic pre-publish gate - one PASS/WARN/FAIL
  decision, offline, in milliseconds, no API cost. Severity-tiered
  (critical/high/medium/low/info); a finding is not a verdict (curl|bash from
  bun.sh does not block, a C2 IP does). `--json` for CI, `--block-on` to set
  the bar, exit code 1 on fail.
- `.huskpolicy` file: per-package policy (block_on / warn_on / ignore /
  example_paths). `example_paths` lets a security tool declare the docs that
  legitimately quote attack strings, so those are reported not blocked -
  author-declared, never auto-guessed (real malware is disguised as security
  tooling, measured on the benchmark).
- GitHub Action rebuilt around the gate: severity-based pass/fail, PR comment
  with the result, optional SARIF upload. Example workflow + pre-commit hook.

### Changed (precision, all measured on the 15,474-sample benchmark)
- Proximity requirement added to the identity-file, wallet, and credential-
  harvesting rules: the marker and the dangerous action must be near each
  other, not merely both present somewhere in the file.
- Trusted-installer allowlist: `curl | bash` from a reputable vendor endpoint
  (bun.sh, rustup, foundry, the OpenClaw CLI, ...) is INFO; unknown hosts stay
  flagged.
- Bare-IP rule excludes bind-all/placeholder/doc IPs (0.0.0.0, 1.2.3.4, RFC
  5737). osascript-JXA and split-base64-without-a-real-payload demoted to INFO.
- Net result: benign skills correctly cleared 92.2% -> 95.4%, curated real
  skills 98.8% -> 99.6%, recall 63.9% -> 62.8%.

## [1.1.3] - 2026-09-26

From the second live ClawHub run (600 skills, 0 download errors).

### Changed
- "File references a credential-file pattern" is an INFO note in documentation
  files unless a network-send call is within 15 lines. It was 33 of Husk's 45
  flags on ClawHub-clean skills. Benign clean 90.8% -> 92.2%; recall
  MalSkillBench 64.2% -> 63.9%, ASB 63.3% -> 63.1%.

### Fixed
- ClawHub's own verdict was "unavailable" for skills whose name is shared by
  several publishers; Husk now falls back to /verify?ownerHandle=.

### Added
- The ClawHub benchmark records ClawHub's reason codes and summarises why
  ClawHub flagged skills that Husk passed.

## [1.1.2] - 2026-09-25

Found by running Husk against 452 real ClawHub skills (benchmarks/clawhub_benchmark.py).

### Fixed
- A file containing null bytes crashed the whole package scan.
- ClawHub lookups failed for skills whose name is shared by several publishers
  (HTTP 409); Husk now passes the owner, and explains the error when none is given.

### Changed
- "Unusually long hidden comment" is now an INFO note unless the comment is
  directed at the agent. It flagged ~10% of real clean ClawHub skills.
  Recall: MalSkillBench 64.6% -> 64.2%, ASB 63.5% -> 63.3%; benign clean 90.7% -> 90.8%.

### Added
- `benchmarks/clawhub_benchmark.py`: compares Husk with ClawHub's published
  verdicts on real skills (public API only, rate-limit aware, resumable).

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
  permanent regression fixture added.

## [1.0.1] and earlier

First public releases: the core detection engine, package/archive and
pickle-model scanning, the optional sandbox and LLM-review layers, and
the dual-dataset benchmark.
