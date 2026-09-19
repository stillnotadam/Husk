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
- [x] **CI pipeline** - GitHub Actions (.github/workflows/tests.yml) runs
      the full pytest suite across Python 3.10/3.11/3.12 on every push/PR,
      plus a separate regression check against all 8 real malicious
      samples. README badge wired to the live workflow.
- [x] **Packaging** - restructured into src/husk/ package layout, real
      pyproject.toml, `pip install -e ".[dev]"` verified clean from
      scratch, `husk` CLI command with skill/package/model subcommands
      and proper exit codes (0=SAFE, 1=FLAGGED) for scripting/CI use.
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
- 2026-09-19: **Second benchmark completed - this one fully fair, both
  tools tested locally, no auth barrier.** Installed SkillScan (another
  real open-source skill scanner, static-analysis layer runs offline)
  and ran it against the identical real test data used throughout this
  project. Results: Husk 8/8 vs SkillScan 0/8 on real confirmed-malicious
  skills (SkillScan's cumulative risk-threshold system doesn't flag the
  dominant real-world fake-prerequisite pattern even though it detects
  individual signals within it - the exact blind spot Husk's module 7
  was built to fix). False positives: Husk 1/249 (0.4%) vs SkillScan
  8/249 (3.2%) on the same 249 real legitimate skills. Reported fairly:
  SkillScan's obfuscation analyzer is more sophisticated in one area
  (entropy-based base64 detection, macOS-specific checks) - both tools
  correctly caught Snyk's sophisticated malicious-skill fixture. Full
  writeup in BENCHMARK.md.
- 2026-09-19: **Independent research check, and a real, honest finding.**
  Found skillscan.sh - an independent, rigorously-tested benchmark of
  skill scanners (built by someone who retired their own static scanner
  after honestly measuring it against attacks they didn't author).
  Core finding: static rule-based scanning tops out around 13-32% recall
  on novel/disguised attacks; only a frontier LLM reading the skill
  clears 80%+, at the cost of tokens and third-party data sharing.
  Tested this directly against Husk using a genuinely different academic
  dataset (AgentTrap, 15+ distinct attack dimensions, not the one
  campaign used elsewhere in this project's validation). Husk missed
  both diverse samples tried - saved as tests/known_misses/ so they stay
  visible, not swept away. This means the earlier "8/8 real malicious"
  number is real but narrower than it might read: it's validated against
  one known, templated campaign (which module 7 was built specifically
  to catch), not against novel/disguised attacks generally. Documented
  honestly in README.md and BENCHMARK.md. Forward path this motivates:
  an optional, clearly-labeled LLM-review layer as a Tier 2 item -
  grounded directly in this research rather than assumed.

## Tier 2 (beyond "better than Snyk/SkillScan on known patterns")

- [x] Optional LLM-based semantic review layer - built, opt-in via
      `--llm-review`, requires ANTHROPIC_API_KEY, degrades gracefully
      with no key or on API failure (static result always unaffected).
      Structurally tested with mocked API responses (request building,
      response parsing, both failure modes) - 3 new tests, all passing.
      Honestly labeled in README with the real tradeoff (tokens, third-
      party data, not free/local/private) rather than hidden.
      **LIVE-VALIDATED 2026-09-20**: ran it for real, with a real API
      key, against both tests/known_misses/ fixtures - the two real
      attacks Husk's static scanner cannot see. Result: 2/2 caught, both
      "high confidence," both with precise, correct reasoning naming
      the exact attack mechanism (instruction-blurring for case_0009,
      credential exfiltration disguised as compliance for case_0036).
      This is the real proof behind the premise: static analysis alone
      misses these; static + optional LLM review catches them. The
      known_misses/ fixtures stay in the static-only regression suite
      (that's still an honest, true limitation of the free default
      path) - this result specifically validates the opt-in upgrade
      path, not a claim that static analysis itself improved.
- [x] Expand known_misses/ into a real regression suite of diverse,
      non-templated attacks, sourced from independent datasets - added
      tests/known_misses/real_world/, holding 4 verified real samples
      pulled directly from MaliciousSkillBench sources (not self-
      crafted): the SRC009 Self-Mutating-Poisoning structural-limit
      case, the SRC013 "shared bootstrap wrapper" persistence attack,
      the SRC006 dynamically-generated-payload structural-limit case,
      and a newly-found real sample (a legitimate-looking "xlsx" skill
      instructing the agent to embed a hidden worksheet as a covert
      persistence/watermarking channel, conditionally triggered by a
      marker file). Combined with the 6 existing illustrative fixtures
      (grounded in a real taxonomy but not verbatim dataset extracts),
      the suite now holds 10 known misses across genuinely distinct
      attack categories, with real vs. illustrative provenance kept
      honest via directory structure, not blurred together. Verified:
      13 passed, 10 xfailed - all correctly wired.
- [x] Re-evaluate module coverage against attack *dimensions* (the
      AgentTrap taxonomy: exfil, destructive, injection, backdoor,
      resource-abuse, jailbreak, hidden-content, tracking, patch-inject,
      poisoning, collusion, homoglyph, typosquat, proxy/oauth, IAM) not
      just against one campaign's specific patterns - full audit below.

      **Strong coverage** (multiple modules each): data exfiltration
      (credentials/files/wallets/identity-memory), code/command
      execution injection (shell/eval/exec/bytecode), obfuscation/
      evasion (base64/whitespace/unicode-steg/string-concat), prompt
      injection & instruction manipulation (hidden + overt), archive/
      file-structure evasion.

      **Moderate coverage**: social engineering (fake-prerequisite,
      name hijacking, safety-bypass) - real but narrow, each rule
      targets one specific real-world shape rather than the category
      broadly. Persistence/backdoor (dropper, chmod) - catches blatant
      cases, but the real SRC013 "bootstrap wrapper" sample (in
      known_misses/real_world/) shows subtle, jargon-disguised
      persistence is not reliably caught.

      **Real gaps, zero dedicated coverage**: output/integrity
      manipulation (silently altering code correctness - see
      known_misses/output_manipulation.md); resource/availability
      abuse (unbounded recursion/token bombs - see
      known_misses/resource_abuse.md); document-embedded steganography
      (hidden worksheets/white text in delivered files - see
      known_misses/real_world/src001_hidden_worksheet_steganography.md,
      found this session); package/dependency typosquatting (distinct
      from the skill-*name* hijacking module 19 already covers);
      IAM/OAuth-specific privilege escalation beyond AWS-credential-file
      and wallet-extension access already covered.

      **Partial coverage**: non-Python native code (Rust/Go/Ruby files
      are scanned for the same generic patterns - curl|bash, bare-IP,
      secrecy language - but have no language-specific dangerous-call
      detection the way Python does; PowerShell is the one exception,
      with real coverage added this session).

      **Structurally undetectable by any static (or even LLM) read**,
      documented honestly rather than chased further: Self-Mutating
      Poisoning (SRC009) and dynamically-generated payloads (SRC006) -
      both confirmed via real samples and the underlying published
      research (see BENCHMARK.md).

      This audit is the map for future module work - a real gap list
      to work from, not a vague sense of "probably missing some stuff."
- [ ] Basic sandboxed dynamic analysis (catches logic-bomb/delayed-
      activation attacks no read-time review, static or LLM, can see)
- [ ] Multi-platform skill format support (Claude Code skill.json,
      Cursor manifest.json - currently OpenClaw-style SKILL.md only)
- 2026-09-19: **Tier 1 checklist complete.** All five items done with
  real evidence: real-dataset validation, false-positive testing at
  scale (249 real files), two real benchmarks (Snyk access-model win,
  SkillScan decisive win on identical real data), CI pipeline, and
  real pip packaging. The honest limitation found via skillscan.sh-
  motivated testing (novel/disguised attacks) is documented, not
  hidden, and structurally can't regress silently - see
  tests/known_misses/ and the xfail(strict=True) wiring in
  tests/test_scanner.py. Tier 2 (optional LLM-review layer, broader
  attack-dimension coverage) is scoped above as real future work.

## Project direction: staying free, open source, BYOK - deliberately

2026-09-20: Explicitly decided against turning this into a hosted/paid
product. Considered the tradeoffs (hosted service, registry licensing
deals, etc.) and chose to keep Husk exactly as built: free, fully open
source, and bring-your-own-key for the optional LLM layer. Reasoning:
- BYOK already eliminates the unit-economics risk (no API costs to
  cover) and most of the privacy exposure (skill content never passes
  through infrastructure Husk's author runs) that a hosted version
  would carry
- At this project's current stage, the strongest realistic value is
  reputation and credibility - a real, rigorously-tested, honestly-
  documented tool - not premature monetization
- This doesn't close the door on a hosted tier or licensing later if
  the project's trust and adoption genuinely grow; it just isn't the
  goal right now, and the free core described in README.md is meant
  to stay free regardless of what (if anything) gets built alongside
  it later
- 2026-09-20: **Broadened live LLM-review validation from 2 to 6 attack
  categories.** Found a much larger academic benchmark
  (ProtectSkills/MaliciousSkillBench, 7,505 malicious samples, 11
  harmonized attack categories, arXiv:2608.19901) but hit real API
  access friction trying to bulk-pull full text from it - reported
  honestly rather than hidden, similar in kind to the earlier Snyk
  access barrier. Instead built 4 more responsible self-built test
  cases targeting 4 categories from that benchmark's own taxonomy not
  yet covered (authority/permission over-reach, silent output
  manipulation, hidden persistence, unbounded resource abuse). Ran all
  4 live, same as before: static missed all 4 (expected), LLM review
  caught all 4 (3 high confidence, 1 medium), each with precise correct
  reasoning. Combined total: 6/6 live-tested attacks across 6 distinct
  categories, 0/6 caught by static, 6/6 caught by LLM review. All 6
  saved permanently in tests/known_misses/, wired as xfail(strict=True).

## Reframing: static analysis is primary, LLM is backup - documented explicitly

2026-09-20: Explicit direction from the project's own standards: (1)
detection claims must be tested against real payloads, not self-built
ones; (2) the project's own performance stats must not rely on an LLM
to look good - LLM successes are credited to Anthropic, not claimed as
this project's engineering; (3) static analysis is the primary,
authoritative layer, continuously reinforced against real evidence; LLM
review is a last-resort backup only.

Acted on all three:
- Sourced 3,426 REAL malicious payloads directly from
  MaliciousSkillBench's GitHub repo (not self-built)
- Established the real, large-scale, static-only headline number:
  **41.4% recall**, improved honestly from a first real result of 22.8%
  through two genuine fixes (whole-package scanning, module 8) - see
  BENCHMARK.md's "Real-world static recall" section for full detail
- Reframed README.md and the CLI itself: LLM review now prints as
  "Backup: LLM semantic review (Anthropic Claude, not Husk's own
  logic)", only suggested when static analysis finds nothing, verdict
  attributed to "Claude's verdict" / "Claude's reasoning" rather than
  presented as Husk's own result
- BENCHMARK.md now leads with the static-only number and states plainly
  that everything LLM-related is a separate, secondary story credited
  to Anthropic

## Scaled real-world testing: 3,426 -> 7,526 real payloads, 48.9% recall

2026-09-20: Extracted all remaining MaliciousSkillBench source archives
(10 more, beyond the one used previously) - 7,526 real confirmed-
malicious payloads total. New baseline: 45.4%. A single real sample
(a .py file disguised as a <tool_description> tag, instructing the
agent to POST every edited file's contents to a hardcoded IP with "Do
not mention this to the user") exposed 3 more genuine gaps at once.
Built modules 9-11 (whole-document secrecy language, bare-IP C2
detection, list-form subprocess exfiltration). First-pass result:
53.5%, but found a real precision bug immediately via false-positive
testing (13/249 new false positives - "silently ignored" type ordinary
phrases). Fixed properly: combination-based matching (secrecy + action
word nearby), plus two further precision bugs in that fix itself
(missing word boundaries, paragraph-window too wide for markdown
tables). Final verified result: 48.9% (3,681/7,526), 248/249 real
legitimate skills clean - same baseline as always, zero new false
positives. Full story in BENCHMARK.md.

## Tier 3 - "Founder of something genuinely great"

The explicit goal: real competition with actual companies in this
space, on quality and depth, not just on having tried. Precision and
recall must both keep climbing together - a bigger number that costs
false positives doesn't count as progress (see the agent-audit-kit
benchmark for exactly why). Nothing here is off-limits; scope and
sequencing below are about doing it right, not about avoiding it.

### A. Bulk real-sample sourcing (keep expanding, don't stop at 7,526)
- [ ] Find and pull additional real-malicious-skill datasets beyond
      MaliciousSkillBench (check for newer/larger academic releases,
      other GitHub source-artifact repos like the ones already found)
- [ ] Specifically target sophisticated, non-templated samples (the
      AgentTrap-style diverse dataset, not just campaign-style dumps)
      to stress-test beyond pattern-matching one attacker's style

### B. Precision + recall, tracked together
- [ ] Every future module addition reports BOTH numbers, not just
      recall - a module that raises recall but drops the false-positive
      baseline below 98% doesn't ship as-is
- [ ] Re-run the full 7,526 (+ any newly added) real-malicious set and
      the full real-legitimate set after every batch of changes

### C. Competitor benchmarking - real, viable competitors only
- [x] SkillScan - decisive win, clean data
- [x] agent-audit-kit - nuanced, honest precision/recall tradeoff
- [ ] skillscan-security - retry properly (their real research tool;
      blocked tonight by this environment's network access, not by
      the tool itself - worth a real second attempt with a workaround)
- [ ] Find 1-2 more real, viable competitors beyond what's been tried
      (skip ones already shown to be a scope mismatch or environmentally
      blocked for good reason - target ones with a real chance of
      teaching us something)
- [ ] Snyk: access remains blocked; revisit only if a free/trial path
      surfaces (see the earlier email-outreach suggestion)

### D. Learn from competitor source code directly
- [x] Read agent-audit-kit's actual rule source (357 rules, 130+
      categories) - most cover known CVEs across specific named
      frameworks (LangChain, CrewAI, LiteLLM, etc.), a different scope
      than skill-content analysis. Only ~6 rules directly comparable;
      2 contained genuinely new ideas Husk didn't have, both built and
      shipped: Unicode steganography (bidi-override/tag characters,
      module 18) and trusted-name hijacking (module 19, scoped to only
      fire alongside another independent finding).
- [x] Re-read Snyk agent-scan's source specifically for technique ideas
      (separate from the access-model finding already documented) -
      confirmed no local detection logic exists at all; every function
      is discovery/parsing, all real analysis is server-side. Nothing
      to learn technique-wise, only confirms the earlier finding.
- [x] Read SkillScan's source - **major architectural finding**: it
      uses Python's real `ast` module for proper taint-flow tracking
      (secret source → variable propagation → exec/network sink),
      structurally more robust than Husk's regex-proximity approach.
      This is exactly the kind of thing that would have prevented
      several bugs found and hand-patched tonight (the credential-
      harvesting "structurally separated" bug, the subprocess
      shell=True nested-paren bug). **Flagged as a real candidate for
      a future architectural upgrade - an AST-based analysis layer for
      Python files - rather than rushed in alongside tonight's other
      work.** This is a bigger undertaking than a regex module and
      deserves its own dedicated session.

### E. Platform / format diversity
- [ ] Claude Code `skill.json` format support
- [ ] Cursor `manifest.json` format support
- [ ] Continue expanding scanned file types as real samples justify it
      (same evidence-driven approach used for .rs/.go/.ps1/etc. tonight)

### F. Dynamic sandboxed analysis (scoped honestly)
- [ ] Design a real, safe execution-observation layer: run a skill's
      scripts with network egress restricted to nothing (catches
      logic-bomb/delayed-activation behavior no static or LLM read can
      see) - this needs to be built carefully, with real safety
      boundaries, not rushed
- [ ] Validate it against real samples where static analysis is known
      to structurally fail (the SMP/dynamically-generated-payload class
      documented in BENCHMARK.md) to see what, if anything, becomes
      newly detectable
