# Husk

A static security scanner for AI agent skill packages - built to specifically defend against bypass techniques that were shown, in published 2026 security research, to defeat production scanners from Snyk, Cisco, and Vercel's skills.sh.

## Why this exists

AI agents can now install "skills" - reusable packages that tell an agent how to accomplish tasks, often bundling instructions with executable code. This is a fast-growing, under-protected attack surface: research published by Cisco (January 2026) found that roughly a quarter of agent skills across major registries contained at least one security vulnerability, and coordinated malicious-skill campaigns have already compromised thousands of skills across registries like ClawHub.

In June 2026, Trail of Bits researchers (published via the Cloud Security Alliance) demonstrated that the existing detection tools protecting these registries - including tools from Snyk, Cisco, and Vercel - could be bypassed using well-understood obfuscation techniques, in most cases in under an hour of effort. Some of these tools rely on an LLM to judge whether a skill is safe, which introduces a further weakness: the judge itself can be talked out of flagging something dangerous.

Husk is a response to that specific finding - not a general-purpose scanner, but one built and tested against the exact documented bypass techniques that beat the existing tools.

## What it defends against

| Technique | What it does | Status |
|---|---|---|
| Whitespace inflation | Pads a file with blank content to push malicious code past a scanner's context limit | Detected |
| Bytecode / base64 hiding | Encodes the payload so plain-text pattern matching can't read it | Detected, decoded, and recursively re-scanned |
| Archive indirection | Hides the payload inside a nested archive disguised with an innocent file extension | Detected via real file signatures, not filenames - recurses through nested archives |
| Prompt-injection against the scanner itself | Talks an LLM-based judge into approving a malicious skill | Not applicable by design - Husk never uses an LLM to make a safety decision; all detection is deterministic pattern analysis |
| Hidden instructions (prompt injection *targeting the agent*) | Directive language hidden in markdown/HTML comments, invisible on render, instructing the AI agent to act against the user's interest | Detected - verified against a real published example from academic research on 98,380 real-world skills |
| Credential harvesting | Scans for `.env`, `.pem`, `credentials.json`, SSH keys, etc. and exfiltrates them, often disguised as a backup/CI step | Detected - requires both file-access-to-a-credential-pattern AND network-send capability present, specifically to avoid flagging normal setup docs that just mention `.env` |
| Fake-prerequisite social engineering | Plain-English instructions telling a human to manually download and run a "required utility" - the actual dominant real-world pattern (86.3% of wild malicious skills per published research) | Detected - added after real-dataset testing revealed modules 1-6 caught 0/8 real malicious samples; now 8/8 |
| Exfiltration chains | The specific documented sequence: read a file, base64-encode it, send it over the network | Detected as a three-step chain, not a single pattern |

## Validated against real-world research, not just self-built test cases

Beyond the self-built test suite, Husk's hidden-instruction detector has been verified against an actual documented attack published in "*'Do Not Mention This to the User': Detecting and Understanding Malicious Agent Skills in the Wild*" - a large-scale academic study that confirmed 157 malicious skills out of a 98,380-skill snapshot. The paper's title comes directly from a real malicious skill instructing an agent to silently exfiltrate data. Husk correctly flags that exact pattern, and correctly leaves a normal, honest code comment unflagged.

## How detection works, honestly

Husk does not use machine learning or an LLM to decide whether something is safe. Every check is deterministic: opcode inspection for pickle files, pattern matching against known-dangerous constructs, real binary signature checks for archives, and a lightweight constant-propagation pass that resolves simple string concatenation before pattern matching, specifically to catch payloads split across variables to dodge plain-text detection.

This is a first version. It has been adversarially self-tested - evasion variants were built specifically to try to defeat each check, two real gaps were found in that process (Unicode whitespace padding, and base64 payloads split across multiple short fragments), and both were fixed and re-verified. That process is ongoing; no static scanner is ever a finished, unbeatable thing, and Husk does not claim to be one.

## Usage

```bash
# Scan a single pickle-based model file
python3 scanner.py path/to/model.pkl

# Scan a single skill file
python3 skill_scanner.py path/to/SKILL.md

# Scan an entire skill package (handles nested/disguised archives)
python3 package_scanner.py path/to/skill_package/
```

## What v1 does NOT do yet

- No packaged CLI install (`pip install` support) yet
- No large-scale false-positive testing against a broad set of legitimate skills yet (currently 11 hand-built test cases, 3 clean / 8 flagged, zero false positives so far - but this is a small sample)
- Archive extraction currently supports ZIP; GZIP/7z/RAR extraction is detected but not yet unpacked
- Credential-harvesting detection only covers a fixed list of filename patterns (.env, .pem, credentials.json, etc.) - a renamed or unlisted credential file type would be missed
- Exfiltration-chain detection currently checks for presence of all three steps anywhere in the file, not strict call-order - a coincidental combination could theoretically false-positive, though none has been observed yet
- **Does not reliably catch novel, semantically-disguised attacks with no code and no recognizable keywords** - tested directly against an independent academic dataset (AgentTrap) with genuinely different attack styles than the campaign used for the "8/8" validation elsewhere in this README, and missed both samples tried (a subtle instruction-blurring attack, and a fake "compliance auditor" that asks in plain prose for secrets to be sent to an external endpoint). This matches independent published research (see BENCHMARK.md) showing static pattern-matching tops out around 13-32% recall on novel/disguised attacks generally - not a Husk-specific flaw, but a real, honest limit of this entire approach. Husk is a fast, free, local first-pass filter, not a complete security boundary.

## Research this project is grounded in

- Trail of Bits / Cloud Security Alliance, *"AI Agent Skill Scanners: Bypassed Across the Board"* (June 2026)
- OWASP Agentic Skills Top 10 (v0.5, June 2026)
- Cisco skill registry security research (January 2026)
- *"'Do Not Mention This to the User': Detecting and Understanding Malicious Agent Skills in the Wild"* - 98,380-skill academic study, 157 confirmed malicious

## License

MIT
