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
- Not yet tested against real-world malicious skill samples from public research datasets - only against samples built to match documented technique classes
- No large-scale false-positive testing against a broad set of legitimate skills yet
- Archive extraction currently supports ZIP; GZIP/7z/RAR extraction is detected but not yet unpacked

## Research this project is grounded in

- Trail of Bits / Cloud Security Alliance, *"AI Agent Skill Scanners: Bypassed Across the Board"* (June 2026)
- OWASP Agentic Skills Top 10 (v0.5, June 2026)
- Cisco skill registry security research (January 2026)

## License

MIT
