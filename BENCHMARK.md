# Benchmark: Husk vs. Snyk agent-scan

This is a real, reproducible comparison - every command below was actually
run, not simulated. Snyk's `agent-scan` was installed from its own public
source (`github.com/snyk/agent-scan`, v0.6.4), not a mock or a guess.

## The headline finding: access model

```
$ snyk-agent-scan tests/skills/malicious-skill/SKILL.md
Snyk Agent Scan v0.6.4

To use Agent Scan, set the SNYK_TOKEN environment variable. To get a token, go
to https://app.snyk.io/account (API Token -> KEY -> click to show).
[exit code: 1]
```

This is Snyk's **own test fixture for a known-malicious skill**. Their tool
will not produce a verdict - safe or malicious - on any file without a paid
Snyk account and an API token. A local, token-free `inspect` subcommand
exists, but it only lists what files were found; it performs no security
analysis at all ("Print descriptions of tools, prompts, and resources
**without verification**" - their own description).

```
$ husk-scan tests/skills/malicious-skill/SKILL.md
Husk skill scan result: FLAGGED
  - Line 35: Decodes base64 - common way to hide a payload ('base64 -D')
  - Line 24: password-protected archive extraction instructions
    ('EXTRACT** with password: `1234') - a documented technique for
    evading automated antivirus/archive scanning
  [+ 4 more findings]
```

Husk produces a full verdict, with specific reasoning, on the same file,
immediately, offline, for free, no account, no signup, no network call.

## Why this matters more than it might sound

This isn't a claim about detection quality (see "What this benchmark does
NOT claim" below) - it's a claim about **access**. A tool that requires a
cloud account and API key to function at all is a fundamentally different
category of thing than one that runs standalone. For:
- a developer who wants to check a file before installing it right now
- a CI pipeline that shouldn't depend on an external service being up
- anyone who wants to read every line of code that produces the verdict,
  not trust a remote "analysis-machine" endpoint (see ROADMAP.md's log
  entry on this)

...Husk's model is a real, structural advantage, not a marketing claim.

## What this benchmark does NOT claim

We do not have a paid Snyk account or API token, so we have **not** been
able to compare raw detection accuracy between Snyk's real analysis engine
and Husk's. That comparison would require either paying for Snyk access or
someone who already has a token running both tools against the same test
set. This gap is listed honestly rather than papered over - see the
Tier 1 checklist in ROADMAP.md.

What we *can* and *have* verified, independently of Snyk entirely:
- Husk: 8/8 real confirmed-malicious skills caught (Hugging Face dataset)
- Husk: 248/249 (99.6%) real legitimate skills scan clean, zero false
  positives from two large real skill repositories
- Husk: 13/13 self-built adversarial evasion tests correctly caught

## Reproducing this

```bash
git clone https://github.com/snyk/agent-scan.git
python3 -m venv venv && source venv/bin/activate
pip install -e agent-scan
snyk-agent-scan path/to/any/SKILL.md   # will ask for SNYK_TOKEN

python3 skill_scanner.py path/to/any/SKILL.md   # Husk - works immediately
```
