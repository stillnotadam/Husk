# Husk vs. skills.sh's auditors (Gen, Socket, Snyk): pilot, 2026-09-28

Source: the three auditors' published verdicts on https://www.skills.sh/audits (top 50 by
installs; 24 Feishu skills were still "Pending" and are not on GitHub, so excluded).
Husk 1.3.5 scanned each skill's files fetched from its GitHub source. 24 skills compared.

## Agreement with Husk
| Auditor | Agrees with Husk |
|---|---|
| Socket (flag = any alert) | 24/24 |
| Gen Agent Trust Hub (flag = anything but Safe) | 23/24 |
| Snyk (flag = Med risk or above) | 14/24 |
| Snyk (flag = High/Critical only) | 23/24 |

Husk passed all 24. Every skill an auditor rated risky was reviewed by hand (every line touching
credentials, network, installs or execution). None were malicious: they install a CLI via npm and
use a login token (the RunComfy skills), post to an issue tracker (triage), or run `npx skills`.
Snyk rated image-to-video Critical while near-identical sibling skills got Med.

## Limits (read before quoting)
- These are the most-installed skills from established publishers, so this measures **false
  alarms on legitimate skills**, not detection. It cannot show Husk catching something the
  auditors missed; that needs malicious skills that carry published audits.
- Snyk's risk levels appear to score capability (installs, tokens, network) rather than malicious
  intent, a different design goal, not simply a wrong answer.
- 24 skills is a pilot, not a benchmark.

| Skill | Gen | Socket alerts | Snyk | Husk |
|---|---|---|---|---|
| vercel-labs/skills/find-skills | Safe | 0 | Med | SAFE |
| mattpocock/skills/grill-me | Safe | 0 | Low | SAFE |
| mattpocock/skills/grill-with-docs | Safe | 0 | Low | SAFE |
| mattpocock/skills/improve-codebase-architecture | Safe | 0 | Med | SAFE |
| mattpocock/skills/tdd | Safe | 0 | Low | SAFE |
| vercel-labs/agent-browser/agent-browser | Safe | 0 | Med | SAFE |
| anthropics/skills/frontend-design | Safe | 0 | Low | SAFE |
| mattpocock/skills/setup-matt-pocock-skills | Safe | 0 | Low | SAFE |
| mattpocock/skills/handoff | Safe | 0 | Low | SAFE |
| mattpocock/skills/triage | Med | 0 | Med | SAFE |
| mattpocock/skills/prototype | Safe | 0 | Low | SAFE |
| mattpocock/skills/grilling | Safe | 0 | Low | SAFE |
| vercel-labs/agent-skills/vercel-react-best-practices | Safe | 0 | Low | SAFE |
| mattpocock/skills/teach | Safe | 0 | Low | SAFE |
| mattpocock/skills/domain-modeling | Safe | 0 | Low | SAFE |
| genmedia-labs/skills/video-edit | Safe | 0 | Med | SAFE |
| genmedia-labs/skills/ai-music | Safe | 0 | Med | SAFE |
| genmedia-labs/skills/ai-video-generation | Safe | 0 | Med | SAFE |
| genmedia-labs/skills/image-to-video | Safe | 0 | Critical | SAFE |
| genmedia-labs/skills/ai-image-generation | Safe | 0 | Med | SAFE |
| heygen-com/hyperframes/hyperframes-cli | Safe | 0 | Med | not scanned (126 MB repo, over the 30 MB fetch cap) |
| mattpocock/skills/codebase-design | Safe | 0 | Low | SAFE |
| vercel-labs/agent-skills/web-design-guidelines | Safe | 0 | Low | SAFE |
| mattpocock/skills/diagnosing-bugs | Safe | 0 | Low | SAFE |
| flowkit-labs/skills/reddit-automation | Safe | 0 | Med | SAFE |
