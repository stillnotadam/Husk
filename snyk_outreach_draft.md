Subject: Student research request - evaluating Snyk Agent Scan for a comparative security study

Hi Snyk team,

My name is Adam, I'm a first-year CS/Math student at the University of Strasbourg. I've built an open-source static security scanner for AI agent "skill" packages, called Husk (github link below once pushed), and I've been running honest, published benchmarks comparing it against several real competitors in this space - SkillScan, agent-audit-kit, agent-audit, and NVIDIA's SkillSpector so far.

I'd like to include a fair comparison against Snyk Agent Scan, but I've hit a real access wall: the CLI (github.com/snyk/agent-scan) requires a Snyk account token, and both an Auth Token and a Personal Access Token from a free-tier account return 403 Forbidden on the actual analysis endpoint. From what I can tell, real detection is gated behind an entitlement beyond free signup.

Is there any way to get short-term, read-only or trial access to Agent Scan's real detection engine - enough to run it against a public, already-labeled malicious-skill dataset (MaliciousSkillBench, cited in my benchmark writeup) and report the real number? I'd publish the result exactly as I do for every other tool: honestly, including anywhere it beats my own project.

Happy to share my existing benchmark writeup (BENCHMARK.md) so you can see the methodology and that this isn't a hit piece - every comparison I've run so far has been reported fairly, including cases where I lost.

Thanks for your time,
Adam
meetadam.net
