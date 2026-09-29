# Competitor benchmark harness

Everything used for the 2026-09 head-to-head in BENCHMARK.md.

- `sample.json` / `sample_small.json`: the fixed, seeded sample (699 skills) and the shared
  200-skill subset used for the slowest tools.
- `tools.json`: the exact command each scanner was run with. `meta.json`: versions.
- `runner.py <tool> <workers>`: runs one tool over the sample, resumable, stores raw output.
- `score.py` and `report.py`: reduce every tool's output to one severity on a shared scale and
  build the tables. Strict = high/critical, loose = low and above. No-result skills are excluded
  from a tool's percentages and reported separately.
- `raw/*.jsonl.gz`: every tool's raw output for every skill, so any row can be re-scored.
- `mondoo_results.json`, `fetchdir.py`: the Mondoo highest-risk comparison.

Paths inside the files point at the benchmark machine (`/home/claude/...`); the sample lists
map to the MalSkillBench, ASB-derived and curated datasets described in BENCHMARK.md.
