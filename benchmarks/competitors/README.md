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

## 2026-10 refresh

`raw/2026-10/` holds the refresh described at the top of BENCHMARK.md: the 549 sample
skills available on the newer benchmark machine (the ASB-derived half was not), run with
Husk 1.4.0 (`husk`) and 1.4.1 (`huskdev`) and the competitors released since 2026-09.
`runner_local.py` reads `sample_local.json` (original path, local path) and stores records
under the original path, so `report_local.py` can join them with the 2026-09 raw files
(set `HUSK_OLD_RAW` to an absolute path to `raw/`).
