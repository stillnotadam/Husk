# Contributing to Husk

Thanks for considering it. This project runs on the same discipline
throughout its own history - every change should be backed by
evidence, not assertion.

## The core rule: every detection change reports both numbers

A change that improves recall (catches more real attacks) without
checking its effect on false positives isn't a complete change. Before
opening a PR that touches `src/husk/skill_scanner.py`,
`taint_analysis.py`, or any detection logic:

1. Find or build a **real** example the change is meant to catch -
   ideally from an actual dataset, not just a hypothetical. If you
   found the pattern in a real sample, say where.
2. Verify the change catches it.
3. Run the false-positive check against real legitimate skills (see
   `tests/` for the existing baseline fixtures) and report the result.
4. Run the full test suite (`pytest tests/`) and confirm nothing
   regresses.

PRs that add a detection pattern without a false-positive check
against real data won't be merged as-is - this has been the standard
throughout the project's own development (see `BENCHMARK.md` and
`ROADMAP.md` for many examples of exactly this process, including
several real precision bugs found and fixed this way).

## Setup

```bash
git clone <this repo>
cd husk
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a PR

```bash
ruff check src/ tests/      # lint - must pass clean
mypy src/husk/ --ignore-missing-imports   # type check - must pass clean
pytest tests/ --cov=src/husk --cov-report=term-missing   # full suite + coverage
```

Run all three yourself before opening a PR - they're not automated,
so it's on you to check them.

## Code style

- Every non-obvious detection pattern gets a docstring explaining
  *why* it exists - ideally citing the real sample or published
  research it came from. Future contributors (including future you)
  shouldn't have to guess what a regex is for.
- Broad `except Exception:` blocks are allowed, deliberately, for
  graceful degradation (LLM API calls, sandbox execution, parsing
  untrusted content) - but each one needs a comment explaining why a
  broad catch is the right choice *there specifically*, not a
  shortcut. See `pyproject.toml`'s `[tool.ruff.lint]` section for the
  full, documented rationale on this and a few other deliberate style
  choices.
- Don't mechanically wrap long regex/string lines to satisfy a line-
  length limit - a misplaced line break inside a regex is a real,
  easy-to-miss way to introduce a bug. This project has hit that
  exact mistake before; `E501` is disabled project-wide for exactly
  this reason.

## Adding a new detection module

Look at any recent module in `skill_scanner.py` for the expected
shape: a docstring explaining the real attack it targets (with a
citation if it came from published research or a specific real
sample), a narrowly-scoped regex or AST check, and a wired-in call
site with a numbered comment. Then:

1. Write a test proving it catches the real/realistic case.
2. Write a test proving it does *not* fire on a plausible legitimate
   case that superficially resembles the pattern (this has caught
   real bugs before - see `BENCHMARK.md` for examples like the
   Ethereum-address-vs-base64 collision, or the "system" keyword
   colliding between Ruby's shell function and AI-prompt-parameter
   documentation).
3. Run it against real data if you have access to any (see
   `BENCHMARK.md`'s "Sourcing real payloads" section for how this
   project found its own).

## Reporting a false positive

Open an issue with the flagged file's content (redact anything
sensitive) and which finding fired. This project's own false-positive
rate on real, curated legitimate skills is tracked directly in
`BENCHMARK.md` - a real false positive is exactly the kind of thing
that's been fixed quickly and documented honestly throughout this
project's history, not something to be defensive about.

## Reporting a missed attack

Even better - if you have (or can point to) a real sample of a
malicious skill that Husk misses, that's the single most valuable kind of
contribution this project can receive. See `tests/known_misses/` for
how currently-known gaps are tracked openly rather than hidden.
