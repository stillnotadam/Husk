# Publishing husk-scanner to PyPI

**Live**: `husk-scanner` 1.0.1 is published. `pip install husk-scanner`
works, but installs a version that predates everything in this
session's work, SARIF output, the aggregator, the taint-analysis
fixes, none of it exists in what's currently live.

## What's changed since 1.0.1, worth publishing for on its own

Not a routine bump - a materially different feature set:

- SARIF 2.1.0 output and finding suppression (`.huskignore`), real CI
  integration that didn't exist before
- The aggregator (`husk aggregate`), combining Husk's own verdict with
  other marketplaces' published opinions on an already-listed skill
- AST-based taint tracking now follows multi-hop parameter
  reassignment, closing a real gap found via testing against actual
  credential-harvesting samples
- Confidence tiering and several real, individually-verified false-
  positive fixes (see BENCHMARK.md for the full, honest account,
  including the real recall cost that came with the precision gain)
- Relicensed MIT -> AGPL-3.0-or-later (see README.md's own License
  section for why)

`pyproject.toml` is already at `1.1.0`. Full detail in CHANGELOG.md,
written for exactly this kind of release.

## What's already done and verified

- `pyproject.toml` is complete: real metadata, keywords, classifiers,
  the new AGPL-3.0-or-later license, a matching `LICENSE` file present
  (full text, not a stub)
- A fresh build passes `twine check` (PyPI's own metadata validator) -
  confirmed directly, not assumed
- Confirmed the built wheel includes every new module (`reporting.py`,
  `taint_analysis.py`, `aggregator.py`, etc) - checked the actual file
  listing in the build output, not just that the build succeeded
- Installed the built wheel into a genuinely clean, fresh virtual
  environment (not this project's own dev setup) and confirmed the
  `husk` CLI works end-to-end: `--help` lists all 4 subcommands
  (`skill`, `package`, `model`, `aggregate`), a clean scan reports
  SAFE, a malicious one reports FLAGGED with the right exit code
- `dist/` and `build/` are in `.gitignore` - always rebuild fresh at
  release time, don't publish stale artifacts

## The actual publish (needs your PyPI account - this step is yours, not something that can be done for you)

You should already have the account and token from publishing 1.0.0/
1.0.1 - if so, skip to step 3.

1. PyPI account, if you don't have one: https://pypi.org/account/register/
2. API token: https://pypi.org/manage/account/token/ (scope it to this
   project, since it already exists on PyPI)
3. From the project root, rebuild fresh and upload:

```bash
rm -rf dist/ build/ *.egg-info
python3 -m build
python3 -m twine check dist/*
python3 -m twine upload dist/*
```

Twine prompts for a username and password - use `__token__` as the
username and your actual API token (starting with `pypi-`) as the
password.

4. Once live:

```bash
pip install husk-scanner
```

## Recommended: test on TestPyPI first

PyPI publishes are permanent - a version number can never be reused,
even after deleting a release. Worth a dry run on the test index,
especially for a release this much bigger than the last one:

```bash
python3 -m twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ husk-scanner
```

(Needs a separate TestPyPI account/token: https://test.pypi.org/account/register/)

## After publishing: the website backend needs a redeploy too

The website's backend (a separate repo, `husk-website/`) installs
`husk-scanner` as a normal PyPI dependency with no upper-version pin,
so once 1.1.0 is live, a plain redeploy (no code change needed there)
picks it up automatically on most platforms (Render, Railway) that
rebuild on every push. See `husk-website/README.md` for the full
deploy process - that repo's Dockerfile was also updated this session
to include Node.js, required for the new aggregator feature's real
ClawHub CLI calls to actually work in production, not just locally.
