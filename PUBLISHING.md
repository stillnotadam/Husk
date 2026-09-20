# Publishing husk-scanner to PyPI

Everything up through building and validating the package is done.
The one remaining step needs your own PyPI account - not something I
have or should have credentials for.

## What's already done and verified

- `pyproject.toml` is complete: real metadata, keywords, classifiers,
  modern SPDX license format (fixed a deprecation warning), an MIT
  `LICENSE` file present
- Built both distributions: `husk_scanner-0.1.0.tar.gz` (sdist) and
  `husk_scanner-0.1.0-py3-none-any.whl` (wheel)
- Both pass `twine check` (PyPI's own metadata validator)
- Installed the built wheel into a completely clean, fresh virtual
  environment (no dependency on this project's dev setup) and
  confirmed the `husk` CLI actually works end-to-end: help text
  correct, a clean skill scans SAFE (exit code 0), a malicious one
  scans FLAGGED (exit code 1)
- Confirmed `husk-scanner` (the package name) appears genuinely
  available on PyPI - the bare name `husk` is taken by an unrelated
  Cornell-notes tool, but `husk-scanner` returned nothing
- `dist/` and `build/` added to `.gitignore` - always rebuild fresh
  at release time, don't commit stale artifacts

## One thing to fix first: your real GitHub username

Three files still have the placeholder `YOUR-USERNAME` in URLs
(`pyproject.toml`, `README.md`, `src/husk/cli.py`'s help text) - I
don't know your real GitHub username, so I left it as a placeholder
rather than guess. Give me the real one and I'll do a clean find-and-
replace across all of them before you publish, or you can do it
yourself with:

```bash
grep -rl "YOUR-USERNAME" --include="*.py" --include="*.toml" --include="*.md" . | xargs sed -i 's/YOUR-USERNAME/your-real-username/g'
```

## The actual publish (needs your PyPI account)

1. Create a PyPI account if you don't have one: https://pypi.org/account/register/
2. Create an API token: https://pypi.org/manage/account/token/
   (scope it to this project once it exists, or "entire account" for
   the very first upload since the project doesn't exist yet)
3. From the project root, rebuild fresh and upload:

```bash
rm -rf dist/ build/ *.egg-info
python3 -m build
python3 -m twine check dist/*
python3 -m twine upload dist/*
```

Twine will prompt for a username and password - use `__token__` as
the username and your actual API token (starting with `pypi-`) as the
password.

4. Once live, anyone can install it with:

```bash
pip install husk-scanner
```

## Recommended: test on TestPyPI first

PyPI publishes are permanent - you can't reuse a version number even
if you delete a release. Worth a dry run on the test index first:

```bash
python3 -m twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ husk-scanner
```

(Needs a separate TestPyPI account/token: https://test.pypi.org/account/register/)
