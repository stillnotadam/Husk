# Releasing Husk (manual)

In PowerShell, from the Husk folder:

1. Check the version is right (both must say the new version):
   ```
   Select-String -Path pyproject.toml, src\husk\__init__.py -Pattern 'version'
   ```
2. Clear old build output (stale files here caused the husk-0.0.0 upload error once):
   ```
   Remove-Item dist, build, src\*.egg-info -Recurse -Force -ErrorAction SilentlyContinue
   ```
3. Build, then look before uploading:
   ```
   python -m build
   Get-ChildItem dist
   ```
   Exactly two files, both `husk_scanner-X.Y.Z...`. Anything named `husk-0.0.0` means
   pyproject.toml is wrong - stop.
4. Upload (username `__token__`, password your `pypi-...` token):
   ```
   python -m twine upload dist/*
   ```
5. Commit, push and tag:
   ```
   git add -A
   git commit -m "X.Y.Z"
   git push
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

CI (`.github/workflows/ci.yml`) runs lint, type checks and the tests on Python 3.9-3.13
on every push, so check it's green on GitHub after pushing.
