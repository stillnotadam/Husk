"""
Husk test suite - runs every fixture in tests/ against the scanner and
checks the expected verdict.

Fixtures are named so the expected result is obvious: files starting
with 'legit_' or 'normal_' should scan SAFE; everything else in tests/
(the evasion attempts, the real malicious samples used to build test
cases, etc.) should scan FLAGGED.

tests/known_misses/ is tested separately and marked xfail - these are
real attacks Husk currently misses (see BENCHMARK.md and ROADMAP.md for
the honest story). They stay in the suite, visibly failing, rather than
being quietly excluded, so the gap can't be accidentally "fixed" by
deletion and stays visible to CI.
"""

import glob
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.skill_scanner import scan_skill_file  # noqa: E402

FIXTURE_DIR = os.path.join(os.path.dirname(__file__))

SAFE_FIXTURES = sorted(glob.glob(os.path.join(FIXTURE_DIR, "legit_*.md"))) + \
    sorted(glob.glob(os.path.join(FIXTURE_DIR, "normal_*.md")))

FLAGGED_FIXTURES = sorted(
    f for f in glob.glob(os.path.join(FIXTURE_DIR, "*.md"))
    if f not in SAFE_FIXTURES
)

KNOWN_MISS_FIXTURES = sorted(glob.glob(os.path.join(FIXTURE_DIR, "known_misses", "*.md")))


@pytest.mark.parametrize("path", SAFE_FIXTURES, ids=[os.path.basename(p) for p in SAFE_FIXTURES])
def test_legitimate_files_stay_safe(path):
    result = scan_skill_file(path)
    assert result["verdict"] == "SAFE", (
        f"{os.path.basename(path)} should be SAFE but got FLAGGED: {result['findings']}"
    )


@pytest.mark.parametrize("path", FLAGGED_FIXTURES, ids=[os.path.basename(p) for p in FLAGGED_FIXTURES])
def test_malicious_patterns_get_flagged(path):
    result = scan_skill_file(path)
    assert result["verdict"] == "FLAGGED", (
        f"{os.path.basename(path)} should be FLAGGED but got SAFE - regression!"
    )


@pytest.mark.xfail(
    reason="Known limitation: novel/disguised attacks with no code or "
           "recognizable keywords. See BENCHMARK.md 'Honest limitation' "
           "section and ROADMAP.md Tier 2. Kept visible in CI on purpose.",
    strict=True,
)
@pytest.mark.parametrize("path", KNOWN_MISS_FIXTURES, ids=[os.path.basename(p) for p in KNOWN_MISS_FIXTURES])
def test_known_misses_are_still_missed(path):
    """
    If this test starts PASSING (i.e. Husk starts catching one of these),
    that's good news - move the fixture out of known_misses/ into the
    main flagged set and update BENCHMARK.md/README.md accordingly.
    strict=True means an unexpected pass fails CI, forcing that update
    rather than letting a real improvement go undocumented.
    """
    result = scan_skill_file(path)
    assert result["verdict"] == "FLAGGED", (
        f"{os.path.basename(path)} was expected to be missed (known limitation) "
        f"but got SAFE - this is actually the expected 'miss' outcome for xfail"
    )
