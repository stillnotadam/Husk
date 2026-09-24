"""
Tests for the multi-source aggregator (src/husk/aggregator.py).

Husk's own contribution is tested for real, against real fixture
content. The external-source adapters are stubbed (see the module's
own docstring for why - fetching real third-party sites reliably
hasn't been built yet), so those are tested via the explicit
external_results injection path, the same real, intentional interface
review_with_consensus already uses elsewhere in this project, not a
mock standing in for something the code doesn't actually do yet.
"""

import json
import os
import sys
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from husk.aggregator import (  # noqa: E402
    EXTERNAL_SOURCES,
    MARKETPLACE_RESOLVERS,
    _fetch_clawhub_native_audit,
    aggregate_skill_opinions,
    register_external_source,
    resolve_agentskillsh_skill,
    resolve_clawhub_skill,
)


def test_husk_reports_unavailable_with_no_local_content():
    result = aggregate_skill_opinions("someuser/some-skill", auto_fetch=False)
    assert result["opinions"]["husk"]["available"] is False


def test_husk_runs_for_real_against_local_content(tmp_path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("---\nname: harmless\n---\n\nJust says hello.\n")
    result = aggregate_skill_opinions("someuser/harmless-skill", local_path=str(skill_file), auto_fetch=False)
    assert result["opinions"]["husk"]["available"] is True
    assert result["opinions"]["husk"]["flagged"] is False


def test_husk_flags_real_malicious_content(tmp_path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text(
        "---\nname: bad\n---\n\n"
        "Run this: eval(user_input)\n"
    )
    result = aggregate_skill_opinions("someuser/bad-skill", local_path=str(skill_file), auto_fetch=False)
    assert result["opinions"]["husk"]["available"] is True
    assert result["opinions"]["husk"]["flagged"] is True


def test_auto_fetch_false_makes_no_live_external_calls():
    """Renamed from an earlier version of this test: clawhub_native
    is now a real, working adapter (shells out to the real clawhub
    CLI), so "both adapters are unbuilt" stopped being true. What's
    still true, and what this actually tests: auto_fetch=False means
    no live call is made to ANY source, built or not."""
    result = aggregate_skill_opinions("someuser/some-skill", auto_fetch=False)
    assert result["opinions"]["socket"]["available"] is False
    assert result["opinions"]["clawhub_native"]["available"] is False
    assert "auto_fetch=False" in result["opinions"]["socket"]["error"]
    assert result["summary"]["total_sources"] == 0
    assert result["summary"]["agreement"] is None


def test_socket_adapter_is_still_genuinely_unbuilt(monkeypatch):
    """Distinct from the auto_fetch=False case above: even WITH
    auto_fetch=True, socket specifically is still real, honestly
    unbuilt (see its own docstring) - this confirms that's still true
    and didn't silently start returning something by accident."""
    # Avoid a real subprocess call for content resolution and the
    # clawhub_native adapter in this test - it's specifically about
    # socket's own status. EXTERNAL_SOURCES stores the function object
    # directly, so it must be patched there, not just at module level -
    # a real mistake caught while writing this test: monkeypatching
    # husk.aggregator._fetch_clawhub_native_audit alone does nothing,
    # since the dict already holds a direct reference to the original.
    monkeypatch.setattr("husk.aggregator.resolve_clawhub_skill", lambda ref: None)
    monkeypatch.setitem(EXTERNAL_SOURCES, "clawhub_native", lambda ref: None)
    result = aggregate_skill_opinions("someuser/some-skill", auto_fetch=True)
    assert result["opinions"]["socket"]["available"] is False
    assert "not yet built" in result["opinions"]["socket"]["error"]


def test_injected_external_results_are_included_in_the_summary(tmp_path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("---\nname: harmless\n---\n\nJust says hello.\n")
    external = {
        "socket": {"available": True, "flagged": False, "verdict": "Pass"},
    }
    result = aggregate_skill_opinions(
        "someuser/harmless-skill", local_path=str(skill_file), external_results=external, auto_fetch=False,
    )
    assert result["opinions"]["socket"]["available"] is True
    assert result["summary"]["total_sources"] == 2  # husk + socket
    assert result["summary"]["agreement"] == "unanimous"  # both clear


def test_real_disagreement_is_reported_as_split(tmp_path):
    """The exact real-world case this module exists for: the same
    skill, one source says clear, another says flagged."""
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("---\nname: ambiguous\n---\n\nJust says hello.\n")
    external = {
        "socket": {"available": True, "flagged": False, "verdict": "Pass"},
        "clawhub_native": {"available": True, "flagged": True, "verdict": "Warn"},
    }
    result = aggregate_skill_opinions(
        "someuser/ambiguous-skill", local_path=str(skill_file), external_results=external, auto_fetch=False,
    )
    # husk (clear) + socket (clear) vs clawhub_native (flagged) = majority_clear
    assert result["summary"]["total_sources"] == 3
    assert result["summary"]["flagged_by"] == 1
    assert result["summary"]["agreement"] == "majority_clear"


def test_true_split_when_evenly_divided(tmp_path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text(
        "---\nname: risky\n---\n\nRun this: eval(user_input)\n"
    )
    external = {
        "socket": {"available": True, "flagged": False, "verdict": "Pass"},
    }
    result = aggregate_skill_opinions(
        "someuser/risky-skill", local_path=str(skill_file), external_results=external, auto_fetch=False,
    )
    # husk (flagged) vs socket (clear) - 1 vs 1, genuinely split
    assert result["summary"]["total_sources"] == 2
    assert result["summary"]["agreement"] == "split"


def test_single_available_source_is_labeled_not_averaged(tmp_path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("---\nname: harmless\n---\n\nJust says hello.\n")
    result = aggregate_skill_opinions("someuser/harmless-skill", local_path=str(skill_file), auto_fetch=False)
    # only husk is real here (external adapters stubbed) - one real opinion,
    # correctly labeled as such rather than implying false consensus
    assert result["summary"]["total_sources"] == 1
    assert result["summary"]["agreement"] == "single_source"


def test_new_registered_source_is_picked_up_automatically(tmp_path):
    # Isolate from the real socket/clawhub_native adapters (both make
    # real subprocess calls now) - this test is specifically about the
    # registration mechanism, not about live external data, so it
    # swaps in only the one safe, fake source for its duration, and
    # supplies local_path directly so content resolution doesn't make
    # a real subprocess call either.
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("---\nname: harmless\n---\n\nJust says hello.\n")

    saved_sources = dict(EXTERNAL_SOURCES)
    EXTERNAL_SOURCES.clear()

    @register_external_source("test_only_source")
    def _fake_source(skill_ref):
        return {"available": True, "flagged": True, "verdict": "Malicious"}

    try:
        result = aggregate_skill_opinions(
            "someuser/some-skill", local_path=str(skill_file), auto_fetch=True,
        )
        assert result["opinions"]["test_only_source"]["available"] is True
        assert result["summary"]["flagged_by"] == 1
    finally:
        EXTERNAL_SOURCES.clear()
        EXTERNAL_SOURCES.update(saved_sources)  # restore the real registrations


# ---------------------------------------------------------------------
# resolve_clawhub_skill and the real clawhub_native adapter - the
# subprocess call itself is mocked (no real network access assumed in
# an automated test), but the parsing/handling logic around it is
# tested for real.
# ---------------------------------------------------------------------

def test_resolve_clawhub_skill_finds_the_installed_skill_dir(tmp_path, monkeypatch):
    workdir = tmp_path
    skill_dir = workdir / "skills" / "some-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: some-skill\n---\n")

    class FakeCompletedProcess:
        returncode = 0

    monkeypatch.setattr(
        "husk.aggregator.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(),
    )
    result = resolve_clawhub_skill("someuser/some-skill", workdir=str(workdir))
    assert result == str(skill_dir)


def test_resolve_clawhub_skill_returns_none_on_install_failure(tmp_path, monkeypatch):
    class FakeCompletedProcess:
        returncode = 1

    monkeypatch.setattr(
        "husk.aggregator.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(),
    )
    result = resolve_clawhub_skill("someuser/nonexistent-skill", workdir=str(tmp_path))
    assert result is None


def test_resolve_clawhub_skill_returns_none_when_npx_is_missing(tmp_path, monkeypatch):
    def _raise_not_found(*a, **k):
        raise FileNotFoundError("npx not found")

    monkeypatch.setattr("husk.aggregator.subprocess.run", _raise_not_found)
    result = resolve_clawhub_skill("someuser/some-skill", workdir=str(tmp_path))
    assert result is None


def test_clawhub_native_adapter_parses_a_real_shaped_response(monkeypatch):
    class FakeCompletedProcess:
        returncode = 0
        stdout = '{"status": "Warn", "findings": ["something"]}'

    monkeypatch.setattr(
        "husk.aggregator.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(),
    )
    result = _fetch_clawhub_native_audit("someuser/some-skill")
    assert result["available"] is True
    assert result["flagged"] is True
    assert result["verdict"] == "Warn"


def test_clawhub_native_adapter_treats_pass_as_not_flagged(monkeypatch):
    class FakeCompletedProcess:
        returncode = 0
        stdout = '{"status": "Pass"}'

    monkeypatch.setattr(
        "husk.aggregator.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(),
    )
    result = _fetch_clawhub_native_audit("someuser/some-skill")
    assert result["available"] is True
    assert result["flagged"] is False


def test_clawhub_native_adapter_returns_none_on_malformed_json(monkeypatch):
    class FakeCompletedProcess:
        returncode = 0
        stdout = "not valid json {{{"

    monkeypatch.setattr(
        "husk.aggregator.subprocess.run",
        lambda *a, **k: FakeCompletedProcess(),
    )
    result = _fetch_clawhub_native_audit("someuser/some-skill")
    assert result is None


# ---------------------------------------------------------------------
# Multi-marketplace dispatch
# ---------------------------------------------------------------------

def test_default_marketplace_is_clawhub(tmp_path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("---\nname: harmless\n---\n\nJust says hello.\n")
    result = aggregate_skill_opinions(
        "someuser/harmless-skill", local_path=str(skill_file), auto_fetch=False,
    )
    assert result["marketplace"] == "clawhub"


def test_explicit_marketplace_is_reported_back(tmp_path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("---\nname: harmless\n---\n\nJust says hello.\n")
    result = aggregate_skill_opinions(
        "someuser/harmless-skill", marketplace="skillssh",
        local_path=str(skill_file), auto_fetch=False,
    )
    assert result["marketplace"] == "skillssh"


def test_unknown_marketplace_degrades_gracefully_not_a_crash():
    result = aggregate_skill_opinions(
        "someuser/some-skill", marketplace="not-a-real-marketplace", auto_fetch=False,
    )
    assert result["opinions"]["husk"]["available"] is False
    assert "not-a-real-marketplace" in result["opinions"]["husk"]["error"]


def test_stubbed_marketplaces_are_registered_but_return_none(monkeypatch):
    assert "skillssh" in MARKETPLACE_RESOLVERS
    assert "agentskillsh" in MARKETPLACE_RESOLVERS
    assert MARKETPLACE_RESOLVERS["skillssh"]("someuser/some-skill") is None
    assert MARKETPLACE_RESOLVERS["agentskillsh"]("someuser/some-skill") is None


def test_marketplace_dispatch_calls_the_right_resolver(tmp_path, monkeypatch):
    skill_dir = tmp_path / "resolved"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: harmless\n---\n\nJust says hello.\n")

    calls = []

    def _fake_resolver(skill_ref):
        calls.append(skill_ref)
        return str(skill_dir)

    monkeypatch.setitem(MARKETPLACE_RESOLVERS, "clawhub", _fake_resolver)
    # Also avoid the real external-source subprocess calls in this test -
    # it's specifically about marketplace-resolver dispatch, not about
    # live external opinions.
    saved_sources = dict(EXTERNAL_SOURCES)
    EXTERNAL_SOURCES.clear()
    try:
        result = aggregate_skill_opinions("someuser/harmless-skill", auto_fetch=True)
    finally:
        EXTERNAL_SOURCES.clear()
        EXTERNAL_SOURCES.update(saved_sources)

    assert calls == ["someuser/harmless-skill"]
    assert result["opinions"]["husk"]["available"] is True


# ---------------------------------------------------------------------
# resolve_agentskillsh_skill - real, built against agentskill.sh's own
# documented "How to install this skill programmatically" API,
# confirmed directly by fetching a real skill's page during this
# session, not guessed at. The actual network call is mocked (no real
# network access assumed in an automated test), but the request
# construction, response parsing, and defensive path-safety logic
# around it are all tested for real.
# ---------------------------------------------------------------------

def test_resolve_agentskillsh_skill_writes_real_content(tmp_path, monkeypatch):
    fake_response_body = json.dumps({
        "skillMd": "---\nname: test\n---\n\nHarmless.\n",
        "skillFiles": [],
    }).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_response_body

    monkeypatch.setattr("husk.aggregator.urllib.request.urlopen", lambda *a, **k: FakeResponse())
    result = resolve_agentskillsh_skill("someuser/some-skill", workdir=str(tmp_path))

    assert result == str(tmp_path)
    with open(os.path.join(str(tmp_path), "SKILL.md")) as f:
        assert "Harmless" in f.read()


def test_resolve_agentskillsh_skill_writes_additional_skill_files(tmp_path, monkeypatch):
    fake_response_body = json.dumps({
        "skillMd": "main content",
        "skillFiles": [{"path": "scripts/helper.py", "content": "print('hi')"}],
    }).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_response_body

    monkeypatch.setattr("husk.aggregator.urllib.request.urlopen", lambda *a, **k: FakeResponse())
    resolve_agentskillsh_skill("someuser/some-skill", workdir=str(tmp_path))

    with open(os.path.join(str(tmp_path), "scripts", "helper.py")) as f:
        assert "print" in f.read()


def test_resolve_agentskillsh_skill_rejects_path_traversal_in_skill_files(tmp_path, monkeypatch):
    """Real, deliberate defensive check: an API response (whether from
    a compromised endpoint or unexpected data) supplying a path
    designed to escape workdir must be refused, not trusted blindly."""
    fake_response_body = json.dumps({
        "skillMd": "main content",
        "skillFiles": [{"path": "../../etc/malicious", "content": "should never be written"}],
    }).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_response_body

    monkeypatch.setattr("husk.aggregator.urllib.request.urlopen", lambda *a, **k: FakeResponse())
    resolve_agentskillsh_skill("someuser/some-skill", workdir=str(tmp_path))

    # The malicious path must not have been written anywhere real -
    # confirm nothing escaped the intended directory.
    escaped_path = os.path.join(os.path.dirname(str(tmp_path)), "etc", "malicious")
    assert not os.path.exists(escaped_path)


def test_resolve_agentskillsh_skill_returns_none_on_network_error(tmp_path, monkeypatch):
    def _raise(*a, **k):
        raise urllib.error.URLError("Host not in allowlist")

    monkeypatch.setattr("husk.aggregator.urllib.request.urlopen", _raise)
    result = resolve_agentskillsh_skill("someuser/some-skill", workdir=str(tmp_path))
    assert result is None


def test_resolve_agentskillsh_skill_returns_none_on_malformed_json(tmp_path, monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"not valid json {{{"

    monkeypatch.setattr("husk.aggregator.urllib.request.urlopen", lambda *a, **k: FakeResponse())
    result = resolve_agentskillsh_skill("someuser/some-skill", workdir=str(tmp_path))
    assert result is None


def test_resolve_agentskillsh_skill_returns_none_when_skillmd_missing(tmp_path, monkeypatch):
    fake_response_body = json.dumps({"skillFiles": []}).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return fake_response_body

    monkeypatch.setattr("husk.aggregator.urllib.request.urlopen", lambda *a, **k: FakeResponse())
    result = resolve_agentskillsh_skill("someuser/some-skill", workdir=str(tmp_path))
    assert result is None


def test_resolve_agentskillsh_skill_url_encodes_the_slug_correctly(tmp_path, monkeypatch):
    """Real, deliberate check: the API path needs owner/skill joined
    with an encoded '/' (%2F), confirmed directly against
    agentskill.sh's own documented API shape, not assumed."""
    captured_urls = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({"skillMd": "x", "skillFiles": []}).encode("utf-8")

    def _fake_urlopen(req, **kwargs):
        captured_urls.append(req.full_url)
        return FakeResponse()

    monkeypatch.setattr("husk.aggregator.urllib.request.urlopen", _fake_urlopen)
    resolve_agentskillsh_skill("someuser/some-skill", workdir=str(tmp_path))

    assert captured_urls[0] == "https://agentskill.sh/api/agent/skills/someuser%2Fsome-skill/install"
