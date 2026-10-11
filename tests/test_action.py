"""Static checks on the published GitHub Action (action/action.yml)."""
import re
from pathlib import Path

ACTION = Path(__file__).resolve().parent.parent / "action" / "action.yml"


def _run_blocks(text):
    """Yield the body of every `run:` script in the composite action."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)run:\s*(.*)$", line)
        if not m:
            continue
        indent, inline = len(m.group(1)), m.group(2)
        if inline and inline not in ("|", ">"):
            yield inline
            continue
        body = []
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            body.append(nxt)
        yield "\n".join(body)


def test_action_inputs_never_interpolated_into_shell():
    # ${{ inputs.* }} inside a run: script is expanded before bash parses it,
    # so a crafted input becomes shell code. Inputs must go through env:.
    scripts = list(_run_blocks(ACTION.read_text(encoding="utf-8")))
    assert scripts, "no run: steps found - parser out of sync with action.yml"
    for script in scripts:
        assert "${{" not in script, f"expression interpolated into a run: script:\n{script}"


def test_action_installs_husk_from_its_own_checkout():
    # Pinning the action to a tag/SHA must pin the scanner code too.
    text = ACTION.read_text(encoding="utf-8")
    assert '"$GITHUB_ACTION_PATH/.."' in text
    assert "pip install husk-scanner" not in text
