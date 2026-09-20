"""
Husk CLI - entry point installed as `husk` after `pip install`.

Usage:
    husk skill path/to/SKILL.md          Scan a single skill file
    husk package path/to/skill_dir/      Scan a whole skill package/directory
    husk model path/to/model.pkl         Scan a pickle-based model file
"""

import argparse
import glob
import os
import sys

from .llm_review import review_skill_with_llm
from .package_scanner import scan_package
from .pickle_scanner import scan_file as scan_pickle_file
from .sandbox import sandbox_run_script
from .skill_scanner import scan_skill_file


def _print_result(verdict, findings, label):
    print(f"\nHusk {label} scan result: {verdict}")
    for f in findings:
        print(f"  - {f}")
    print()
    return 0 if verdict in ("SAFE", "INFO") else 1


def cmd_skill(args):
    result = scan_skill_file(args.path)
    exit_code = _print_result(result["verdict"], result["findings"], "skill")

    if args.llm_review:
        print("--- Backup: LLM semantic review (Anthropic Claude, not Husk's own logic) ---")
        with open(args.path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        review = review_skill_with_llm(content)
        if not review["available"]:
            print(f"  [skipped] {review['error']}\n")
        else:
            print(f"  Claude's verdict: {review['verdict']} (confidence: {review['confidence']})")
            print(f"  Claude's reasoning: {review['reasoning']}\n")
            if review["verdict"] == "SUSPICIOUS":
                exit_code = 1
    elif result["verdict"] == "SAFE":
        print("Note: static analysis found nothing, but it has real, documented limits")
        print("against attacks using no code or recognizable keywords (see BENCHMARK.md).")
        print("For extra assurance on a file you're unsure about, you can opt into a")
        print("backup LLM review: husk skill <path> --llm-review\n")

    return exit_code


def cmd_package(args):
    findings = scan_package(args.path)
    verdict = "FLAGGED" if findings else "SAFE"
    exit_code = _print_result(verdict, findings, "package")

    if args.sandbox:
        print("--- Basic dynamic sandbox (actually RUNS scripts - Python/JS/shell/Ruby/Rust/Go - see README.md for real limits) ---")
        scripts = []
        for ext in ("*.py", "*.js", "*.sh", "*.rb", "*.rs", "*.go"):
            scripts += glob.glob(os.path.join(args.path, "**", ext), recursive=True)
        if not scripts:
            print("  No sandboxable scripts (Python/JS/shell/Ruby/Rust/Go) found.\n")
        for script in scripts:
            print(f"  Running: {os.path.relpath(script, args.path)}")
            result = sandbox_run_script(script)
            if result["findings"]:
                exit_code = 1
                for f in result["findings"]:
                    print(f"    - {f}")
            else:
                print("    - No unexpected behavior observed (see README.md - this is not a safety guarantee).")
        print()

    return exit_code


def cmd_model(args):
    result = scan_pickle_file(args.path)
    return _print_result(result["verdict"], result["findings"], "model")


def main():
    parser = argparse.ArgumentParser(
        prog="husk",
        description="Static security scanner for AI agent skill packages. "
                     "See https://github.com/YOUR-USERNAME/husk for the full "
                     "story, including honest limitations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_skill = subparsers.add_parser("skill", help="Scan a single skill file (e.g. SKILL.md)")
    p_skill.add_argument("path", help="Path to the skill file")
    p_skill.add_argument(
        "--llm-review", action="store_true",
        help="Opt-in second opinion from an LLM (requires ANTHROPIC_API_KEY). "
             "Sends the file content to a third-party API and costs tokens - "
             "never runs unless you pass this flag. See README.md for why "
             "this exists and what it costs.",
    )
    p_skill.set_defaults(func=cmd_skill)

    p_package = subparsers.add_parser("package", help="Scan a whole skill package/directory")
    p_package.add_argument("path", help="Path to the skill package directory")
    p_package.add_argument(
        "--sandbox", action="store_true",
        help="Opt-in: ACTUALLY RUNS the package's scripts (Python, "
             "JavaScript, shell) in a "
             "restricted, observed environment (timeout, CPU/memory limits, "
             "filesystem-diff observation) to catch logic-bomb/delayed-"
             "activation behavior no static or LLM read can see. This is a "
             "BASIC sandbox, not OS-level isolation - read README.md's real "
             "limits before relying on it, and only run this where network "
             "egress is already restricted.",
    )
    p_package.set_defaults(func=cmd_package)

    p_model = subparsers.add_parser("model", help="Scan a pickle-based model file")
    p_model.add_argument("path", help="Path to the model file")
    p_model.set_defaults(func=cmd_model)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
