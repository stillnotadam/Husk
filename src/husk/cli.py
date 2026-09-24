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

from .aggregator import aggregate_skill_opinions
from .llm_review import (
    PACKAGE_SCANNABLE_EXTENSIONS,
    review_package_with_llm,
    review_skill_with_llm,
    review_with_consensus,
)
from .package_scanner import scan_package
from .pickle_scanner import scan_file as scan_pickle_file
from .reporting import apply_suppressions, write_sarif
from .sandbox import sandbox_run_script
from .skill_scanner import scan_skill_file
from .virustotal_check import check_package_against_virustotal


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
        provider_label = {
            "anthropic": "Claude", "gemini": "Gemini", "deepseek": "DeepSeek",
            "grok": "Grok", "kimi": "Kimi",
        }.get(args.llm_provider, args.llm_provider)
        print(f"--- Backup: LLM semantic review ({provider_label}, not Husk's own logic) ---")
        with open(args.path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        review = review_skill_with_llm(content, provider=args.llm_provider)
        if not review["available"]:
            print(f"  [skipped] {review['error']}\n")
        else:
            print(f"  {provider_label}'s verdict: {review['verdict']} (confidence: {review['confidence']})")
            print(f"  {provider_label}'s reasoning: {review['reasoning']}\n")
            if review["verdict"] == "SUSPICIOUS":
                exit_code = 1
    elif result["verdict"] == "SAFE":
        print("Note: static analysis found nothing, but it has real, documented limits")
        print("against attacks using no code or recognizable keywords (see BENCHMARK.md).")
        print("For extra assurance on a file you're unsure about, you can opt into a")
        print("backup LLM review: husk skill <path> --llm-review\n")

    return exit_code


def _consensus_review_package(package_path):
    """Runs multi-provider consensus review across every scannable file
    in a package, mirroring review_package_with_llm's own aggregation
    (SUSPICIOUS if any file's consensus verdict is SUSPICIOUS)."""
    per_file = {}
    any_available = False
    overall_verdict = None

    for dirpath, _, filenames in os.walk(package_path):
        for name in filenames:
            if not name.lower().endswith(PACKAGE_SCANNABLE_EXTENSIONS):
                continue
            full_path = os.path.join(dirpath, name)
            rel_path = os.path.relpath(full_path, package_path)
            try:
                with open(full_path, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError:
                continue
            result = review_with_consensus(content)
            per_file[rel_path] = result
            if result["available"]:
                any_available = True
                if result["verdict"] == "SUSPICIOUS":
                    overall_verdict = "SUSPICIOUS"

    if overall_verdict is None and any_available:
        overall_verdict = "SAFE"

    return {"available": any_available, "verdict": overall_verdict, "per_file": per_file}


def cmd_package(args):
    findings = scan_package(args.path)

    suppress_path = args.suppress or os.path.join(args.path, ".huskignore")
    findings, suppressed_count = apply_suppressions(findings, suppress_path)

    verdict = "FLAGGED" if findings else "SAFE"
    exit_code = _print_result(verdict, findings, "package")
    if suppressed_count:
        print(f"  ({suppressed_count} finding(s) suppressed via {os.path.basename(suppress_path)})\n")

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

    if args.virustotal:
        print("--- Backup: VirusTotal signature check (known-malware match, not Husk's own logic) ---")
        vt_findings, vt_results = check_package_against_virustotal(args.path)
        checked = [r for r in vt_results if r["available"]]
        if not checked:
            err = vt_results[0]["error"] if vt_results else "no files to check"
            print(f"  [skipped] {err}\n")
        else:
            if vt_findings:
                exit_code = 1
                for f in vt_findings:
                    print(f"  - {f}")
            else:
                print(f"  Checked {len(checked)} file(s) against VirusTotal - no known-malware signature matches.")
            print()

    if args.llm_review:
        provider_label = {
            "anthropic": "Claude", "gemini": "Gemini", "deepseek": "DeepSeek",
            "grok": "Grok", "kimi": "Kimi",
        }.get(args.llm_provider, args.llm_provider)

        if args.llm_consensus:
            print("--- Backup: multi-provider LLM consensus review (not Husk's own logic) ---")
        else:
            print(f"--- Backup: LLM semantic review ({provider_label}, not Husk's own logic) ---")
        print("  Real cost scaling, stated plainly: one API call per scannable file"
              + (", per provider queried" if args.llm_consensus else "") + ".\n")

        if args.llm_consensus:
            review = _consensus_review_package(args.path)
        else:
            review = review_package_with_llm(args.path, provider=args.llm_provider)

        if not review["available"]:
            print("  [skipped] No provider had a usable API key set - the static "
                  "scan result above is unaffected.\n")
        else:
            for rel_path, file_result in review["per_file"].items():
                if not file_result["available"]:
                    continue
                print(f"  {rel_path}: {file_result['verdict']}"
                      + (f" ({file_result.get('agreement')} agreement, "
                         f"{file_result.get('votes')})" if args.llm_consensus else
                         f" (confidence: {file_result.get('confidence')})"))
                if file_result["verdict"] == "SUSPICIOUS":
                    exit_code = 1
            print()
            if review["verdict"] == "SUSPICIOUS":
                exit_code = 1
    elif verdict == "SAFE":
        print("Note: static analysis found nothing, but it has real, documented limits")
        print("against attacks using no code or recognizable keywords (see BENCHMARK.md).")
        print("For extra assurance, you can opt into a backup LLM review:")
        print("husk package <path> --llm-review\n")

    if args.output:
        if args.output.endswith(".sarif"):
            write_sarif(findings, args.output, target_path=args.path)
            print(f"SARIF report written to: {args.output}\n")
        else:
            print(f"[skipped] --output only supports .sarif files right now, got: {args.output}\n")

    return exit_code


def cmd_aggregate(args):
    result = aggregate_skill_opinions(args.skill_ref, marketplace=args.marketplace, local_path=args.local)

    print(f"\nAggregate opinion for: {args.skill_ref} (marketplace: {result['marketplace']})")
    for source, opinion in result["opinions"].items():
        if opinion.get("available"):
            flag_word = "FLAGGED" if opinion.get("flagged") else "clear"
            print(f"  {source}: {flag_word} ({opinion.get('verdict', 'n/a')})")
        else:
            print(f"  {source}: unavailable ({opinion.get('error', 'no reason given')})")

    summary = result["summary"]
    print(f"\nSummary: {summary['flagged_by']}/{summary['total_sources']} sources flag "
          f"this, agreement: {summary['agreement']}\n")

    if summary["agreement"] in ("split", "majority_flagged"):
        return 1
    return 0


def cmd_model(args):
    result = scan_pickle_file(args.path)
    return _print_result(result["verdict"], result["findings"], "model")


def main():
    parser = argparse.ArgumentParser(
        prog="husk",
        description="Static security scanner for AI agent skill packages. "
                     "See https://github.com/ctrl-adam/Husk for the full "
                     "story, including honest limitations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_skill = subparsers.add_parser("skill", help="Scan a single skill file (e.g. SKILL.md)")
    p_skill.add_argument("path", help="Path to the skill file")
    p_skill.add_argument(
        "--llm-review", action="store_true",
        help="Opt-in second opinion from an LLM (requires an API key for "
             "whichever provider you pick with --llm-provider). Sends the "
             "file content to a third-party API and costs tokens - never "
             "runs unless you pass this flag. See README.md for why this "
             "exists and what it costs.",
    )
    p_skill.add_argument(
        "--llm-provider", default="anthropic",
        choices=["anthropic", "gemini", "deepseek", "grok", "kimi"],
        help="Which provider to use with --llm-review (default: anthropic, "
             "the primary, most-tested path this project is built around). "
             "Each needs its own env var: ANTHROPIC_API_KEY, GEMINI_API_KEY, "
             "DEEPSEEK_API_KEY, XAI_API_KEY, or MOONSHOT_API_KEY.",
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
    p_package.add_argument(
        "--virustotal", action="store_true",
        help="Opt-in: hashes each file in the package and checks it against "
             "VirusTotal's known-malware database (requires your own free "
             "VIRUSTOTAL_API_KEY, only the file's hash is sent, never its "
             "content). Catches a known-malware binary bundled in the "
             "package - something no static or LLM read of a skill's "
             "instructions can see, since it's not a code-pattern or "
             "language issue at all, just a byte-for-byte signature match.",
    )
    p_package.add_argument(
        "--suppress", metavar="PATH",
        help="Path to a suppression file (one rule ID per line, '#' comments "
             "allowed). Defaults to a '.huskignore' file inside the scanned "
             "package directory, if one exists - same convention as "
             ".gitignore. Run a scan once, read the findings, add the rule "
             "IDs you've reviewed and accepted to .huskignore, and future "
             "scans won't re-flag them.",
    )
    p_package.add_argument(
        "--output", metavar="PATH",
        help="Write a report to PATH. Currently supports .sarif (SARIF "
             "2.1.0), for GitHub Code Scanning and other SARIF-consuming CI "
             "tools - findings show up directly in a PR's Files Changed "
             "view and the repo's Security tab, not just a terminal log.",
    )
    p_package.add_argument(
        "--llm-review", action="store_true",
        help="Opt-in second opinion from an LLM, across EVERY scannable file "
             "in the package, not just SKILL.md (requires an API key for "
             "whichever provider you pick with --llm-provider). Real cost "
             "scaling: one API call per file. Never runs unless you pass "
             "this flag.",
    )
    p_package.add_argument(
        "--llm-provider", default="anthropic",
        choices=["anthropic", "gemini", "deepseek", "grok", "kimi"],
        help="Which provider to use with --llm-review (default: anthropic). "
             "Ignored if --llm-consensus is also set.",
    )
    p_package.add_argument(
        "--llm-consensus", action="store_true",
        help="With --llm-review: query every provider you have a key "
             "configured for (not just one) and report agreement, not a "
             "single model's opinion. Real cost scaling, stated plainly: "
             "one call per file PER PROVIDER queried.",
    )
    p_package.set_defaults(func=cmd_package)

    p_model = subparsers.add_parser("model", help="Scan a pickle-based model file")
    p_model.add_argument("path", help="Path to the model file")
    p_model.set_defaults(func=cmd_model)

    p_aggregate = subparsers.add_parser(
        "aggregate", help="Combine Husk's own verdict with other independent "
                          "auditors' published opinions on an already-listed "
                          "skill (early: most external sources aren't wired up "
                          "yet, see src/husk/aggregator.py)",
    )
    p_aggregate.add_argument("skill_ref", help="The skill's identifier (e.g. owner/skill-name)")
    p_aggregate.add_argument(
        "--local", metavar="PATH",
        help="Local path to the skill's SKILL.md, if you have it, so Husk's "
             "own scan actually runs. Without this, Husk's own opinion is "
             "reported as unavailable rather than skipped silently.",
    )
    p_aggregate.add_argument(
        "--marketplace", default="clawhub",
        choices=["clawhub", "skillssh", "agentskillsh"],
        help="Which marketplace to resolve skill_ref against (default: "
             "clawhub, the only one with a fully verified resolver right "
             "now - see src/husk/aggregator.py for real, current status).",
    )
    p_aggregate.set_defaults(func=cmd_aggregate)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
