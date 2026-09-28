"""
Husk CLI - entry point installed as `husk` after `pip install`.

Usage:
    husk skill path/to/SKILL.md          Scan a single skill file
    husk package path/to/skill_dir/      Scan a whole skill package/directory
    husk model path/to/model.pkl         Scan a pickle-based model file
"""

import argparse
import glob
import json
import os
import sys

from husk import __version__ as HUSK_VERSION

from .aggregator import aggregate_skill_opinions
from .attestation import (
    build_attestation,
    now_timestamp,
    verify_attestation,
)
from .badge import badge_html, badge_markdown
from .crossref import crossref_skill
from .gate import evaluate as gate_evaluate
from .gate import load_policy
from .js_taint_analysis import analyze_js_taint
from .llm_review import (
    PACKAGE_SCANNABLE_EXTENSIONS,
    review_package_with_llm,
    review_skill_with_llm,
    review_with_consensus,
)
from .package_scanner import scan_package
from .pickle_scanner import scan_file as scan_pickle_file
from .registry_store import connect as reg_connect
from .registry_store import ingest_results_file, top_flagged
from .registry_store import lookup as reg_lookup
from .registry_store import stats as reg_stats
from .reporting import apply_suppressions, write_sarif
from .sandbox import sandbox_run_script
from .scan_cache import scan_many
from .skill_scanner import scan_skill_file
from .taint_analysis import analyze_taint_flows
from .virustotal_check import check_package_against_virustotal
from .watch import watch as watch_skills


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
    if result.get("source_url"):
        print(f"  Listing: {result['source_url']}")
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


def cmd_gate(args):
    """Pre-publish gate: one deterministic pass/warn/fail decision.

    This is the command a skill author runs before publishing, and the
    one a registry can run in CI on every push - offline, instant, no
    API cost, no secrets. It reuses the exact same static scan as
    `husk package`, then applies a severity policy (tunable via a
    .huskpolicy file in the package) to decide whether the package is fit
    to publish."""
    if not os.path.isdir(args.path):
        print(f"husk gate expects a package directory, got: {args.path}", file=sys.stderr)
        return 2

    findings = scan_package(args.path)
    suppress_path = args.suppress or os.path.join(args.path, ".huskignore")
    findings, suppressed_count = apply_suppressions(findings, suppress_path)

    policy, policy_error = load_policy(args.path)
    if args.block_on:
        policy["block_on"] = args.block_on
    result = gate_evaluate(findings, policy)

    if args.json:
        print(json.dumps({
            "path": args.path,
            "decision": result["decision"],
            "policy": {"block_on": policy["block_on"], "warn_on": policy["warn_on"]},
            "counts": result["counts"],
            "blocking": result["blocking"],
            "warnings": result["warnings"],
            "info": result["info"],
            "suppressed": suppressed_count,
        }, indent=2))
        return 0 if result["decision"] != "fail" else 1

    decision = result["decision"]
    badge = {"pass": "PASS", "warn": "PASS (with warnings)", "fail": "FAIL"}[decision]
    print(f"\nHusk gate: {badge}")
    c = result["counts"]
    print(f"  {c['critical']} critical, {c['high']} high, {c['medium']} medium, "
          f"{c['low']} low, {c['info']} info"
          + (f"  ({suppressed_count} suppressed)" if suppressed_count else ""))
    print(f"  Policy: block at '{policy['block_on']}' and above"
          + (f"  [{policy_error}]" if policy_error else ""))

    if result["blocking"]:
        print("\n  Blocking (must fix before publishing):")
        for e in result["blocking"]:
            print(f"    [{e['severity']}] {e['finding']}")
    if result["warnings"]:
        print("\n  Warnings (allowed, but worth a look):")
        for e in result["warnings"][:20]:
            print(f"    [{e['severity']}] {e['finding']}")
        if len(result["warnings"]) > 20:
            print(f"    ... and {len(result['warnings']) - 20} more")

    if decision == "fail":
        print("\nThis package would be BLOCKED. Fix the findings above, or, if a "
              "finding is a\nreviewed false positive, add its rule to .huskignore "
              "or tune .huskpolicy.\n")
    elif decision == "warn":
        print("\nThis package PASSES the gate. The warnings above did not meet the "
              "blocking\nthreshold, but are worth reviewing.\n")
    else:
        print("\nThis package PASSES the gate cleanly.\n")
    return 0 if decision != "fail" else 1


def cmd_attest(args):
    """Produce a deterministic, standards-compliant attestation of a scan.

    Emits an in-toto Statement v1 (SLSA-style verification summary) binding
    the skill's content digest to Husk's verdict and ruleset digest. The
    thing an AI review cannot give: reproducible, offline-verifiable proof of
    what was scanned and what the result was."""
    if not os.path.isdir(args.path):
        print(f"husk attest expects a package directory, got: {args.path}", file=sys.stderr)
        return 2

    findings = scan_package(args.path)
    policy, _ = load_policy(args.path)
    timestamp = None if args.no_timestamp else now_timestamp()
    statement = build_attestation(
        args.path, findings, policy=policy, skill_ref=args.name, timestamp=timestamp,
    )

    if args.sign:
        from .attestation_signing import sign_statement  # noqa: PLC0415 - optional dep
        signed, error = sign_statement(statement, staging=args.staging)
        if error:
            print(f"Signing failed: {error}", file=sys.stderr)
            return 1
        output = json.dumps(signed, indent=2)
    else:
        output = json.dumps(statement, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        pred = statement["predicate"]
        print(f"Attestation written to {args.output}")
        print(f"  subject sha256: {statement['subject'][0]['digest']['sha256']}")
        print(f"  verdict: {pred['verdict']} ({pred['verificationResult']})")
        print(f"  ruleset sha256: {pred['scanner']['rulesetDigest']['sha256'][:16]}...")
    else:
        print(output)
    return 0 if statement["predicate"]["verificationResult"] == "PASSED" else 1


def cmd_verify_attestation(args):
    """Check a claimed attestation against the skill on disk, offline.

    Re-derives the skill's content digest and the ruleset digest and confirms
    the attestation really describes THIS skill with THIS ruleset - no network,
    no trust in whoever produced it."""
    if not os.path.isdir(args.path):
        print(f"husk verify-attestation expects a package directory, got: {args.path}", file=sys.stderr)
        return 2
    try:
        with open(args.attestation, encoding="utf-8") as fh:
            statement = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"Could not read attestation: {exc}", file=sys.stderr)
        return 2

    # If it's a signed DSSE envelope, unwrap the payload for content checks.
    if "payload" in statement and "payloadType" in statement:
        import base64  # noqa: PLC0415
        try:
            statement = json.loads(base64.b64decode(statement["payload"]))
        except Exception as exc:  # noqa: BLE001
            print(f"Could not decode signed envelope payload: {exc}", file=sys.stderr)
            return 2

    result = verify_attestation(args.path, statement)
    print("\nHusk attestation verification")
    print(f"  subject digest: {'MATCH' if result['subject_match'] else 'MISMATCH'}")
    if result.get("ruleset_match") is not None:
        print(f"  ruleset digest: {'MATCH' if result['ruleset_match'] else 'DIFFERENT (verdict may differ if re-run)'}")
    for err in result["errors"]:
        print(f"  - {err}")
    if result["subject_match"]:
        pred = statement.get("predicate", {})
        print("\nThis attestation genuinely describes the skill on disk.")
        print(f"  Recorded verdict: {pred.get('verdict', '?')} ({pred.get('verificationResult', '?')})")
        return 0
    print("\nThis attestation does NOT match the skill on disk.")
    return 1


def cmd_crossref(args):
    """Cross-marketplace verification: fetch the same skill from every
    marketplace, digest and scan each, and flag divergence. Husk as the
    neutral layer above any single registry - catches a skill that is benign
    on the registry a reviewer checked and malicious on the one a user
    installs from."""
    marketplaces = args.marketplace or None
    result = crossref_skill(args.skill_ref, marketplaces=marketplaces)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["verdict_agreement"] != "disagree" and result["content_agreement"] != "divergent" else 1

    print(f"\nHusk cross-marketplace check: {args.skill_ref}")
    for name, r in result["marketplaces"].items():
        if r["available"]:
            print(f"  {name}: {r['verdict']}  (content {r['content_digest'][:12]}, "
                  f"{r['finding_count']} finding(s))")
        else:
            print(f"  {name}: unavailable - {r['error']}")
    if result["alerts"]:
        print()
        for a in result["alerts"]:
            print(f"  {a}")
    else:
        print("\n  No cross-marketplace data to compare (need 2+ resolvable registries).")
    print()
    divergent = result["content_agreement"] == "divergent" or result["verdict_agreement"] == "disagree"
    return 1 if divergent else 0


def cmd_watch(args):
    """Re-scan installed skills against a stored baseline and alert on
    changes - especially a skill that was SAFE at install and is FLAGGED now
    (a malicious update). The time dimension no point-in-time scan covers."""
    report = watch_skills(
        paths=args.path or None,
        roots=args.root or None,
        baseline_path=args.baseline,
        update=not args.no_update,
    )
    if args.json:
        print(json.dumps(report, indent=2))
        return 1 if report["newly_flagged"] else 0

    print(f"\nHusk watch: checked {report['checked']} skill(s)")
    if report["new"]:
        print(f"  {len(report['new'])} new (now baselined):")
        for n in report["new"][:20]:
            print(f"    + {os.path.basename(n['path'])}: {n['verdict']}")
    print(f"  {report['unchanged']} unchanged")
    if report["changed"]:
        print(f"  {len(report['changed'])} changed:")
    if report["alerts"]:
        print()
        for a in report["alerts"]:
            print(f"  {a}")
    if report["newly_flagged"]:
        print(f"\n{len(report['newly_flagged'])} skill(s) turned malicious since you last checked. Review them now.\n")
        return 1
    if not report["new"] and not report["changed"]:
        print("\n  Nothing changed since the last check.\n")
    else:
        print()
    return 0


def cmd_explain(args):
    """Show explainable data-flow traces for a file or package: the exact
    source -> variable -> sink path behind each taint finding. The 'why' a
    security reviewer trusts over a bare verdict - and something an LLM review
    cannot produce deterministically."""
    targets = []
    if os.path.isfile(args.path):
        targets = [args.path]
    elif os.path.isdir(args.path):
        for dp, _dirs, files in os.walk(args.path):
            for fn in files:
                if fn.lower().endswith((".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")):
                    targets.append(os.path.join(dp, fn))
    else:
        print(f"husk explain expects a file or directory, got: {args.path}", file=sys.stderr)
        return 2

    all_traces = []
    for path in sorted(targets):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                code = fh.read()
        except OSError:
            continue
        analyzer = (analyze_js_taint if path.lower().endswith(
            (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")) else analyze_taint_flows)
        for finding in analyzer(code):
            rel = os.path.relpath(path, args.path) if os.path.isdir(args.path) else path
            all_traces.append((rel, finding))

    if args.json:
        print(json.dumps([
            {"file": rel, **finding.to_dict()} for rel, finding in all_traces
        ], indent=2))
        return 1 if all_traces else 0

    if not all_traces:
        print("\nNo data-flow (taint) findings to explain in this target.\n")
        return 0

    print(f"\nHusk data-flow traces ({len(all_traces)} flow(s)):\n")
    for rel, finding in all_traces:
        print(f"  {rel}:")
        for step in finding.trace():
            print(f"    {step}")
        print()
    print("Each trace is a real source->variable->sink path found by AST analysis, "
          "not text matching.\n")
    return 1


def cmd_registry(args):
    """Scan many skills incrementally with a content-addressed cache - the
    registry-scale entry point. On a repeat sweep only new or changed skills
    are actually scanned, so a full re-scan of thousands of skills is fast."""
    skills = []
    for raw_root in args.path:
        root = os.path.expanduser(raw_root)
        if not os.path.isdir(root):
            continue
        if any(n.lower() == "skill.md" for n in os.listdir(root)):
            skills.append(root)
            continue
        for entry in sorted(os.listdir(root)):
            full = os.path.join(root, entry)
            if os.path.isdir(full) and any(n.lower() == "skill.md" for n in os.listdir(full)):
                skills.append(full)
    if not skills:
        print("No skills found (need directories containing a SKILL.md).", file=sys.stderr)
        return 2

    def _progress(done, total, path, cached):
        if not args.json and (cached is False or done == total):
            print(f"  [{done}/{total}] {os.path.basename(path)}"
                  + ("" if not cached else " (cached)"))
    results = scan_many(skills, cache_path=args.cache, progress=_progress)

    flagged = {p: r for p, r in results.items() if r["findings"]}
    cached_n = sum(1 for r in results.values() if r["cached"])
    if args.json:
        print(json.dumps({
            "scanned": len(results),
            "from_cache": cached_n,
            "flagged": {os.path.basename(p): len(r["findings"]) for p, r in flagged.items()},
        }, indent=2))
        return 1 if flagged else 0

    print(f"\nHusk registry scan: {len(results)} skills "
          f"({cached_n} from cache, {len(results) - cached_n} freshly scanned)")
    if flagged:
        print(f"\n  {len(flagged)} FLAGGED:")
        for p in sorted(flagged):
            print(f"    {os.path.basename(p)}: {len(flagged[p]['findings'])} finding(s)")
        print()
        return 1
    print("\n  All clean.\n")
    return 0


def cmd_registry_ingest(args):
    """Ingest an ecosystem scan's results.jsonl into the trust registry, then
    print a summary. Turns a one-off scan into persistent, queryable history."""
    conn = reg_connect(args.db)
    summary = ingest_results_file(conn, args.results, source=args.source, husk_version=HUSK_VERSION)
    print(f"Ingested {args.results}: {summary}")
    st = reg_stats(conn)
    print(f"Registry now holds {st['skills']} skills - "
          f"{st['fail']} fail, {st['warn']} warn, {st['pass']} pass, "
          f"{st['security_tools']} security tools, {st['turned_malicious']} turned malicious.")
    return 0


def cmd_registry_lookup(args):
    """Look up a skill in the trust registry: 'is this skill safe?'"""
    conn = reg_connect(args.db)
    if args.top:
        for r in top_flagged(conn, limit=args.top):
            print(f"  {r['latest_verdict']:5} score={r['latest_score']:6} {r['ref']}")
        return 0
    r = reg_lookup(conn, args.ref)
    if r is None:
        print(f"'{args.ref}' is not in the registry (never scanned).")
        return 2
    print(json.dumps(r, indent=2))
    return 1 if r["verdict"] == "fail" else 0


def cmd_badge(args):
    """Print the README snippet for a live, verifiable Husk trust badge.

    The badge image reflects the skill's CURRENT registry verdict (a malicious
    update flips it to FAIL automatically), and it links to the skill's
    verifiable registry record. The trust primitive skills display to prove
    they passed."""
    ref = args.ref.strip()
    base = args.registry.rstrip("/")
    if args.html:
        print(badge_html(ref, base))
    else:
        print(badge_markdown(ref, base))
    if not args.quiet:
        print("\nPaste that into your README. The badge stays live - it shows "
              "your skill's current Husk verdict and links to its verifiable "
              "registry record.", file=sys.stderr)
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

    p_gate = subparsers.add_parser(
        "gate",
        help="Pre-publish gate: one deterministic PASS/FAIL decision for a "
             "skill package. Offline, instant, no API cost - the check to run "
             "before publishing and in CI on every push.",
    )
    p_gate.add_argument("path", help="Path to the skill package directory")
    p_gate.add_argument(
        "--block-on", choices=["critical", "high", "medium", "low"],
        help="Block (FAIL) on this severity and above. Overrides any "
             ".huskpolicy in the package. Default: high.",
    )
    p_gate.add_argument(
        "--suppress", metavar="PATH",
        help="Suppression file (defaults to .huskignore in the package), "
             "same convention as husk package.",
    )
    p_gate.add_argument(
        "--json", action="store_true",
        help="Emit the full decision as JSON (for CI to parse) instead of "
             "the human-readable summary.",
    )
    p_gate.set_defaults(func=cmd_gate)

    p_attest = subparsers.add_parser(
        "attest",
        help="Produce a deterministic, standards-compliant attestation "
             "(in-toto Statement v1) of a skill scan - reproducible, "
             "offline-verifiable proof of what was scanned and the verdict.",
    )
    p_attest.add_argument("path", help="Path to the skill package directory")
    p_attest.add_argument("--output", metavar="PATH", help="Write the attestation JSON to PATH (default: stdout)")
    p_attest.add_argument("--name", metavar="REF", help="Subject name for the attestation (e.g. owner/skill-name)")
    p_attest.add_argument("--no-timestamp", action="store_true",
                          help="Omit verifiedAt, for a fully byte-reproducible attestation")
    p_attest.add_argument("--sign", action="store_true",
                          help="Sign the statement with Sigstore keyless (needs the 'sigstore' extra)")
    p_attest.add_argument("--staging", action="store_true", help="Use Sigstore staging (testing only)")
    p_attest.set_defaults(func=cmd_attest)

    p_verify = subparsers.add_parser(
        "verify-attestation",
        help="Check a claimed attestation against the skill on disk, offline - "
             "confirm it really describes THIS skill and ruleset.",
    )
    p_verify.add_argument("path", help="Path to the skill package directory")
    p_verify.add_argument("attestation", help="Path to the attestation JSON file")
    p_verify.set_defaults(func=cmd_verify_attestation)

    p_crossref = subparsers.add_parser(
        "crossref",
        help="Cross-marketplace verification: fetch the same skill from every "
             "registry, compare content digests and verdicts, and flag a "
             "registry serving different or more-dangerous content under the "
             "same name (a supply-chain substitution attack).",
    )
    p_crossref.add_argument("skill_ref", help="Skill reference, e.g. owner/skill-name")
    p_crossref.add_argument("--marketplace", action="append",
                            help="Restrict to specific marketplaces (repeatable). "
                                 "Default: every registered marketplace.")
    p_crossref.add_argument("--json", action="store_true", help="Emit the full result as JSON")
    p_crossref.set_defaults(func=cmd_crossref)

    p_watch = subparsers.add_parser(
        "watch",
        help="Re-scan installed skills against a saved baseline and alert when "
             "one changes - especially a skill that was safe at install and is "
             "flagged now (a malicious update). Run it on a schedule.",
    )
    p_watch.add_argument("path", nargs="*", help="Specific skill directories to watch (default: auto-discover)")
    p_watch.add_argument("--root", action="append",
                         help="Directory to auto-discover skills under (repeatable). "
                              "Default: common agent skill locations.")
    p_watch.add_argument("--baseline", metavar="PATH", help="Baseline file (default: ~/.husk/watch.json)")
    p_watch.add_argument("--no-update", action="store_true",
                         help="Don't update the baseline (report changes without accepting them)")
    p_watch.add_argument("--json", action="store_true", help="Emit the full report as JSON")
    p_watch.set_defaults(func=cmd_watch)

    p_explain = subparsers.add_parser(
        "explain",
        help="Show explainable data-flow traces (source -> variable -> sink) "
             "behind taint findings - the auditable 'why' an AI review can't "
             "produce deterministically.",
    )
    p_explain.add_argument("path", help="A .py file or a package directory")
    p_explain.add_argument("--json", action="store_true", help="Emit structured traces as JSON")
    p_explain.set_defaults(func=cmd_explain)

    p_registry = subparsers.add_parser(
        "registry",
        help="Scan many skills at once with an incremental content-addressed "
             "cache - only new or changed skills are re-scanned. For scanning "
             "a whole registry or skills directory efficiently.",
    )
    p_registry.add_argument("path", nargs="+", help="Directories to scan (each a skill, or a parent of skills)")
    p_registry.add_argument("--cache", metavar="PATH", help="Cache file (default: ~/.husk/scan-cache.json)")
    p_registry.add_argument("--json", action="store_true", help="Emit results as JSON")
    p_registry.set_defaults(func=cmd_registry)

    p_ingest = subparsers.add_parser(
        "registry-ingest",
        help="Ingest an ecosystem scan's results.jsonl into the persistent "
             "trust registry (builds queryable verdict history).")
    p_ingest.add_argument("results", help="Path to results.jsonl from an ecosystem scan")
    p_ingest.add_argument("--db", help="Registry DB path (default ~/.husk/registry.db)")
    p_ingest.add_argument("--source", default="github")
    p_ingest.set_defaults(func=cmd_registry_ingest)

    p_rlookup = subparsers.add_parser(
        "registry-lookup",
        help="Look up a skill in the trust registry ('is this skill safe?'), "
             "or --top N for the most dangerous skills.")
    p_rlookup.add_argument("ref", nargs="?", help="Skill ref, e.g. owner/name")
    p_rlookup.add_argument("--top", type=int, help="List the top N flagged skills instead")
    p_rlookup.add_argument("--db", help="Registry DB path (default ~/.husk/registry.db)")
    p_rlookup.set_defaults(func=cmd_registry_lookup)

    p_badge = subparsers.add_parser(
        "badge",
        help="Print the README snippet for a live, verifiable Husk trust badge "
             "for your skill (reflects its current registry verdict).")
    p_badge.add_argument("ref", help="Your skill ref, e.g. owner/name")
    p_badge.add_argument("--registry", default="https://husk.zone",
                         help="Registry base URL (default https://husk.zone)")
    p_badge.add_argument("--html", action="store_true", help="Emit HTML instead of Markdown")
    p_badge.add_argument("--quiet", action="store_true", help="Snippet only, no explanation")
    p_badge.set_defaults(func=cmd_badge)

    p_model = subparsers.add_parser("model", help="Scan a pickle-based model file")
    p_model.add_argument("path", help="Path to the model file")
    p_model.set_defaults(func=cmd_model)

    p_aggregate = subparsers.add_parser(
        "aggregate", help="Download a published skill (e.g. owner/skill-name "
                          "on ClawHub), scan the whole package with Husk, and "
                          "compare against the marketplace's own security "
                          "verdict where one is published",
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
