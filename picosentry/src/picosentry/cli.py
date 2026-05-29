#!/usr/bin/env python3
"""
PicoSentry — CLI entry point.

Usage:
    picosentry scan ./my-project [--format json|sarif|table|ml-context]
    picosentry scan ./my-project --format ml-context --token-budget 2048
    picosentry scan ./my-project --quiet              # CI-friendly summary only
    picosentry scan ./my-project --summary            # One-line for notifications
    picosentry rules
    picosentry update
    picosentry version
    picosentry diff scan_a.json scan_b.json

Deterministic: same target + same corpus = same output. Every time.
"""
import argparse
import contextlib
import hashlib
import json
import sys
from pathlib import Path

from picosentry import __version__
from picosentry.config import load_config
from picosentry.engine import create_default_engine
from picosentry.formatters import format_json, format_ml_context, format_sarif, format_table
from picosentry.formatters.table import _PINCH_LABELS
from picosentry.models import ScanResult, Severity, apply_baseline, load_baseline


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="picosentry",
        description="PicoSentry — deterministic supply-chain scanner for npm/pnpm",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a project directory for supply chain risks")
    scan_parser.add_argument("target", type=str, help="Path to project directory to scan")
    scan_parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "table", "ml-context"],
        default="table",
        help="Output format (default: table)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Write output to file instead of stdout",
    )
    scan_parser.add_argument(
        "--rules", "-r",
        nargs="+",
        default=None,
        help="Run only specific rules (e.g., L2-POST-001 L2-OBFS-001)",
    )
    scan_parser.add_argument(
        "--corpus", "-c",
        type=str,
        default=None,
        help="Path to corpus directory (default: built-in)",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (table format only)",
    )
    scan_parser.add_argument(
        "--token-budget",
        type=int,
        default=4096,
        help="Token budget for ml-context format (default: 4096)",
    )
    scan_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with code 1 if findings found, 0 if clean",
    )
    scan_parser.add_argument(
        "--severity-threshold",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity to include in output (default: show all)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default=None,
        help="Exit with code 1 only if findings at or above this severity (implies --exit-code)",
    )
    scan_parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only show summary line (findings count by severity). No detailed findings.",
    )
    scan_parser.add_argument(
        "--summary",
        action="store_true",
        help="One-line summary for CI notifications (e.g. 'PicoSentry: 3 HARD PINCH, 1 SOFT PINCH'). Implies --quiet.",
    )
    scan_parser.add_argument(
        "--baseline", "-b",
        type=str,
        default=None,
        help="Path to baseline JSON file (previous scan output) or ignore file. Known findings are suppressed.",
    )
    scan_parser.add_argument(
        "--baseline-update",
        action="store_true",
        help="Write updated baseline file (with new findings added) after filtering. Use with --baseline.",
    )

    # rules command
    rules_parser = subparsers.add_parser("rules", help="List available detector rules")
    rules_parser.add_argument(
        "--json", "-j",
        action="store_true",
        dest="json_output",
        help="Output rules as JSON",
    )

    # version command
    subparsers.add_parser("version", help="Show PicoSentry version")

    # diff command
    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare two scan JSON files for determinism verification",
    )
    diff_parser.add_argument(
        "scan_a",
        type=str,
        help="First scan JSON file (baseline)",
    )
    diff_parser.add_argument(
        "scan_b",
        type=str,
        help="Second scan JSON file (comparison)",
    )
    diff_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed diff of findings",
    )

    # update command
    update_parser = subparsers.add_parser(
        "update",
        help="Download latest package corpus from npm registry (requires network)",
    )
    update_parser.add_argument(
        "--top", "-n",
        type=int,
        default=1000,
        help="Number of top packages to download (default: 1000)",
    )
    update_parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output path for corpus JSON (default: built-in corpus)",
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "version":
        engine = create_default_engine()
        print(f"picosentry v{__version__}")
        print(f"corpus: {engine._corpus_version}")
        print(f"rules:  {len(engine.list_rules())}")
        return 0

    if args.command == "diff":
        return _cmd_diff(args)

    if args.command == "rules":
        from picosentry.rules import RULE_INFO
        engine = create_default_engine()
        rule_ids = engine.list_rules()
        if args.json_output:
            rules_data = []
            for rule_id in rule_ids:
                info = RULE_INFO.get(rule_id, {})
                rules_data.append({
                    "rule_id": rule_id,
                    "name": info.get("name", ""),
                    "description": info.get("description", ""),
                    "severity": info.get("severity", ""),
                    "category": info.get("category", ""),
                })
            print(json.dumps(rules_data, indent=2, sort_keys=False))
        else:
            print(f"Available detector rules ({len(rule_ids)}):\n")
            for rule_id in rule_ids:
                info = RULE_INFO.get(rule_id, {})
                desc = info.get("description", "No description")
                sev = info.get("severity", "?")
                cat = info.get("category", "?")
                name = info.get("name", "?")
                print(f"  {rule_id}  {name:<25} [{sev:>8}]  {desc}  ({cat})")
        return 0

    if args.command == "update":
        return _cmd_update(args)

    if args.command == "scan":
        return _cmd_scan(args)

    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    """Compare two scan JSON files for determinism verification.

    Exits 0 if identical, 1 if different. Prints summary of differences.
    This is the determinism guarantee test: sha256(scan_a) == sha256(scan_b).
    """
    path_a = Path(args.scan_a)
    path_b = Path(args.scan_b)

    if not path_a.is_file():
        print(f"Error: {path_a} does not exist", file=sys.stderr)
        return 2
    if not path_b.is_file():
        print(f"Error: {path_b} does not exist", file=sys.stderr)
        return 2

    try:
        data_a = json.loads(path_a.read_text(encoding="utf-8"))
        data_b = json.loads(path_b.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading scan files: {e}", file=sys.stderr)
        return 2

    # Compare scan IDs
    id_a = data_a.get("scan_id", "unknown")
    id_b = data_b.get("scan_id", "unknown")

    # Compare deterministically by re-serializing with sorted keys
    # Exclude duration_ms from comparison (timing is inherently non-deterministic)
    deterministic_fields = {"scan_id", "engine_version", "corpus_version", "target", "findings"}

    json_a = json.dumps(data_a, sort_keys=True, indent=2)
    json_b = json.dumps(data_b, sort_keys=True, indent=2)

    hash_a = hashlib.sha256(json_a.encode()).hexdigest()
    hash_b = hashlib.sha256(json_b.encode()).hexdigest()

    # Also compare only deterministic fields (excluding duration_ms)
    def deterministic_hash(data):
        """Hash only fields that should be identical across repeated scans."""
        det = {k: v for k, v in data.items() if k in deterministic_fields}
        # Also include stats minus duration
        if "stats" in data:
            stats = dict(data["stats"])
            stats.pop("duration_ms", None)
            det["stats"] = stats
        return hashlib.sha256(json.dumps(det, sort_keys=True).encode()).hexdigest()

    det_hash_a = deterministic_hash(data_a)
    det_hash_b = deterministic_hash(data_b)

    if det_hash_a == det_hash_b:
        print("✓ Scans are IDENTICAL — determinism verified")
        print(f"  scan_id: {id_a}")
        print(f"  sha256:  {det_hash_a}")
        print(f"  findings: {len(data_a.get('findings', []))}")
        if hash_a != hash_b:
            print(f"  note: full JSON differs (timing: {data_a.get('stats', {}).get('duration_ms', '?')}ms vs {data_b.get('stats', {}).get('duration_ms', '?')}ms)")
        return 0

    # Different — show what changed
    print("✗ Scans DIFFER — determinism violation detected")
    print(f"  scan_a: id={id_a} sha256={det_hash_a[:16]}...")
    print(f"  scan_b: id={id_b} sha256={det_hash_b[:16]}...")

    findings_a = data_a.get("findings", [])
    findings_b = data_b.get("findings", [])
    print(f"  findings_a: {len(findings_a)}")
    print(f"  findings_b: {len(findings_b)}")

    # Compare metadata
    for key in sorted(set(list(data_a.keys()) + list(data_b.keys()))):
        val_a = data_a.get(key)
        val_b = data_b.get(key)
        if key == "findings":
            continue  # handled separately
        if val_a != val_b:
            print(f"  {key}: {val_a!r} → {val_b!r}")

    # Detailed finding diff
    if args.verbose:
        set_a = {(f["rule_id"], f["package"], f.get("line", 0)) for f in findings_a}
        set_b = {(f["rule_id"], f["package"], f.get("line", 0)) for f in findings_b}

        added = set_b - set_a
        removed = set_a - set_b

        if removed:
            print(f"\n  Removed findings ({len(removed)}):")
            for rule_id, pkg, line in sorted(removed):
                print(f"    - {rule_id} {pkg}:{line}")

        if added:
            print(f"\n  Added findings ({len(added)}):")
            for rule_id, pkg, line in sorted(added):
                print(f"    + {rule_id} {pkg}:{line}")

    return 1


def _cmd_update(args: argparse.Namespace) -> int:
    """Download latest top-N npm packages for the typosquat corpus.

    This is the ONLY command that makes network requests.
    The corpus is saved locally and used by offline scans.
    """
    import urllib.request

    top_n = args.top
    output_path = Path(args.output) if args.output else Path(__file__).parent / "corpus" / "npm_top_packages.json"

    print(f"Fetching top {top_n} npm packages from registry...")

    try:
        # Use npm registry search API to get most depended-on packages
        # Paginate through results
        all_packages = set()
        page_size = 250
        seen = 0

        while seen < top_n:
            url = f"https://registry.npmjs.org/-/v1/search?size={page_size}&from={seen}&text=not:unpopular"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for pkg in data.get("objects", []):
                name = pkg.get("package", {}).get("name", "")
                if name and not name.startswith("@"):
                    all_packages.add(name)

            total = data.get("total", 0)
            seen += page_size
            if seen >= total or seen >= top_n:
                break

        packages = sorted(all_packages)[:top_n]

        # Merge with existing corpus
        existing = set()
        if output_path.is_file():
            with contextlib.suppress(json.JSONDecodeError, OSError):
                existing = set(json.loads(output_path.read_text(encoding="utf-8")))

        merged = sorted(existing | set(packages))

        # Write
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(merged, indent=4, ensure_ascii=False), encoding="utf-8")

        print(f"Corpus updated: {len(merged)} packages ({len(packages)} new from npm, {len(existing)} existing)")
        print(f"Saved to: {output_path}")
        print(f"Corpus version hash: {hashlib.sha256(json.dumps(merged, sort_keys=True).encode()).hexdigest()[:16]}")
        return 0

    except Exception as e:
        print(f"Error updating corpus: {e}", file=sys.stderr)
        print("Falling back to built-in corpus.", file=sys.stderr)
        return 1


def _format_summary(result: ScanResult) -> str:
    """One-line summary for CI notifications.

    Example: PicoSentry: 3 HARD PINCH, 1 SOFT PINCH, 2 NUDGE
    Or:      PicoSentry: No pinches. All clear.
    """
    if not result.findings:
        return "PicoSentry: No pinches. All clear. 🦞"

    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = result.stats.findings_by_severity.get(sev.value, 0)
        if count > 0:
            pinch = _PINCH_LABELS.get(sev, sev.value)
            parts.append(f"{count} {pinch}")

    return f"PicoSentry: {', '.join(parts)}"


def _format_quiet(result: ScanResult) -> str:
    """Quiet mode — summary + finding count per rule, no details.

    Designed for CI logs where you want a quick overview without the full table.
    """
    if not result.findings:
        return "🦞 No pinches. All clear."

    lines = []
    lines.append(f"🦞 PicoSentry: {len(result.findings)} finding(s)")
    lines.append(f"  Target: {result.target}")
    lines.append(f"  Engine: v{result.engine_version} | Corpus: v{result.corpus_version}")
    lines.append(f"  Duration: {result.stats.duration_ms}ms")
    lines.append("")

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = result.stats.findings_by_severity.get(sev.value, 0)
        if count > 0:
            pinch = _PINCH_LABELS.get(sev, sev.value)
            lines.append(f"  {pinch}: {count}")

    lines.append("")
    for rule_id in sorted(result.stats.findings_by_rule):
        count = result.stats.findings_by_rule[rule_id]
        lines.append(f"  {rule_id}: {count}")

    return "\n".join(lines)


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the 'scan' subcommand."""
    target = Path(args.target).resolve()
    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        return 2

    # Load config file from target directory (if present)
    file_config = load_config(target)

    # Merge: CLI args override config file values
    config = file_config.merge_cli(args)

    corpus_dir = Path(config.corpus) if config.corpus else None
    engine = create_default_engine(corpus_dir=corpus_dir)

    result = engine.scan(target, rules=config.rules)

    # Apply severity overrides from config file
    if config.severity_overrides:
        result.findings = config.apply_severity_overrides(result.findings)
        result.recompute_stats()

    # Apply ignore filters from config file
    if config.ignore_packages or config.ignore_paths:
        result.findings = [
            f for f in result.findings
            if not config.should_ignore_package(f.package)
            and not config.should_ignore_path(f.file)
        ]
        result.recompute_stats()

    # Severity filtering (from merged config)
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    if config.severity_threshold or config.fail_on:
        threshold = config.severity_threshold or config.fail_on or "low"
        min_level = severity_order[threshold.lower()]
        result.findings = [
            f for f in result.findings
            if severity_order.get(f.severity.value.lower(), 4) <= min_level
        ]
        result.recompute_stats()

    # Baseline filtering — suppress known findings
    baseline_info = None
    if config.baseline:
        baseline_path = Path(config.baseline)
        if not baseline_path.is_file():
            print(f"Error: baseline file not found: {baseline_path}", file=sys.stderr)
            return 2
        baseline_fingerprints = load_baseline(baseline_path)
        baseline_info = apply_baseline(result, baseline_fingerprints)
        result.findings = baseline_info.remaining
        result.recompute_stats()
        # Log baseline info (not in quiet/summary mode)
        if not config.quiet and not config.summary:
            print(f"Baseline: {baseline_info.suppressed_count} known, {baseline_info.new_count} new (of {baseline_info.original_count} total)", file=sys.stderr)

    # Format output
    if config.summary:
        output = _format_summary(result)
    elif config.quiet and config.format == "table":
        output = _format_quiet(result)
    elif config.format == "json":
        output = format_json(result)
    elif config.format == "sarif":
        output = format_sarif(result)
    elif config.format == "ml-context":
        output = format_ml_context(result, token_budget=config.token_budget)
    else:
        output = format_table(result, color=not config.no_color)

    # Write output
    if config.output:
        Path(config.output).write_text(output, encoding="utf-8")
        print(f"Output written to {config.output}")
    else:
        print(output)

    # Baseline update — write new baseline with current findings added
    if config.baseline and config.baseline_update:
        baseline_path = Path(config.baseline)
        # Load original baseline fingerprints
        load_baseline(baseline_path)
        # Re-scan to get ALL findings (before baseline filtering)
        full_result = engine.scan(target, rules=config.rules)
        # Apply severity overrides
        if config.severity_overrides:
            full_result.findings = config.apply_severity_overrides(full_result.findings)
        # Apply ignore filters
        if config.ignore_packages or config.ignore_paths:
            full_result.findings = [
                f for f in full_result.findings
                if not config.should_ignore_package(f.package)
                and not config.should_ignore_path(f.file)
            ]
        # Apply severity filter if set
        if config.severity_threshold or config.fail_on:
            threshold = config.severity_threshold or config.fail_on or "low"
            min_level = severity_order[threshold.lower()]
            full_result.findings = [
                f for f in full_result.findings
                if severity_order.get(f.severity.value.lower(), 4) <= min_level
            ]
        # Build updated baseline as scan JSON (authoritative format)
        updated_json = full_result.to_json(indent=2)
        baseline_path.write_text(updated_json, encoding="utf-8")
        new_count = len(full_result.findings)
        print(f"Baseline updated: {baseline_path} ({new_count} findings)", file=sys.stderr)

    # Exit code
    fail_on = config.fail_on
    use_exit_code = config.exit_code or fail_on is not None
    if use_exit_code:
        if fail_on:
            # Only fail if findings at or above the threshold severity
            min_level = severity_order[fail_on.lower()]
            has_fail_findings = any(
                severity_order.get(f.severity.value.lower(), 4) <= min_level
                for f in result.findings
            )
            return 1 if has_fail_findings else 0
        return 1 if result.findings else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
