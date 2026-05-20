"""
SecDev L4 Behavioral Analysis — CLI entry point.

Usage:
    python -m iron_dome.L4_behavioral.cli analyze --trace results.json
    python -m iron_dome.L4_behavioral.cli analyze --trace results.json --baseline npm-install
    python -m iron_dome.L4_behavioral.cli analyze --profile profile.json
    python -m iron_dome.L4_behavioral.cli baselines
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional

from .models import (
    AnalysisResult, BehavioralProfile, Baseline, BehavioralVerdict,
)
from .engine import L4Engine, create_default_engine
from .baseline import load_all_baselines, load_baseline, save_baseline
from .profiler import profile_from_trace, profile_from_sandbox_result
from .formatters import format_json, format_sarif, format_table


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="secdev-behavioral",
        description="SecDev L4 Behavioral Analysis — deterministic, zero-trust behavioral profiling",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ─── analyze ───────────────────────────────────────────────────────
    analyze_parser = sub.add_parser("analyze", help="Analyze behavioral profile or L3 sandbox trace")
    analyze_parser.add_argument(
        "--trace", "-t",
        type=Path,
        help="Path to L3 SandboxResult JSON file",
    )
    analyze_parser.add_argument(
        "--profile", "-p",
        type=Path,
        help="Path to pre-built BehavioralProfile JSON file",
    )
    analyze_parser.add_argument(
        "--baseline", "-b",
        type=str,
        default=None,
        help="Baseline name to compare against (e.g., npm-install)",
    )
    analyze_parser.add_argument(
        "--baselines-dir",
        type=Path,
        default=None,
        help="Directory containing baseline YAML/JSON files",
    )
    analyze_parser.add_argument(
        "--rules", "-r",
        nargs="+",
        default=None,
        help="Run only specific rule groups (L4-TIME, L4-EXFIL, L4-ENTROPY, L4-HONEY, L4-BASE)",
    )
    analyze_parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "table"],
        default="table",
        help="Output format (default: table)",
    )
    analyze_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Write output to file instead of stdout",
    )
    analyze_parser.add_argument(
        "--package",
        type=str,
        default="",
        help="Package name for the analysis",
    )
    analyze_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in table output",
    )

    # ─── baselines ─────────────────────────────────────────────────────
    baselines_parser = sub.add_parser("baselines", help="List available baselines")
    baselines_parser.add_argument(
        "--format", "-f",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # ─── export-baseline ────────────────────────────────────────────────
    export_parser = sub.add_parser("export-baseline", help="Export a baseline to file")
    export_parser.add_argument(
        "name",
        type=str,
        help="Baseline name (e.g., npm-install)",
    )
    export_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output file path",
    )

    # ─── plant-canaries ────────────────────────────────────────────────
    canary_parser = sub.add_parser("plant-canaries", help="Plant canary files in a directory")
    canary_parser.add_argument(
        "target_dir",
        type=Path,
        help="Directory to plant canary files in",
    )
    canary_parser.add_argument(
        "--count", "-n",
        type=int,
        default=3,
        help="Number of canary files to plant (default: 3)",
    )

    args = parser.parse_args(argv)

    if args.command == "analyze":
        return _cmd_analyze(args)
    elif args.command == "baselines":
        return _cmd_baselines(args)
    elif args.command == "export-baseline":
        return _cmd_export_baseline(args)
    elif args.command == "plant-canaries":
        return _cmd_plant_canaries(args)

    return 2


def _cmd_analyze(args: argparse.Namespace) -> int:
    """Execute the 'analyze' subcommand."""
    profile: Optional[BehavioralProfile] = None

    # Load profile from trace or pre-built
    if args.trace:
        if not args.trace.exists():
            print(f"Error: trace file not found: {args.trace}", file=sys.stderr)
            return 2

        trace_data = json.loads(args.trace.read_text(encoding="utf-8"))

        # Try to detect format: SandboxResult (from L3) or raw trace
        if "events" in trace_data and "command" in trace_data:
            # L3 SandboxResult format
            from ..L3_execution.models import SandboxResult, SandboxEvent, Verdict as L3Verdict, Policy

            # Reconstruct minimal SandboxResult for profiling
            events = []
            for ev in trace_data.get("events", []):
                from ..L3_execution.models import RuleID
                try:
                    rule_id = RuleID(ev.get("rule_id", "L3-SYS-001"))
                except ValueError:
                    rule_id = RuleID.L3_SYS_001
                events.append(SandboxEvent(
                    timestamp=ev.get("timestamp", ""),
                    rule_id=rule_id,
                    verdict=L3Verdict(ev.get("verdict", "DENY")),
                    operation=ev.get("operation", "unknown"),
                    detail=ev.get("detail", ""),
                    path=ev.get("path"),
                    address=ev.get("address"),
                ))

            result = SandboxResult(
                command=trace_data.get("command", []),
                events=events,
                overall_verdict=L3Verdict(trace_data.get("overall_verdict", "ALLOW")),
                duration_ms=trace_data.get("duration_ms", 0),
                peak_memory_mb=trace_data.get("peak_memory_mb", 0.0),
                cpu_time_seconds=trace_data.get("cpu_time_seconds", 0.0),
            )
            profile = profile_from_sandbox_result(result, package=args.package)
        else:
            # Raw trace format
            profile = profile_from_trace(
                package=args.package or "unknown",
                command=trace_data.get("command", []),
                events=trace_data.get("events", trace_data.get("timing_points", [])),
                duration_ms=trace_data.get("duration_ms", 0),
            )

    elif args.profile:
        if not args.profile.exists():
            print(f"Error: profile file not found: {args.profile}", file=sys.stderr)
            return 2

        profile_data = json.loads(args.profile.read_text(encoding="utf-8"))
        profile = BehavioralProfile(
            package=profile_data.get("package", "unknown"),
            command=profile_data.get("command", []),
            duration_ms=profile_data.get("duration_ms", 0),
            egress_entropy=profile_data.get("egress_entropy", 0.0),
            dns_entropy=profile_data.get("dns_entropy", 0.0),
            total_bytes_sent=profile_data.get("total_bytes_sent", 0),
            total_bytes_received=profile_data.get("total_bytes_received", 0),
            peak_memory_mb=profile_data.get("peak_memory_mb", 0.0),
            canary_file_accesses=profile_data.get("canary_file_accesses", []),
            canary_dns_lookups=profile_data.get("canary_dns_lookups", []),
            canary_env_reads=profile_data.get("canary_env_reads", []),
            call_frequencies=profile_data.get("call_frequencies", {}),
        )

    else:
        print("Error: provide --trace or --profile", file=sys.stderr)
        return 2

    # Load baselines
    baselines: Dict[str, Baseline] = {}
    if args.baselines_dir:
        # Load custom baselines
        import yaml
        baselines_path = Path(args.baselines_dir)
        for f in baselines_path.iterdir():
            if f.suffix in (".yml", ".yaml", ".json"):
                try:
                    content = f.read_text(encoding="utf-8")
                    data = yaml.safe_load(content) if f.suffix != ".json" else json.loads(content)
                    from .baseline import _parse_baseline
                    bl = _parse_baseline(data)
                    baselines[bl.name] = bl
                except Exception:
                    pass
    else:
        baselines = load_all_baselines()

    # If specific baseline requested, filter
    if args.baseline:
        bl = load_baseline(args.baseline)
        if bl:
            baselines = {bl.name: bl}
        else:
            print(f"Warning: baseline '{args.baseline}' not found, using all defaults", file=sys.stderr)

    # Run analysis
    engine = create_default_engine()
    result = engine.analyze(profile, baselines=baselines, rules=args.rules)

    # Format output
    fmt = args.format
    if fmt == "json":
        text = format_json(result)
    elif fmt == "sarif":
        text = format_sarif(result)
    else:
        text = format_table(result, color=not args.no_color)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Results written to {args.output}")
    else:
        print(text)

    # Exit code: 0=CLEAN, 1=SUSPICIOUS, 2=MALICIOUS, 3=error
    verdict_codes = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
    return verdict_codes.get(result.overall_verdict.value, 3)


def _cmd_baselines(args: argparse.Namespace) -> int:
    """List available baselines."""
    baselines = load_all_baselines()

    if args.format == "json":
        data = {name: bl.to_dict() for name, bl in baselines.items()}
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print("\n  Available Behavioral Baselines:")
        print("  " + "=" * 50)
        for name, bl in baselines.items():
            print(f"  {name:20s} {bl.description}")
        print()

    return 0


def _cmd_export_baseline(args: argparse.Namespace) -> int:
    """Export a baseline to file."""
    bl = load_baseline(args.name)
    if bl is None:
        print(f"Error: baseline '{args.name}' not found", file=sys.stderr)
        return 2

    output = args.output or Path(f"{args.name}-baseline.yml")
    path = save_baseline(bl, output)
    print(f"Baseline '{args.name}' exported to {path}")
    return 0


def _cmd_plant_canaries(args: argparse.Namespace) -> int:
    """Plant canary files in a directory."""
    from .honeypot import plant_canary_files

    if not args.target_dir.exists():
        print(f"Error: directory not found: {args.target_dir}", file=sys.stderr)
        return 2

    paths = plant_canary_files(args.target_dir, count=args.count)
    print(f"Planted {len(paths)} canary file(s):")
    for p in paths:
        print(f"  {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
