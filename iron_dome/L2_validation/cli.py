"""
SecDev L2 Supply Chain Scanner — CLI entry point.

Usage:
    python -m iron_dome.L2_validation.cli scan ./project
    python -m iron_dome.L2_validation.cli scan ./project --format sarif -o results.sarif
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import create_default_engine
from .formatters import format_json, format_sarif, format_table


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns exit code: 0=clean, 1=findings, 2=error."""
    parser = argparse.ArgumentParser(
        prog="shogun-scan",
        description="SecDev L2 Supply Chain Scanner — deterministic, zero-trust package scanning",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Scan a project directory for supply chain risks")
    scan_parser.add_argument(
        "target",
        type=Path,
        help="Path to project directory (e.g., ./project, ./node_modules)",
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "table"],
        default="table",
        help="Output format (default: table)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        type=Path,
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
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in table output",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)

    return 2


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the 'scan' subcommand."""
    target = args.target.resolve()

    if not target.exists():
        print(f"Error: target path does not exist: {target}", file=sys.stderr)
        return 2

    engine = create_default_engine()

    result = engine.scan(target, rules=args.rules)

    # Format output
    fmt = args.format
    if fmt == "json":
        text = format_json(result)
    elif fmt == "sarif":
        text = format_sarif(result)
    else:
        text = format_table(result, color=not args.no_color)

    # Write to file or stdout
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Results written to {args.output}")
    else:
        print(text)

    # Exit code: 1 if findings, 0 if clean
    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
