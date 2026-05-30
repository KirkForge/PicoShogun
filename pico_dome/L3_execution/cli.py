"""
SecDev L3 Sandbox — CLI entry point.

Usage:
    python -m pico_dome.L3_execution.cli run --policy default.yml -- ./command
    python -m pico_dome.L3_execution.cli run -- ./command
    python -m pico_dome.L3_execution.cli policy --output default.yml
    python -m pico_dome.L3_execution.cli generate-policy --from-l2 results.json --output sandbox.yml
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import sandbox_run
from .formatters import format_json, format_sarif, format_table
from .policy_loader import load_policy, write_default_policy


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="picoshogun-sandbox",
        description="SecDev L3 Execution Sandbox — deterministic, zero-trust process sandboxing",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ─── run ──────────────────────────────────────────────────────────
    run_parser = sub.add_parser("run", help="Run a command under sandbox policy")
    run_parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to execute (preceded by --)",
    )
    run_parser.add_argument(
        "--policy", "-p",
        type=Path,
        default=None,
        help="Path to policy YAML (default: built-in deny-by-default)",
    )
    run_parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "table"],
        default="table",
        help="Output format (default: table)",
    )
    run_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Write output to file instead of stdout",
    )
    run_parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=None,
        help="Override wall-time limit (seconds)",
    )
    run_parser.add_argument(
        "--cwd",
        type=Path,
        default=None,
        help="Working directory for the command",
    )
    run_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in table output",
    )

    # ─── policy ────────────────────────────────────────────────────────
    policy_parser = sub.add_parser("policy", help="Write default policy to file")
    policy_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("default-policy.yml"),
        help="Output file path (default: default-policy.yml)",
    )

    # ─── generate-policy ───────────────────────────────────────────────
    gen_parser = sub.add_parser(
        "generate-policy",
        help="Generate L3 policy from L2 scan results",
    )
    gen_parser.add_argument(
        "--from-l2",
        type=Path,
        required=True,
        help="L2 scan results JSON file",
    )
    gen_parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path("sandbox-policy.yml"),
        help="Output policy YAML file",
    )

    args = parser.parse_args(argv)

    if args.command == "run":
        return _cmd_run(args)
    elif args.command == "policy":
        return _cmd_policy(args)
    elif args.command == "generate-policy":
        return _cmd_generate_policy(args)

    return 2


def _cmd_run(args: argparse.Namespace) -> int:
    """Execute the 'run' subcommand."""
    if not args.command:
        print("Error: no command specified. Use -- before the command.", file=sys.stderr)
        return 2

    policy = load_policy(args.policy)
    result = sandbox_run(
        command=args.command,
        policy=policy,
        timeout=args.timeout,
        cwd=str(args.cwd) if args.cwd else None,
    )

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

    # Exit code: 0=ALLOW, 1=DENY, 2=AUDIT, 3=error
    verdict_codes = {"ALLOW": 0, "DENY": 1, "AUDIT": 2}
    return verdict_codes.get(result.overall_verdict.value, 3)


def _cmd_policy(args: argparse.Namespace) -> int:
    """Write default policy to file."""
    path = write_default_policy(args.output)
    print(f"Default policy written to {path}")
    return 0


def _cmd_generate_policy(args: argparse.Namespace) -> int:
    """Generate L3 policy from L2 scan results."""
    from ..L2_validation.models import Confidence, Finding, Severity
    from .policy_generator import generate_policy_from_findings

    if not args.from_l2.exists():
        print(f"Error: L2 results file not found: {args.from_l2}", file=sys.stderr)
        return 2

    data = json.loads(args.from_l2.read_text(encoding="utf-8"))
    findings_data = data.get("findings", [])
    findings = []
    for fd in findings_data:
        findings.append(Finding(
            rule_id=fd["rule_id"],
            severity=Severity(fd.get("severity", "HIGH")),
            confidence=Confidence(fd.get("confidence", "MEDIUM")),
            package=fd.get("package", "unknown"),
            file=fd.get("file", ""),
            message=fd.get("message", ""),
            evidence=fd.get("evidence", ""),
            remediation=fd.get("remediation", ""),
            references=fd.get("references", []),
        ))

    policy = generate_policy_from_findings(findings)

    # Write as YAML
    import yaml
    output_data = policy.to_dict()
    # Convert PolicyRules to dicts for YAML serialization
    output_data["rules"] = [
        {
            "rule_id": r.rule_id.value if hasattr(r.rule_id, "value") else str(r.rule_id),
            "action": r.action.value if hasattr(r.action, "value") else str(r.action),
            "description": r.description,
            "patterns": r.patterns,
            "severity": r.severity.value if hasattr(r.severity, "value") else str(r.severity),
        }
        for r in policy.rules
    ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.dump(output_data, default_flow_style=False), encoding="utf-8")
    print(f"L3 policy generated from {len(findings)} L2 findings → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
