"""Human-readable table output formatter for sandbox results."""
from __future__ import annotations

from typing import IO

from ..models import SandboxResult

_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_VERDICT_COLOR = {
    "ALLOW": _GREEN,
    "DENY": _RED,
    "AUDIT": _YELLOW,
}


def format_table(result: SandboxResult, output: IO[str] | None = None, color: bool = True) -> str:
    lines: list[str] = []
    def _colorize(s: str, code: str) -> str:
        return f"{code}{s}{_RESET}" if color and code else s

    lines.append("")
    lines.append(_colorize("  SecDev L3 Execution Sandbox", _BOLD))
    lines.append(_colorize(f"  {'=' * 50}", _BOLD))

    verdict_color = _VERDICT_COLOR.get(result.overall_verdict.value, "")
    lines.append(f"  Verdict:  {_colorize(result.overall_verdict.value, verdict_color)}")
    lines.append(f"  Run ID:   {result.run_id}")
    lines.append(f"  Command:  {' '.join(result.command)}")
    lines.append(f"  Policy:   {result.policy.name if result.policy else 'none'}")
    lines.append(f"  Time:      {result.timestamp}")
    lines.append("")

    if not result.events:
        lines.append(_colorize("  ✓ No policy violations", _GREEN))
    else:
        for event in result.events:
            vc = _VERDICT_COLOR.get(event.verdict.value, "")
            lines.append(
                f"  [{_colorize(event.verdict.value, vc)}] {event.rule_id.value if hasattr(event.rule_id, 'value') else event.rule_id}"
                f"  {event.operation}"
            )
            lines.append(f"    {event.detail}")
            if event.path:
                lines.append(f"    path: {event.path}")
            if event.address:
                lines.append(f"    addr: {event.address}")
            lines.append("")

    lines.append(_colorize(f"  {'─' * 50}", _DIM))
    lines.append(
        f"  Exit: {result.exit_code}  "
        f"Duration: {result.duration_ms}ms  "
        f"Events: {len(result.events)}"
    )
    lines.append("")

    text = "\n".join(lines)
    if output:
        output.write(text)
        output.write("\n")
    return text
