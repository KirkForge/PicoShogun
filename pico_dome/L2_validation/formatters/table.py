"""Human-readable table output formatter for scan results."""
from __future__ import annotations

from typing import IO

from ..models import ScanResult

# ANSI color codes
_RED = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_SEVERITY_COLOR = {
    "CRITICAL": _RED + _BOLD,
    "HIGH": _RED,
    "MEDIUM": _YELLOW,
    "LOW": _CYAN,
    "INFO": "",
}


def format_table(result: ScanResult, output: IO[str] | None = None, color: bool = True) -> str:
    """
    Format a ScanResult as a human-readable table.

    Args:
        result: The scan result to format.
        output: Optional writable stream.
        color: Whether to use ANSI colors.

    Returns:
        Formatted table string.
    """
    lines: list[str] = []
    def _colorize(s: str, code: str) -> str:
        return f"{code}{s}{_RESET}" if color and code else s

    lines.append("")
    lines.append(_colorize("  SecDev L2 Supply Chain Scan", _BOLD))
    lines.append(_colorize(f"  {'=' * 50}", _BOLD))
    lines.append(f"  Target:  {result.target}")
    lines.append(f"  Scan ID: {result.scan_id}")
    lines.append(f"  Time:    {result.timestamp}")
    lines.append("")

    if not result.findings:
        lines.append(_colorize("  ✓ No findings — supply chain looks clean.", _GREEN))
    else:
        sev_col = {k: v for k, v in _SEVERITY_COLOR.items()} if color else {}
        for finding in result.findings:
            color_code = sev_col.get(finding.severity.value, "")
            sev_str = _colorize(finding.severity.value, color_code) if color else finding.severity.value
            lines.append(
                f"  [{sev_str}] {finding.rule_id}  {finding.package}"
            )
            lines.append(f"    {finding.message}")
            if finding.file:
                loc = finding.file
                if finding.line:
                    loc += f":{finding.line}"
                lines.append(f"    {loc}")
            if finding.evidence:
                ev = finding.evidence[:100] + ("..." if len(finding.evidence) > 100 else "")
                lines.append(f"    Evidence: {ev}")
            lines.append("")

    lines.append(_colorize(f"  {'─' * 50}", ""))
    stats = result.stats
    lines.append(
        f"  Packages: {stats.packages_scanned}  "
        f"Files: {stats.files_scanned}  "
        f"Duration: {stats.duration_ms}ms"
    )
    lines.append(
        f"  Findings: {len(result.findings)}  "
        + "  ".join(
            f"{k}: {v}" for k, v in stats.findings_by_severity.items()
        )
    )
    lines.append("")

    text = "\n".join(lines)
    if output:
        output.write(text)
        output.write("\n")
    return text
