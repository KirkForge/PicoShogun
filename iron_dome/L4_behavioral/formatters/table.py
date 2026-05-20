"""Human-readable table output formatter for L4 behavioral analysis results."""
from __future__ import annotations

from typing import IO

from ..models import AnalysisResult, BehavioralVerdict

_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_MAGENTA = "\033[95m"
_RESET = "\033[0m"

_VERDICT_COLOR = {
    "CLEAN": _GREEN,
    "SUSPICIOUS": _YELLOW,
    "MALICIOUS": _RED,
}

_SEVERITY_COLOR = {
    "CRITICAL": _RED,
    "HIGH": _RED,
    "MEDIUM": _YELLOW,
    "LOW": _CYAN,
    "INFO": _DIM,
}


def format_table(result: AnalysisResult, output: IO[str] | None = None, color: bool = True) -> str:
    """Format an AnalysisResult as a human-readable table."""
    lines: list[str] = []
    c = lambda s, code: f"{code}{s}{_RESET}" if color and code else s

    lines.append("")
    lines.append(c("  SecDev L4 Behavioral Analysis", _BOLD))
    lines.append(c(f"  {'=' * 50}", _BOLD))

    verdict_color = _VERDICT_COLOR.get(result.overall_verdict.value, "")
    lines.append(f"  Verdict:  {c(result.overall_verdict.value, verdict_color)}")
    lines.append(f"  ID:       {result.analysis_id}")
    lines.append(f"  Target:   {result.target}")
    lines.append(f"  Time:     {result.timestamp}")

    if result.profile:
        lines.append(f"  Duration: {result.profile.duration_ms}ms")
        lines.append(f"  Events:   {len(result.profile.timing_points)}")
        lines.append(f"  Net:      {len(result.profile.network_calls)} calls, "
                     f"{len(result.profile.dns_queries)} DNS")
        lines.append(f"  FS:       {len(result.profile.fs_ops)} ops")
        lines.append(f"  Spawns:   {len(result.profile.spawns)}")

    lines.append("")

    # Drift results
    if result.drift_results:
        lines.append(c("  Baseline Drift:", _BOLD))
        for drift in result.drift_results:
            lines.append(f"    {drift.baseline_name}:")
            lines.append(f"      call_freq:  {drift.call_frequency_drift:.3f}")
            lines.append(f"      network:    {drift.network_drift:.3f}")
            lines.append(f"      resource:  {drift.resource_drift:.3f}")
            lines.append(f"      entropy:    {drift.entropy_drift:.3f}")
            lines.append(f"      duration:   {drift.duration_drift:.3f}")
        lines.append("")

    # Findings
    if not result.findings:
        lines.append(c("  ✓ No behavioral anomalies detected", _GREEN))
    else:
        lines.append(c(f"  ⚠ {len(result.findings)} finding(s):", _YELLOW))
        lines.append("")
        for finding in result.findings:
            sev_color = _SEVERITY_COLOR.get(finding.severity.value, "")
            lines.append(
                f"  [{c(finding.severity.value, sev_color)}] "
                f"{finding.rule_id}  {finding.message[:80]}"
            )
            if finding.evidence:
                lines.append(f"    {c(finding.evidence[:120], _DIM)}")
            lines.append("")

    # Stats
    lines.append(c(f"  {'─' * 50}", _DIM))
    stats = result.stats
    lines.append(
        f"  Events: {stats.events_analyzed}  "
        f"Net: {stats.network_calls_analyzed}  "
        f"DNS: {stats.dns_queries_analyzed}  "
        f"FS: {stats.fs_ops_analyzed}  "
        f"Spawns: {stats.spawns_analyzed}"
    )
    lines.append(f"  Analysis time: {stats.duration_ms}ms")
    lines.append("")

    text = "\n".join(lines)
    if output:
        output.write(text)
        output.write("\n")
    return text
