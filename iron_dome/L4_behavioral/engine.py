"""
L4 Behavioral Analysis Engine.

Orchestrates detector rules, collects findings, produces AnalysisResult.
Pipeline: L2 static scan → L3 sandbox → L4 behavioral analysis.

Deterministic: same profile + same baseline = same findings. No ML, no guessing.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence

from .baseline import load_all_baselines
from .differ import find_best_baseline
from .models import (
    AnalysisResult,
    AnalysisStats,
    Baseline,
    BehavioralProfile,
    BehavioralVerdict,
    DriftResult,
    Finding,
    Severity,
)

logger = logging.getLogger("iron_dome.L4.engine")

# Type alias: a detector rule takes a profile and optional baselines dict, returns findings.
DetectorRule = Callable[..., list[Finding]]


class L4Engine:
    """
    Deterministic behavioral analysis engine.

    Register detector rules, then analyze a behavioral profile.
    Each rule runs independently — composable, no side-effects between rules.
    """

    def __init__(self) -> None:
        self._rules: dict[str, DetectorRule] = {}

    def register(self, rule_id: str, rule: DetectorRule) -> L4Engine:
        """Register a detector rule. Returns self for chaining."""
        self._rules[rule_id] = rule
        return self

    def unregister(self, rule_id: str) -> None:
        """Remove a detector rule."""
        self._rules.pop(rule_id, None)

    def list_rules(self) -> list[str]:
        """Return sorted list of registered rule IDs."""
        return sorted(self._rules.keys())

    def analyze(
        self,
        profile: BehavioralProfile,
        baselines: dict[str, Baseline] | None = None,
        rules: Sequence[str] | None = None,
    ) -> AnalysisResult:
        """
        Run behavioral analysis on a profile.

        Args:
            profile: The behavioral profile to analyze.
            baselines: Optional dict of baselines. None = load shipped defaults.
            rules: Optional subset of rule IDs to run. None = all rules.

        Returns:
            AnalysisResult with all findings and verdict.
        """
        if baselines is None:
            baselines = load_all_baselines()

        selected_rules = (
            {k: v for k, v in self._rules.items() if k in rules}
            if rules
            else dict(self._rules)
        )

        if not selected_rules:
            logger.warning("No detector rules selected for analysis")
            return AnalysisResult(
                target=profile.package,
                profile=profile,
                overall_verdict=BehavioralVerdict.CLEAN,
            )

        logger.info(
            "Starting L4 analysis: target=%s rules=%s",
            profile.package,
            list(selected_rules.keys()),
        )

        start_ms = _now_ms()
        all_findings: list[Finding] = []

        for rule_id, rule_fn in selected_rules.items():
            try:
                # Try calling with baselines, fall back to profile-only
                import inspect
                sig = inspect.signature(rule_fn)
                params = list(sig.parameters.keys())
                findings = rule_fn(profile, baselines) if len(params) >= 2 else rule_fn(profile)
                all_findings.extend(findings)
                logger.debug("Rule %s: %d findings", rule_id, len(findings))
            except Exception:
                logger.exception("Rule %s raised an exception", rule_id)

        duration = int(_now_ms() - start_ms)

        # Compute drift results against best baseline
        drift_results: list[DriftResult] = []
        best_match = find_best_baseline(profile, baselines)
        if best_match:
            _, drift = best_match
            drift_results.append(drift)

        # Compute overall verdict
        overall_verdict = _compute_verdict(all_findings)

        # Build stats
        by_severity: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for f in all_findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

        stats = AnalysisStats(
            events_analyzed=len(profile.timing_points),
            network_calls_analyzed=len(profile.network_calls),
            dns_queries_analyzed=len(profile.dns_queries),
            fs_ops_analyzed=len(profile.fs_ops),
            spawns_analyzed=len(profile.spawns),
            duration_ms=duration,
            findings_by_severity=by_severity,
            findings_by_rule=by_rule,
        )

        result = AnalysisResult(
            target=profile.package,
            findings=all_findings,
            profile=profile,
            drift_results=drift_results,
            overall_verdict=overall_verdict,
            stats=stats,
        )

        logger.info(
            "L4 analysis complete: %d findings, verdict=%s, %dms",
            len(all_findings),
            overall_verdict.value,
            duration,
        )

        return result


def create_default_engine() -> L4Engine:
    """Create an L4Engine with all built-in detector rules registered."""
    from .rules.baseline_rules import detect_baseline_drift
    from .rules.entropy_rules import detect_entropy_anomalies
    from .rules.exfil import detect_exfiltration
    from .rules.honeypot_rules import detect_honeypot_touches
    from .rules.timing import detect_timing_anomalies

    engine = L4Engine()
    engine.register("L4-TIME", detect_timing_anomalies)
    engine.register("L4-EXFIL", detect_exfiltration)
    engine.register("L4-ENTROPY", detect_entropy_anomalies)
    engine.register("L4-HONEY", detect_honeypot_touches)
    engine.register("L4-BASE", detect_baseline_drift)
    return engine


def _compute_verdict(findings: list[Finding]) -> BehavioralVerdict:
    """
    Compute overall verdict from findings.
    - Any CRITICAL or HIGH finding → MALICIOUS
    - Any MEDIUM finding → SUSPICIOUS
    - Only LOW/INFO → CLEAN
    """
    if not findings:
        return BehavioralVerdict.CLEAN

    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            return BehavioralVerdict.MALICIOUS

    for f in findings:
        if f.severity == Severity.MEDIUM:
            return BehavioralVerdict.SUSPICIOUS

    return BehavioralVerdict.CLEAN


def _now_ms() -> float:
    return time.monotonic() * 1000
