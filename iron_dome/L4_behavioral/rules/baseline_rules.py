"""
L4 Baseline Drift Detection Rules.

L4-BASE-001: Call frequency drift (z-score based)
L4-BASE-002: Network profile drift (unexpected hosts/DNS)
L4-BASE-003: Resource curve drift (DTW algorithm)

Deterministic: same profile + same baseline = same drift score.
"""
from __future__ import annotations

import logging

from ..differ import find_best_baseline
from ..models import (
    Baseline,
    BehavioralProfile,
    Confidence,
    DriftResult,
    Finding,
    Severity,
)

logger = logging.getLogger("iron_dome.L4.rules.baseline")

CALL_FREQ_Z_THRESHOLD = 2.0
NETWORK_DRIFT_THRESHOLD = 0.3
RESOURCE_DRIFT_THRESHOLD = 0.3
OVERALL_DRIFT_THRESHOLD = 0.3


def detect_baseline_drift(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    """Detect behavioral drift from baselines."""
    from ..baseline import load_all_baselines

    if baselines is None:
        baselines = load_all_baselines()

    if not baselines:
        return []

    result = find_best_baseline(profile, baselines)
    if result is None:
        return []

    baseline, drift = result
    findings: list[Finding] = []
    findings.extend(_detect_call_frequency_drift(profile, baseline, drift))
    findings.extend(_detect_network_drift(profile, baseline, drift))
    findings.extend(_detect_resource_drift(profile, baseline, drift))
    return findings


def _detect_call_frequency_drift(
    profile: BehavioralProfile,
    baseline: Baseline,
    drift: DriftResult,
) -> list[Finding]:
    """L4-BASE-001: Detect call frequency drift from baseline."""
    if not baseline.call_frequencies:
        return []

    if drift.call_frequency_drift < NETWORK_DRIFT_THRESHOLD:
        return []

    cf_drift = drift.call_frequency_drift
    if cf_drift > 0.7:
        severity = Severity.HIGH
        confidence = Confidence.HIGH
    elif cf_drift > 0.5:
        severity = Severity.MEDIUM
        confidence = Confidence.HIGH
    else:
        severity = Severity.LOW
        confidence = Confidence.MEDIUM

    evidence_parts: list[str] = []
    for op, stats in baseline.call_frequencies.items():
        observed = profile.call_frequencies.get(op, 0)
        expected_mean = stats.get("mean", 0.0)
        expected_std = stats.get("stddev", 1.0)
        evidence_parts.append(f"{op}: observed={observed}, expected={expected_mean:.0f}±{expected_std:.0f}")

    return [Finding(
        rule_id="L4-BASE-001",
        severity=severity,
        confidence=confidence,
        package=profile.package,
        message=f"Call frequency drift from baseline '{baseline.name}': drift={cf_drift:.2f} — behavioral deviation detected",
        evidence=f"drift={cf_drift:.3f}; " + "; ".join(evidence_parts[:5]),
        remediation=(
            "Review the package's behavior against the expected baseline. "
            "Significant call frequency deviation may indicate malicious activity "
            "or a compromised package. Compare with known-good behavior."
        ),
        references=["https://attack.mitre.org/tactics/TA0009/"],
    )]


def _detect_network_drift(
    profile: BehavioralProfile,
    baseline: Baseline,
    drift: DriftResult,
) -> list[Finding]:
    """L4-BASE-002: Detect network profile drift from baseline."""
    if drift.network_drift < NETWORK_DRIFT_THRESHOLD:
        return []

    nw_drift = drift.network_drift
    if nw_drift > 0.7:
        severity = Severity.HIGH
        confidence = Confidence.HIGH
    elif nw_drift > 0.5:
        severity = Severity.MEDIUM
        confidence = Confidence.HIGH
    else:
        severity = Severity.LOW
        confidence = Confidence.MEDIUM

    unexpected_hosts: list[str] = []
    for nc in profile.network_calls:
        if baseline.network_hosts:
            if not any(nc.host.endswith(h) or nc.host == h for h in baseline.network_hosts):
                unexpected_hosts.append(nc.host)
        else:
            unexpected_hosts.append(nc.host)

    unexpected_hosts = list(dict.fromkeys(unexpected_hosts))[:5]

    return [Finding(
        rule_id="L4-BASE-002",
        severity=severity,
        confidence=confidence,
        package=profile.package,
        message=f"Network profile drift from baseline '{baseline.name}': drift={nw_drift:.2f} — unexpected network activity",
        evidence=(
            f"drift={nw_drift:.3f}; "
            f"unexpected_hosts={unexpected_hosts if unexpected_hosts else 'none'}; "
            f"dns_queries={len(profile.dns_queries)}; "
            f"network_calls={len(profile.network_calls)}"
        ),
        remediation=(
            "Review network connections against the expected baseline. "
            "Unexpected hosts or DNS queries may indicate data exfiltration "
            "or command-and-control communication. Restrict network access "
            "in sandbox policy."
        ),
        references=["https://attack.mitre.org/techniques/T1071/"],
    )]


def _detect_resource_drift(
    profile: BehavioralProfile,
    baseline: Baseline,
    drift: DriftResult,
) -> list[Finding]:
    """L4-BASE-003: Detect resource curve drift from baseline (DTW)."""
    if not baseline.resource_curve:
        return []

    if drift.resource_drift < RESOURCE_DRIFT_THRESHOLD:
        return []

    res_drift = drift.resource_drift
    if res_drift > 0.7:
        severity = Severity.HIGH
        confidence = Confidence.HIGH
    elif res_drift > 0.5:
        severity = Severity.MEDIUM
        confidence = Confidence.HIGH
    else:
        severity = Severity.LOW
        confidence = Confidence.MEDIUM

    return [Finding(
        rule_id="L4-BASE-003",
        severity=severity,
        confidence=confidence,
        package=profile.package,
        message=f"Resource curve drift from baseline '{baseline.name}': DTW distance={res_drift:.2f} — behavioral deviation detected",
        evidence=(
            f"dtw_distance={res_drift:.3f}; "
            f"baseline='{baseline.name}'; "
            f"samples={len(profile.resource_samples)}; "
            f"peak_mem={profile.peak_memory_mb:.1f}MB; "
            f"duration={profile.duration_ms}ms"
        ),
        remediation=(
            "Review resource usage patterns against the expected baseline. "
            "DTW distance indicates the package's resource consumption curve "
            "differs significantly from known-good behavior. This may indicate "
            "crypto-mining, data processing, or other anomalous behavior."
        ),
        references=["https://en.wikipedia.org/wiki/Dynamic_time_warping"],
    )]
