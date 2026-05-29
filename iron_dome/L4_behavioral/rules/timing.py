"""
L4 Timing Analysis Rules.

L4-TIME-001: Sleep evasion (unnatural delays between operations)
L4-TIME-002: Timing side-channel (timing patterns leaking information)
L4-TIME-003: Burst anomalies (sudden spikes in operation frequency)

Deterministic: same profile = same findings. No ML, no guessing.
"""
from __future__ import annotations

import logging

from ..models import Baseline, BehavioralProfile, Confidence, Finding, Severity

logger = logging.getLogger("iron_dome.L4.rules.timing")

# ─── Thresholds (deterministic, not learned) ─────────────────────────

SLEEP_THRESHOLD_MS = 500.0
SLEEP_COUNT_THRESHOLD = 3
TIMING_CV_THRESHOLD = 0.5
BURST_WINDOW_MS = 100.0
BURST_COUNT_THRESHOLD = 50


def detect_timing_anomalies(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    """Detect timing anomalies: sleep evasion, side-channels, bursts."""
    findings: list[Finding] = []
    findings.extend(_detect_sleep_evasion(profile))
    findings.extend(_detect_timing_side_channel(profile))
    findings.extend(_detect_burst_anomalies(profile))
    return findings


def _detect_sleep_evasion(profile: BehavioralProfile) -> list[Finding]:
    """L4-TIME-001: Detect unnatural sleep patterns (evasion)."""
    if len(profile.sleep_intervals) < SLEEP_COUNT_THRESHOLD:
        return []

    total_sleep = sum(profile.sleep_intervals)
    avg_sleep = total_sleep / len(profile.sleep_intervals)
    max_sleep = max(profile.sleep_intervals)

    return [Finding(
        rule_id="L4-TIME-001",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        package=profile.package,
        message=(
            f"Detected {len(profile.sleep_intervals)} sleep intervals "
            f"(avg={avg_sleep:.0f}ms, max={max_sleep:.0f}ms) — possible evasion"
        ),
        evidence=(
            f"sleep_intervals={profile.sleep_intervals[:10]}, "
            f"total_sleep={total_sleep:.0f}ms"
        ),
        remediation=(
            "Review the package for timing-based evasion. "
            "Sleep delays between operations may indicate anti-analysis techniques. "
            "Consider sandboxing with stricter time limits."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1497/003/",
            "https://github.com/center-for-threat-informed-defense/adversary-emulation",
        ],
    )]


def _detect_timing_side_channel(profile: BehavioralProfile) -> list[Finding]:
    """L4-TIME-002: Detect timing side-channels."""
    if not profile.timing_points or len(profile.timing_points) < 3:
        return []

    op_durations: dict[str, list[float]] = {}
    for tp in profile.timing_points:
        if tp.duration_ms > 0:
            op_durations.setdefault(tp.operation, []).append(tp.duration_ms)

    suspicious_ops: list[str] = []
    for op, durations in op_durations.items():
        if len(durations) < 3:
            continue
        mean = sum(durations) / len(durations)
        if mean == 0:
            continue
        variance = sum((d - mean) ** 2 for d in durations) / len(durations)
        stddev = variance ** 0.5
        cv = stddev / mean

        if cv > TIMING_CV_THRESHOLD:
            suspicious_ops.append(f"{op}(cv={cv:.2f},mean={mean:.1f}ms)")

    if not suspicious_ops:
        return []

    return [Finding(
        rule_id="L4-TIME-002",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        package=profile.package,
        message=(
            f"High timing variance detected in {len(suspicious_ops)} operation types — "
            f"possible timing side-channel"
        ),
        evidence=", ".join(suspicious_ops),
        remediation=(
            "Review the package for timing-based side-channel attacks. "
            "High variance in operation timing can leak secret data. "
            "Consider constant-time implementations."
        ),
        references=[
            "https://en.wikipedia.org/wiki/Timing_attack",
            "https://spectreattack.com/",
        ],
    )]


def _detect_burst_anomalies(profile: BehavioralProfile) -> list[Finding]:
    """L4-TIME-003: Detect burst anomalies (sudden spikes)."""
    if len(profile.timing_points) < BURST_COUNT_THRESHOLD:
        return []

    timestamps = [tp.timestamp_ms for tp in profile.timing_points]
    timestamps.sort()

    max_burst = 0
    max_burst_start = 0.0
    for _i, ts in enumerate(timestamps):
        count = sum(1 for t in timestamps if ts <= t < ts + BURST_WINDOW_MS)
        if count > max_burst:
            max_burst = count
            max_burst_start = ts

    if max_burst < BURST_COUNT_THRESHOLD:
        return []

    return [Finding(
        rule_id="L4-TIME-003",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        package=profile.package,
        message=(
            f"Burst of {max_burst} operations in {BURST_WINDOW_MS:.0f}ms window "
            f"starting at {max_burst_start:.0f}ms — possible exfiltration or DoS"
        ),
        evidence=f"burst_count={max_burst}, window_ms={BURST_WINDOW_MS}, start_ms={max_burst_start:.0f}",
        remediation=(
            "Review the burst pattern. Rapid-fire operations may indicate "
            "data exfiltration, port scanning, or denial-of-service behavior. "
            "Consider rate-limiting in sandbox policy."
        ),
        references=["https://attack.mitre.org/techniques/T1041/"],
    )]
