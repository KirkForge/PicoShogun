"""
L4 Baseline Differ — compares behavioral profiles against baselines.

Deterministic: same profile + same baseline = same drift score. No guessing.
Uses z-scores for scalar comparisons and DTW for curve comparisons.
"""
from __future__ import annotations

import logging

from .dtw import normalized_dtw_distance
from .models import Baseline, BehavioralProfile, DriftResult

logger = logging.getLogger("pico_dome.L4.differ")


def compare_profile_to_baseline(
    profile: BehavioralProfile,
    baseline: Baseline,
) -> DriftResult:
    """Compare a behavioral profile against a baseline and compute drift."""
    call_freq_drift = _compute_call_frequency_drift(profile, baseline)
    network_drift = _compute_network_drift(profile, baseline)
    resource_drift = _compute_resource_drift(profile, baseline)
    entropy_drift = _compute_entropy_drift(profile, baseline)
    duration_drift = _compute_duration_drift(profile, baseline)

    return DriftResult(
        baseline_name=baseline.name,
        call_frequency_drift=call_freq_drift,
        network_drift=network_drift,
        resource_drift=resource_drift,
        entropy_drift=entropy_drift,
        duration_drift=duration_drift,
    )


def find_best_baseline(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline],
) -> tuple[Baseline, DriftResult] | None:
    """Find the best-matching baseline for a profile."""
    if not baselines:
        return None

    best: tuple[Baseline, DriftResult] | None = None
    best_score = float("inf")

    for _name, baseline in baselines.items():
        drift = compare_profile_to_baseline(profile, baseline)
        overall = _overall_drift_score(drift)
        if overall < best_score:
            best_score = overall
            best = (baseline, drift)

    return best


def overall_drift_score(drift: DriftResult) -> float:
    """Compute an overall drift score from a DriftResult."""
    return _overall_drift_score(drift)


def _overall_drift_score(drift: DriftResult) -> float:
    """Weighted average of drift components."""
    # If there's no data for a component, exclude it from the average
    weights = {
        "call_freq": 0.3,
        "network": 0.2,
        "resource": 0.2,
        "entropy": 0.2,
        "duration": 0.1,
    }

    total_weight = sum(weights.values())
    weighted_sum = (
        drift.call_frequency_drift * weights["call_freq"] +
        drift.network_drift * weights["network"] +
        drift.resource_drift * weights["resource"] +
        drift.entropy_drift * weights["entropy"] +
        drift.duration_drift * weights["duration"]
    )

    return weighted_sum / total_weight


def _z_score(value: float, mean: float, stddev: float) -> float:
    if stddev == 0:
        return 0.0 if abs(value - mean) < 0.001 else float("inf")
    return (value - mean) / stddev


def _z_score_to_drift(z: float, cap: float = 3.0) -> float:
    return min(abs(z) / cap, 1.0)


def _compute_call_frequency_drift(
    profile: BehavioralProfile,
    baseline: Baseline,
) -> float:
    if not baseline.call_frequencies:
        return 0.0

    drifts: list[float] = []
    for op, stats in baseline.call_frequencies.items():
        mean = stats.get("mean", 0.0)
        stddev = stats.get("stddev", 1.0)
        observed = profile.call_frequencies.get(op, 0)
        z = _z_score(float(observed), mean, stddev)
        drifts.append(_z_score_to_drift(z))

    # Operations not in baseline but present in profile
    for op in profile.call_frequencies:
        if op not in baseline.call_frequencies and profile.call_frequencies[op] > 0:
            drifts.append(0.5)

    return max(drifts) if drifts else 0.0


def _compute_network_drift(
    profile: BehavioralProfile,
    baseline: Baseline,
) -> float:
    if not baseline.network_hosts and not baseline.dns_domains:
        if profile.network_calls or profile.dns_queries:
            return 0.5
        return 0.0

    host_drift = 0.0
    dns_drift = 0.0
    bytes_drift = 0.0

    if baseline.network_hosts:
        unexpected_hosts = 0
        for nc in profile.network_calls:
            if not any(nc.host.endswith(h) or nc.host == h for h in baseline.network_hosts):
                unexpected_hosts += 1
        if profile.network_calls:
            host_drift = unexpected_hosts / len(profile.network_calls)
    else:
        host_drift = 1.0 if profile.network_calls else 0.0

    if baseline.dns_domains:
        unexpected_dns = 0
        for dq in profile.dns_queries:
            if not any(dq.domain.endswith(d) or dq.domain == d for d in baseline.dns_domains):
                unexpected_dns += 1
        if profile.dns_queries:
            dns_drift = unexpected_dns / len(profile.dns_queries)
    else:
        dns_drift = 1.0 if profile.dns_queries else 0.0

    if baseline.avg_bytes_sent > 0:
        z_sent = _z_score(
            profile.total_bytes_sent,
            baseline.avg_bytes_sent,
            max(baseline.avg_bytes_sent * 0.5, 1.0),
        )
        bytes_drift = _z_score_to_drift(z_sent)

    return min(host_drift * 0.4 + dns_drift * 0.4 + bytes_drift * 0.2, 1.0)


def _compute_resource_drift(
    profile: BehavioralProfile,
    baseline: Baseline,
) -> float:
    if not baseline.resource_curve:
        return 0.0

    # No resource samples collected = no data to compare, not drift
    if not profile.resource_samples:
        return 0.0

    baseline_cpu = [p.get("cpu", 0.0) for p in baseline.resource_curve]
    observed_cpu = [s.cpu_percent for s in profile.resource_samples]

    if not baseline_cpu or not observed_cpu:
        return 0.0

    return normalized_dtw_distance(observed_cpu, baseline_cpu)


def _compute_entropy_drift(
    profile: BehavioralProfile,
    baseline: Baseline,
) -> float:
    # No egress data = no entropy to compare, not drift
    if profile.egress_entropy <= 0:
        return 0.0

    if baseline.avg_egress_entropy == 0 and baseline.std_egress_entropy == 0:
        # No baseline — only drift if entropy is very high
        return 1.0 if profile.egress_entropy > 7.0 else 0.0

    z = _z_score(profile.egress_entropy, baseline.avg_egress_entropy, baseline.std_egress_entropy)
    return _z_score_to_drift(z)


def _compute_duration_drift(
    profile: BehavioralProfile,
    baseline: Baseline,
) -> float:
    if baseline.avg_duration_ms == 0:
        return 0.0

    z = _z_score(
        profile.duration_ms,
        baseline.avg_duration_ms,
        max(baseline.std_duration_ms, 1.0),
    )
    return _z_score_to_drift(z)
