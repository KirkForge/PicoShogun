"""
L4 Entropy Analysis Rules.

L4-ENTROPY-001: High-entropy egress data (encrypted exfil signal, >7.0 bits/byte)
L4-ENTROPY-002: Entropy spikes vs baseline

Deterministic: same data = same entropy. No ML.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

from ..models import Baseline, BehavioralProfile, Finding, Severity, Confidence
from ..entropy import shannon_entropy, detect_entropy_spikes

logger = logging.getLogger("iron_dome.L4.rules.entropy")

HIGH_ENTROPY_THRESHOLD = 7.0
ENTROPY_SPIKE_THRESHOLD = 2.0


def detect_entropy_anomalies(
    profile: BehavioralProfile,
    baselines: Optional[Dict[str, Baseline]] = None,
) -> List[Finding]:
    """Detect entropy anomalies in a behavioral profile."""
    findings: List[Finding] = []
    findings.extend(_detect_high_entropy_egress(profile))

    # Find best baseline for entropy comparison
    baseline_obj = None
    if baselines:
        for bl in baselines.values():
            if bl.avg_egress_entropy > 0:
                baseline_obj = bl
                break

    findings.extend(_detect_entropy_spike(profile, baseline_obj))
    return findings


def _detect_high_entropy_egress(profile: BehavioralProfile) -> List[Finding]:
    """L4-ENTROPY-001: Detect high-entropy egress data."""
    # No egress data at all — not a finding
    if profile.egress_entropy <= 0:
        return []

    if profile.egress_entropy < HIGH_ENTROPY_THRESHOLD:
        return []

    margin = profile.egress_entropy - HIGH_ENTROPY_THRESHOLD
    if margin > 1.0:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif margin > 0.5:
        severity = Severity.HIGH
        confidence = Confidence.HIGH
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.MEDIUM

    return [Finding(
        rule_id="L4-ENTROPY-001",
        severity=severity,
        confidence=confidence,
        package=profile.package,
        message=(
            f"High-entropy egress data detected: {profile.egress_entropy:.2f} bits/byte "
            f"(threshold: {HIGH_ENTROPY_THRESHOLD:.1f}) — possible encrypted exfiltration"
        ),
        evidence=f"egress_entropy={profile.egress_entropy:.2f}, threshold={HIGH_ENTROPY_THRESHOLD}",
        remediation=(
            "Review outbound data. High entropy (>7.0 bits/byte) strongly suggests "
            "encrypted or compressed data exfiltration. Block non-essential outbound "
            "connections in sandbox policy and inspect egress data."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1048/",
            "https://www.sans.org/white-papers/detecting-data-exfiltration/",
        ],
    )]


def _detect_entropy_spike(
    profile: BehavioralProfile,
    baseline: Optional[Baseline],
) -> List[Finding]:
    """L4-ENTROPY-002: Detect entropy spikes compared to baseline."""
    # No egress data — can't have an entropy spike
    if profile.egress_entropy <= 0:
        return []

    if baseline is None:
        return []

    if baseline.avg_egress_entropy <= 0 and baseline.std_egress_entropy <= 0:
        return []

    deviation = abs(profile.egress_entropy - baseline.avg_egress_entropy)
    if deviation < ENTROPY_SPIKE_THRESHOLD:
        return []

    severity = Severity.HIGH if deviation > 3.0 else Severity.MEDIUM
    confidence = Confidence.HIGH if deviation > 3.0 else Confidence.MEDIUM

    return [Finding(
        rule_id="L4-ENTROPY-002",
        severity=severity,
        confidence=confidence,
        package=profile.package,
        message=(
            f"Entropy spike detected: {profile.egress_entropy:.2f} bits/byte "
            f"(baseline: {baseline.avg_egress_entropy:.2f}, "
            f"deviation: {deviation:.2f}) — possible data exfiltration"
        ),
        evidence=(
            f"observed_entropy={profile.egress_entropy:.2f}, "
            f"baseline_entropy={baseline.avg_egress_entropy:.2f}, "
            f"deviation={deviation:.2f}"
        ),
        remediation=(
            "Review outbound data. Entropy significantly above baseline "
            "suggests encrypted or obfuscated exfiltration. Tighten sandbox "
            "network restrictions and investigate egress data."
        ),
        references=["https://attack.mitre.org/techniques/T1048/"],
    )]
