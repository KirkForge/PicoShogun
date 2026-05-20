"""
L4 Covert Channel / Exfiltration Detection Rules.

L4-EXFIL-001: DNS exfiltration (unusual DNS queries encoding data)
L4-EXFIL-002: HTTPS header exfiltration (suspicious header patterns)
L4-EXFIL-003: Error channel exfiltration (data in error messages)

Deterministic: same profile = same findings.
"""
from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional

from ..models import Baseline, BehavioralProfile, Finding, Severity, Confidence
from ..entropy import shannon_entropy_string

logger = logging.getLogger("iron_dome.L4.rules.exfil")

# ─── Thresholds ──────────────────────────────────────────────────────

# L4-EXFIL-001: DNS exfiltration
DNS_ENTROPY_THRESHOLD = 4.0
DNS_LENGTH_THRESHOLD = 50
DNS_UNIQUE_THRESHOLD = 10

# L4-EXFIL-002: HTTPS header exfiltration
HTTPS_HEADER_SIZE_THRESHOLD = 4096

# L4-EXFIL-003: Error channel exfiltration
EXFIL_BYTES_THRESHOLD = 10000


def detect_exfiltration(
    profile: BehavioralProfile,
    baselines: Optional[Dict[str, Baseline]] = None,
) -> List[Finding]:
    """
    Detect covert channel exfiltration in a behavioral profile.
    """
    findings: List[Finding] = []
    findings.extend(_detect_dns_exfiltration(profile))
    findings.extend(_detect_https_exfiltration(profile))
    findings.extend(_detect_error_channel_exfiltration(profile))
    return findings


def _detect_dns_exfiltration(profile: BehavioralProfile) -> List[Finding]:
    """L4-EXFIL-001: Detect DNS-based data exfiltration."""
    if not profile.dns_queries:
        return []

    suspicious_queries: List[str] = []

    for dq in profile.dns_queries:
        domain = dq.domain
        ent = shannon_entropy_string(domain)
        if ent > DNS_ENTROPY_THRESHOLD:
            suspicious_queries.append(f"{domain} (entropy={ent:.1f} bits/char)")
            continue
        if len(domain) > DNS_LENGTH_THRESHOLD:
            suspicious_queries.append(f"{domain} (length={len(domain)} chars)")
            continue

    domain_counts: dict[str, int] = {}
    for dq in profile.dns_queries:
        parts = dq.domain.rsplit(".", 2)
        base = (parts[-2] + "." + parts[-1]) if len(parts) >= 2 else dq.domain
        domain_counts[base] = domain_counts.get(base, 0) + 1

    for base, count in domain_counts.items():
        if count >= DNS_UNIQUE_THRESHOLD:
            suspicious_queries.append(f"{base} ({count} unique queries)")

    if not suspicious_queries:
        return []

    suspicious_queries = list(dict.fromkeys(suspicious_queries))

    return [Finding(
        rule_id="L4-EXFIL-001",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH if len(suspicious_queries) > 3 else Confidence.MEDIUM,
        package=profile.package,
        message=f"DNS exfiltration pattern detected: {len(suspicious_queries)} suspicious DNS queries",
        evidence="; ".join(suspicious_queries[:10]),
        remediation=(
            "Review DNS queries for data exfiltration. High-entropy or "
            "unusually long domain names may encode stolen data. "
            "Block DNS queries to non-essential domains in sandbox policy."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1071/004/",
            "https://www.forcepoint.com/blog/cyber-security-blog/dns-data-exfiltration",
        ],
    )]


def _detect_https_exfiltration(profile: BehavioralProfile) -> List[Finding]:
    """L4-EXFIL-002: Detect HTTPS header-based exfiltration."""
    if not profile.network_calls:
        return []

    large_outbound = [nc for nc in profile.network_calls if nc.bytes_sent > HTTPS_HEADER_SIZE_THRESHOLD]
    if not large_outbound:
        return []

    total_bytes = sum(nc.bytes_sent for nc in large_outbound)
    hosts = list(dict.fromkeys(nc.host for nc in large_outbound))

    return [Finding(
        rule_id="L4-EXFIL-002",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        package=profile.package,
        message=f"Large outbound data detected: {total_bytes} bytes to {len(hosts)} host(s) — possible HTTPS header exfiltration",
        evidence=f"bytes_sent={total_bytes}, hosts={', '.join(hosts[:5])}",
        remediation=(
            "Review outbound HTTPS traffic. Large outbound payloads "
            "may indicate data exfiltration via HTTP headers or request bodies. "
            "Restrict network access in sandbox policy."
        ),
        references=["https://attack.mitre.org/techniques/T1071/001/"],
    )]


def _detect_error_channel_exfiltration(profile: BehavioralProfile) -> List[Finding]:
    """L4-EXFIL-003: Detect error-channel data exfiltration."""
    total_sent = profile.total_bytes_sent
    if total_sent < EXFIL_BYTES_THRESHOLD:
        return []

    return [Finding(
        rule_id="L4-EXFIL-003",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        package=profile.package,
        message=f"Large outbound data ({total_sent} bytes) detected — possible error-channel exfiltration",
        evidence=f"total_bytes_sent={total_sent}",
        remediation=(
            "Review outbound data volume. Large egress despite sandbox "
            "restrictions may indicate error-channel exfiltration. "
            "Consider adding egress bandwidth limits to sandbox policy."
        ),
        references=["https://attack.mitre.org/techniques/T1048/"],
    )]
