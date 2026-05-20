"""
L4 Honeypot Detection Rules.

L4-HONEY-001: Canary file accessed
L4-HONEY-002: Canary DNS lookup
L4-HONEY-003: Canary env token read

Deterministic: if a canary was touched, it was touched. No guessing.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

from ..models import Baseline, BehavioralProfile, Finding, Severity, Confidence

logger = logging.getLogger("iron_dome.L4.rules.honeypot")


def detect_honeypot_touches(
    profile: BehavioralProfile,
    baselines: Optional[Dict[str, Baseline]] = None,
    canary_file_paths: Optional[List[str]] = None,
    canary_dns_domains: Optional[List[str]] = None,
    canary_env_keys: Optional[List[str]] = None,
) -> List[Finding]:
    """Detect honeypot canary touches in a behavioral profile."""
    findings: List[Finding] = []
    findings.extend(_detect_canary_file_access(profile, canary_file_paths or []))
    findings.extend(_detect_canary_dns(profile, canary_dns_domains or []))
    findings.extend(_detect_canary_env(profile, canary_env_keys or []))
    return findings


def _detect_canary_file_access(
    profile: BehavioralProfile,
    canary_paths: List[str],
) -> List[Finding]:
    """L4-HONEY-001: Detect canary file access."""
    if not canary_paths and not profile.canary_file_accesses:
        return []

    accessed = list(profile.canary_file_accesses)
    if not accessed and canary_paths:
        from pathlib import Path
        canary_set = set(canary_paths)
        canary_names = {Path(p).name for p in canary_paths}
        for op in profile.fs_ops:
            if op.path in canary_set or Path(op.path).name in canary_names:
                accessed.append(op.path)

    if not accessed:
        return []

    return [Finding(
        rule_id="L4-HONEY-001",
        severity=Severity.CRITICAL,
        confidence=Confidence.EXACT,
        package=profile.package,
        message=f"Canary file accessed: {len(accessed)} file(s) — strong indicator of data theft or reconnaissance",
        evidence=f"accessed_files={accessed[:5]}",
        remediation=(
            "This is a definitive signal. The package accessed planted canary "
            "files, indicating it is searching for sensitive data. Block all "
            "filesystem access in sandbox policy and investigate immediately."
        ),
        references=[
            "https://canarytokens.org/",
            "https://thinkst.com/canarytokens/",
        ],
    )]


def _detect_canary_dns(
    profile: BehavioralProfile,
    canary_domains: List[str],
) -> List[Finding]:
    """L4-HONEY-002: Detect canary DNS lookup."""
    if not canary_domains and not profile.canary_dns_lookups:
        return []

    looked_up = list(profile.canary_dns_lookups)
    if not looked_up and canary_domains:
        canary_set = set(canary_domains)
        for dq in profile.dns_queries:
            if dq.domain in canary_set:
                looked_up.append(dq.domain)
            elif any(dq.domain.endswith(f".{c}") for c in canary_set):
                looked_up.append(dq.domain)

    if not looked_up:
        return []

    return [Finding(
        rule_id="L4-HONEY-002",
        severity=Severity.CRITICAL,
        confidence=Confidence.EXACT,
        package=profile.package,
        message=f"Canary DNS lookup: {len(looked_up)} domain(s) — definitive DNS exfiltration indicator",
        evidence=f"looked_up_domains={looked_up[:5]}",
        remediation=(
            "This is a definitive signal. The package queried planted canary "
            "DNS domains, confirming DNS-based data exfiltration. Block all "
            "DNS in sandbox policy and investigate immediately."
        ),
        references=[
            "https://canarytokens.org/",
            "https://attack.mitre.org/techniques/T1071/004/",
        ],
    )]


def _detect_canary_env(
    profile: BehavioralProfile,
    canary_keys: List[str],
) -> List[Finding]:
    """L4-HONEY-003: Detect canary env token read."""
    if not canary_keys and not profile.canary_env_reads:
        return []

    read_keys = list(profile.canary_env_reads)

    if not read_keys:
        return []

    return [Finding(
        rule_id="L4-HONEY-003",
        severity=Severity.CRITICAL,
        confidence=Confidence.EXACT,
        package=profile.package,
        message=f"Canary env token read: {len(read_keys)} key(s) — environment variable theft detected",
        evidence=f"read_keys={read_keys[:5]}",
        remediation=(
            "This is a definitive signal. The package read planted canary "
            "environment variables, indicating credential theft. Block env "
            "access in sandbox policy and investigate immediately."
        ),
        references=[
            "https://canarytokens.org/",
            "https://attack.mitre.org/techniques/T1552/",
        ],
    )]
