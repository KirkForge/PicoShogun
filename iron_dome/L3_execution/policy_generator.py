"""
L2 → L3 Policy Generator.

Auto-generates L3 sandbox policies from L2 static analysis findings.
E.g., a post-install script finding → sandbox with no network, no spawn,
filesystem write restricted to /tmp.
"""
from __future__ import annotations

from typing import List

from ..L2_validation.models import Finding, Severity
from .models import Policy, PolicyRule, RuleID, Verdict
from .policy_loader import DEFAULT_POLICY_YAML
import yaml


def generate_policy_from_findings(findings: List[Finding]) -> Policy:
    """
    Generate an L3 sandbox policy from L2 findings.

    Strategy:
    - Start with deny-by-default
    - Tighten restrictions based on finding severity and rule ID
    - Post-install script → restrict network, spawn, filesystem
    - Obfuscation → full lockdown (no network, no spawn, no write)
    - Typosquat → restrict network, DNS
    - Dependency confusion → restrict DNS to allowlist
    - Manifest issues → restrict spawn
    - Fork drift → restrict network
    """
    import copy

    # Load default policy as base
    base_data = yaml.safe_load(DEFAULT_POLICY_YAML)

    # Start with restrictive defaults
    policy = Policy(
        name="auto-generated-from-l2",
        version="1.0",
        description="Auto-generated L3 policy from L2 supply chain findings",
        network_allowlist=[],
        filesystem_write_allowlist=["/tmp"],
        filesystem_read_allowlist=["/usr", "/lib", "/lib64", "/etc/alternatives", "/etc/ld.so"],
        process_allowlist=[],
        dns_allowlist=[],
        cpu_limit_seconds=30,
        memory_limit_mb=512,
        wall_time_limit_seconds=60,
    )

    # Add rules from base
    base_policy_data = yaml.safe_load(DEFAULT_POLICY_YAML)
    for r in base_policy_data.get("rules", []):
        rule_id_str = r.get("rule_id", "")
        try:
            rule_id = RuleID(rule_id_str)
        except ValueError:
            continue

        action_str = r.get("action", "DENY")
        try:
            action = Verdict(action_str)
        except ValueError:
            action = Verdict.DENY

        severity_str = r.get("severity", "HIGH")
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.HIGH

        policy.rules.append(PolicyRule(
            rule_id=rule_id,
            action=action,
            description=r.get("description", ""),
            patterns=r.get("patterns", []),
            severity=severity,
        ))

    # Tighten based on findings
    has_post_install = False
    has_obfuscation = False
    has_typosquat = False
    has_dep_confusion = False
    has_manifest_issue = False
    has_fork_drift = False

    for f in findings:
        if f.rule_id == "L2-POST-001":
            has_post_install = True
        elif f.rule_id.startswith("L2-OBFS"):
            has_obfuscation = True
        elif f.rule_id == "L2-TYPO-001":
            has_typosquat = True
        elif f.rule_id == "L2-DEPC-001":
            has_dep_confusion = True
        elif f.rule_id.startswith("L2-MANI"):
            has_manifest_issue = True
        elif f.rule_id == "L2-FORK-001":
            has_fork_drift = True

    # Post-install scripts: no network, no spawn, restricted filesystem
    if has_post_install:
        policy.network_allowlist = []  # Block all outbound
        policy.process_allowlist = []   # Block all spawn
        policy.dns_allowlist = []      # Block all DNS
        policy.cpu_limit_seconds = 10
        policy.wall_time_limit_seconds = 30
        policy.description += " | Tightened: post-install scripts detected"

    # Obfuscation: full lockdown
    if has_obfuscation:
        policy.network_allowlist = []
        policy.process_allowlist = []
        policy.filesystem_write_allowlist = ["/dev/null"]
        policy.filesystem_read_allowlist = ["/usr", "/lib", "/lib64"]
        policy.dns_allowlist = []
        policy.cpu_limit_seconds = 5
        policy.memory_limit_mb = 128
        policy.wall_time_limit_seconds = 15
        policy.description += " | LOCKDOWN: obfuscated payloads detected"

    # Typosquat: restrict network and DNS
    if has_typosquat:
        policy.network_allowlist = []
        policy.dns_allowlist = []
        policy.description += " | Network restricted: typosquat detected"

    # Dependency confusion: DNS allowlist only
    if has_dep_confusion:
        policy.dns_allowlist = []
        policy.description += " | DNS restricted: dependency confusion risk"

    # Manifest issues: restrict spawn
    if has_manifest_issue:
        policy.process_allowlist = []
        policy.description += " | Spawn restricted: manifest issues detected"

    # Fork drift: restrict network
    if has_fork_drift:
        policy.network_allowlist = []
        policy.description += " | Network restricted: fork drift detected"

    return policy
