"""
L3 Policy DSL — YAML deny-by-default policy loader.

Policies define what a sandboxed process CAN do. Everything else is DENY.
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml

from .models import Policy, PolicyRule, RuleID, Severity, Verdict

logger = logging.getLogger("pico_dome.L3.policy_loader")

# Default deny-by-default policy.
DEFAULT_POLICY_YAML = """\
name: default
version: "1.0"
description: "Deny-by-default sandbox policy"
rules:
  - rule_id: L3-SYS-001
    action: DENY
    description: "Block dangerous syscalls (execve, fork, clone, ptrace, mount)"
    patterns: ["execve", "fork", "clone", "ptrace", "mount", "umount2",
                "reboot", "kexec_load", "init_module", "delete_module",
                "keyctl", "request_key", "add_key", "swapon", "swapoff"]
    severity: CRITICAL

  - rule_id: L3-NET-001
    action: DENY
    description: "Block all outbound network connections not in allowlist"
    patterns: ["connect"]
    severity: HIGH

  - rule_id: L3-NET-002
    action: AUDIT
    description: "Flag DNS lookups to non-allowlisted domains"
    patterns: ["dns"]
    severity: MEDIUM

  - rule_id: L3-FS-001
    action: DENY
    description: "Block filesystem writes outside allowlist"
    patterns: ["write", "rename", "unlink", "chmod", "chown", "mkdir", "rmdir",
                "symlink", "link", "truncate", "mknod"]
    severity: HIGH

  - rule_id: L3-FS-002
    action: DENY
    description: "Block filesystem reads outside allowlist"
    patterns: ["read"]
    severity: MEDIUM

  - rule_id: L3-PROC-001
    action: DENY
    description: "Block process spawning not in allowlist"
    patterns: ["spawn"]
    severity: CRITICAL

  - rule_id: L3-PROC-002
    action: DENY
    description: "Block sending signals to other processes"
    patterns: ["kill", "tgkill", "tkill", "rt_sigqueueinfo"]
    severity: HIGH

  - rule_id: L3-RES-001
    action: DENY
    description: "CPU time limit exceeded"
    severity: HIGH

  - rule_id: L3-RES-002
    action: DENY
    description: "Memory limit exceeded"
    severity: HIGH

  - rule_id: L3-RES-003
    action: DENY
    description: "Wall-time limit exceeded"
    severity: MEDIUM

# Explicit allowlists — anything not listed is denied.
network_allowlist: []
filesystem_write_allowlist:
  - "/tmp"
  - "/dev/null"
filesystem_read_allowlist:
  - "/usr"
  - "/lib"
  - "/lib64"
  - "/etc/alternatives"
  - "/etc/ld.so"
process_allowlist: []
dns_allowlist: []
cpu_limit_seconds: 30
memory_limit_mb: 512
wall_time_limit_seconds: 60
"""


def load_policy(path: str | Path | None = None) -> Policy:
    """
    Load a sandbox policy from a YAML file.
    If path is None, loads the built-in default policy.
    """
    if path is None:
        data = yaml.safe_load(DEFAULT_POLICY_YAML)
    else:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Policy file not found: {p}")
        data = yaml.safe_load(p.read_text(encoding="utf-8"))

    return _parse_policy(data)


def _parse_policy(data: dict) -> Policy:
    """Parse a policy dict into a Policy object."""
    rules: list[PolicyRule] = []
    for r in data.get("rules", []):
        rule_id_str = r.get("rule_id", "")
        try:
            rule_id = RuleID(rule_id_str)
        except ValueError:
            logger.warning("Unknown rule ID %s, skipping", rule_id_str)
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

        rules.append(PolicyRule(
            rule_id=rule_id,
            action=action,
            description=r.get("description", ""),
            patterns=r.get("patterns", []),
            severity=severity,
        ))

    return Policy(
        name=data.get("name", "unnamed"),
        version=str(data.get("version", "1.0")),
        description=data.get("description", ""),
        rules=rules,
        network_allowlist=data.get("network_allowlist", []),
        filesystem_write_allowlist=data.get("filesystem_write_allowlist", []),
        filesystem_read_allowlist=data.get("filesystem_read_allowlist", []),
        process_allowlist=data.get("process_allowlist", []),
        cpu_limit_seconds=float(data.get("cpu_limit_seconds", 30)),
        memory_limit_mb=int(data.get("memory_limit_mb", 512)),
        wall_time_limit_seconds=float(data.get("wall_time_limit_seconds", 60)),
        dns_allowlist=data.get("dns_allowlist", []),
    )


def write_default_policy(path: str | Path) -> Path:
    """Write the default policy YAML to a file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(DEFAULT_POLICY_YAML, encoding="utf-8")
    return p
