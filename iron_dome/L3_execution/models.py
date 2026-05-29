"""
L3 Execution Sandbox — Data Models.

Deterministic sandbox verdict engine. Every operation gets ALLOW, DENY, or AUDIT.
Same policy + same operation = same verdict. No guessing.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    AUDIT = "AUDIT"


class RuleID(str, Enum):
    L3_SYS_001 = "L3-SYS-001"   # Forbidden syscall
    L3_NET_001 = "L3-NET-001"   # Outbound network blocked
    L3_NET_002 = "L3-NET-002"   # DNS exfiltration
    L3_FS_001 = "L3-FS-001"     # Filesystem write denied
    L3_FS_002 = "L3-FS-002"     # Filesystem read denied
    L3_PROC_001 = "L3-PROC-001" # Process spawn denied
    L3_PROC_002 = "L3-PROC-002" # Process signal denied
    L3_RES_001 = "L3-RES-001"   # CPU limit exceeded
    L3_RES_002 = "L3-RES-002"   # Memory limit exceeded
    L3_RES_003 = "L3-RES-003"   # Wall-time exceeded


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class PolicyRule:
    """A single policy rule — deny-by-default, explicitly allowlisted."""
    rule_id: RuleID
    action: Verdict
    description: str = ""
    patterns: list[str] = field(default_factory=list)
    severity: Severity = Severity.HIGH


@dataclass
class Policy:
    """Complete sandbox policy loaded from YAML."""
    name: str = "default"
    version: str = "1.0"
    description: str = ""
    rules: list[PolicyRule] = field(default_factory=list)
    # Allowlists
    network_allowlist: list[str] = field(default_factory=list)
    filesystem_write_allowlist: list[str] = field(default_factory=list)
    filesystem_read_allowlist: list[str] = field(default_factory=list)
    process_allowlist: list[str] = field(default_factory=list)
    # Resource limits
    cpu_limit_seconds: float = 30.0
    memory_limit_mb: int = 512
    wall_time_limit_seconds: float = 60.0
    # DNS settings
    dns_allowlist: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "rules": [{"rule_id": r.rule_id.value, "action": r.action.value,
                        "description": r.description, "patterns": r.patterns,
                        "severity": r.severity.value} for r in self.rules],
            "network_allowlist": self.network_allowlist,
            "filesystem_write_allowlist": self.filesystem_write_allowlist,
            "filesystem_read_allowlist": self.filesystem_read_allowlist,
            "process_allowlist": self.process_allowlist,
            "cpu_limit_seconds": self.cpu_limit_seconds,
            "memory_limit_mb": self.memory_limit_mb,
            "wall_time_limit_seconds": self.wall_time_limit_seconds,
            "dns_allowlist": self.dns_allowlist,
        }


@dataclass(frozen=True)
class SandboxEvent:
    """A single event observed during sandboxed execution."""
    timestamp: str
    rule_id: RuleID
    verdict: Verdict
    operation: str
    detail: str
    path: str | None = None
    address: str | None = None


@dataclass
class SandboxResult:
    """Complete result of a sandboxed execution."""
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    command: list[str] = field(default_factory=list)
    policy: Policy | None = None
    events: list[SandboxEvent] = field(default_factory=list)
    overall_verdict: Verdict = Verdict.ALLOW
    exit_code: int | None = None
    duration_ms: int = 0
    peak_memory_mb: float = 0.0
    cpu_time_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "command": self.command,
            "policy": self.policy.to_dict() if self.policy else None,
            "events": [
                {
                    "timestamp": e.timestamp,
                    "rule_id": e.rule_id.value,
                    "verdict": e.verdict.value,
                    "operation": e.operation,
                    "detail": e.detail,
                    "path": e.path,
                    "address": e.address,
                }
                for e in self.events
            ],
            "overall_verdict": self.overall_verdict.value,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "peak_memory_mb": self.peak_memory_mb,
            "cpu_time_seconds": self.cpu_time_seconds,
        }
