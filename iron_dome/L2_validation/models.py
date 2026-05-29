"""
L2 Supply Chain Scanner — Data Models.

Deterministic, zero-trust package scanning. No LLMs. No guessing.
Same input, same output. Every time.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    EXACT = "EXACT"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Finding:
    """A single deterministic finding from a detector rule."""
    rule_id: str
    severity: Severity
    confidence: Confidence
    package: str
    file: str
    message: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    line: int | None = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "package": self.package,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass(frozen=True)
class ScanStats:
    """Aggregate statistics for a scan run."""
    packages_scanned: int = 0
    files_scanned: int = 0
    duration_ms: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_rule: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "packages_scanned": self.packages_scanned,
            "files_scanned": self.files_scanned,
            "duration_ms": self.duration_ms,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_rule": self.findings_by_rule,
        }


@dataclass
class ScanResult:
    """Complete result of a supply chain scan."""
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    target: str = ""
    engine_version: str = "0.1.0"
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "target": self.target,
            "engine_version": self.engine_version,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats.to_dict(),
        }
