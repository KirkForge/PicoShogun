"""
L4 Behavioral Analysis — Data Models.

Deterministic behavioral profiling from L3 sandbox traces.
No ML. No probabilistic guessing. Same trace + same baseline = same verdict.
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


class BehavioralVerdict(str, Enum):
    """Overall verdict for a behavioral analysis run."""
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class RuleID(str, Enum):
    # Timing analysis
    L4_TIME_001 = "L4-TIME-001"  # Sleep evasion (unnatural delays)
    L4_TIME_002 = "L4-TIME-002"  # Timing side-channel (timing leaks)
    L4_TIME_003 = "L4-TIME-003"  # Burst anomalies (sudden spikes)
    # Covert channel / exfiltration
    L4_EXFIL_001 = "L4-EXFIL-001"  # DNS exfiltration
    L4_EXFIL_002 = "L4-EXFIL-002"  # HTTPS header exfiltration
    L4_EXFIL_003 = "L4-EXFIL-003"  # Error channel exfiltration
    # Entropy analysis
    L4_ENTROPY_001 = "L4-ENTROPY-001"  # High-entropy egress data (encrypted exfil)
    L4_ENTROPY_002 = "L4-ENTROPY-002"  # Entropy spike vs baseline
    # Honeypot detection
    L4_HONEY_001 = "L4-HONEY-001"  # Canary file accessed
    L4_HONEY_002 = "L4-HONEY-002"  # Canary DNS lookup
    L4_HONEY_003 = "L4-HONEY-003"  # Canary env token read
    # Baseline drift
    L4_BASE_001 = "L4-BASE-001"  # Call frequency drift
    L4_BASE_002 = "L4-BASE-002"  # Network profile drift
    L4_BASE_003 = "L4-BASE-003"  # Resource curve drift (DTW)


@dataclass(frozen=True)
class Finding:
    """A single behavioral finding from an L4 detector rule."""
    rule_id: str
    severity: Severity
    confidence: Confidence
    package: str
    message: str
    evidence: str
    remediation: str
    references: list[str] = field(default_factory=list)
    file: str = ""
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


@dataclass
class TimingPoint:
    """A single timing measurement from sandbox trace."""
    timestamp_ms: float
    operation: str  # syscall, network, dns, fs, spawn
    duration_ms: float = 0.0


@dataclass
class NetworkCall:
    """A network call observed in sandbox trace."""
    host: str
    port: int
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    timestamp_ms: float = 0.0


@dataclass
class DNSQuery:
    """A DNS query observed in sandbox trace."""
    domain: str
    query_type: str = "A"
    response_size: int = 0
    timestamp_ms: float = 0.0


@dataclass
class FilesystemOp:
    """A filesystem operation observed in sandbox trace."""
    operation: str  # read, write, rename, unlink, etc.
    path: str
    size_bytes: int = 0
    timestamp_ms: float = 0.0


@dataclass
class ProcessSpawn:
    """A process spawn observed in sandbox trace."""
    command: str
    args: list[str] = field(default_factory=list)
    exit_code: int | None = None
    timestamp_ms: float = 0.0


@dataclass
class ResourceSample:
    """A resource usage sample from sandbox trace."""
    timestamp_ms: float
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    net_bytes_sent: int = 0
    net_bytes_recv: int = 0


@dataclass
class BehavioralProfile:
    """
    Aggregated behavioral profile extracted from L3 sandbox trace.
    This is the core data structure that rules operate on.
    """
    package: str
    command: list[str] = field(default_factory=list)
    duration_ms: int = 0

    # Timing data
    timing_points: list[TimingPoint] = field(default_factory=list)
    sleep_intervals: list[float] = field(default_factory=list)  # ms gaps > threshold

    # Network
    network_calls: list[NetworkCall] = field(default_factory=list)
    dns_queries: list[DNSQuery] = field(default_factory=list)

    # Filesystem
    fs_ops: list[FilesystemOp] = field(default_factory=list)

    # Process
    spawns: list[ProcessSpawn] = field(default_factory=list)

    # Resource curve (time-series of CPU/mem/net)
    resource_samples: list[ResourceSample] = field(default_factory=list)

    # Entropy measurements
    egress_entropy: float = 0.0  # Shannon entropy of outbound data
    egress_sizes: list[int] = field(default_factory=list)  # sizes of egress chunks
    dns_entropy: float = 0.0  # Shannon entropy of DNS query names

    # Honeypot touches
    canary_file_accesses: list[str] = field(default_factory=list)
    canary_dns_lookups: list[str] = field(default_factory=list)
    canary_env_reads: list[str] = field(default_factory=list)

    # Call frequencies (operation -> count)
    call_frequencies: dict[str, int] = field(default_factory=dict)

    # Computed stats
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    peak_memory_mb: float = 0.0
    total_cpu_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "command": self.command,
            "duration_ms": self.duration_ms,
            "timing_points": [
                {"timestamp_ms": t.timestamp_ms, "operation": t.operation, "duration_ms": t.duration_ms}
                for t in self.timing_points
            ],
            "sleep_intervals": self.sleep_intervals,
            "network_calls": [
                {"host": n.host, "port": n.port, "protocol": n.protocol,
                 "bytes_sent": n.bytes_sent, "bytes_received": n.bytes_received,
                 "timestamp_ms": n.timestamp_ms}
                for n in self.network_calls
            ],
            "dns_queries": [
                {"domain": d.domain, "query_type": d.query_type,
                 "response_size": d.response_size, "timestamp_ms": d.timestamp_ms}
                for d in self.dns_queries
            ],
            "fs_ops": [
                {"operation": f.operation, "path": f.path, "size_bytes": f.size_bytes,
                 "timestamp_ms": f.timestamp_ms}
                for f in self.fs_ops
            ],
            "spawns": [
                {"command": s.command, "args": s.args, "exit_code": s.exit_code,
                 "timestamp_ms": s.timestamp_ms}
                for s in self.spawns
            ],
            "resource_samples": [
                {"timestamp_ms": r.timestamp_ms, "cpu_percent": r.cpu_percent,
                 "memory_mb": r.memory_mb, "net_bytes_sent": r.net_bytes_sent,
                 "net_bytes_recv": r.net_bytes_recv}
                for r in self.resource_samples
            ],
            "egress_entropy": self.egress_entropy,
            "egress_sizes": self.egress_sizes,
            "dns_entropy": self.dns_entropy,
            "canary_file_accesses": self.canary_file_accesses,
            "canary_dns_lookups": self.canary_dns_lookups,
            "canary_env_reads": self.canary_env_reads,
            "call_frequencies": self.call_frequencies,
            "total_bytes_sent": self.total_bytes_sent,
            "total_bytes_received": self.total_bytes_received,
            "peak_memory_mb": self.peak_memory_mb,
            "total_cpu_time_ms": self.total_cpu_time_ms,
        }


@dataclass
class Baseline:
    """
    A behavioral baseline for a known-good workload.
    Used for drift comparison.
    """
    name: str
    description: str = ""
    version: str = "1.0"

    # Expected call frequencies (operation -> (mean, stddev))
    call_frequencies: dict[str, dict[str, float]] = field(default_factory=dict)

    # Expected network profile
    network_hosts: list[str] = field(default_factory=list)
    dns_domains: list[str] = field(default_factory=list)
    avg_bytes_sent: int = 0
    avg_bytes_received: int = 0

    # Expected resource ranges
    avg_duration_ms: int = 0
    std_duration_ms: int = 0
    avg_peak_memory_mb: float = 0.0
    std_peak_memory_mb: float = 0.0
    avg_cpu_time_ms: float = 0.0
    std_cpu_time_ms: float = 0.0

    # Expected egress entropy range
    avg_egress_entropy: float = 0.0
    std_egress_entropy: float = 0.0

    # Resource curve template (normalized time -> expected CPU/mem)
    resource_curve: list[dict[str, float]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "call_frequencies": self.call_frequencies,
            "network_hosts": self.network_hosts,
            "dns_domains": self.dns_domains,
            "avg_bytes_sent": self.avg_bytes_sent,
            "avg_bytes_received": self.avg_bytes_received,
            "avg_duration_ms": self.avg_duration_ms,
            "std_duration_ms": self.std_duration_ms,
            "avg_peak_memory_mb": self.avg_peak_memory_mb,
            "std_peak_memory_mb": self.std_peak_memory_mb,
            "avg_cpu_time_ms": self.avg_cpu_time_ms,
            "std_cpu_time_ms": self.std_cpu_time_ms,
            "avg_egress_entropy": self.avg_egress_entropy,
            "std_egress_entropy": self.std_egress_entropy,
            "resource_curve": self.resource_curve,
        }


@dataclass
class DriftResult:
    """Result of comparing a profile against a baseline."""
    baseline_name: str
    call_frequency_drift: float = 0.0  # 0.0 = no drift, 1.0 = complete drift
    network_drift: float = 0.0
    resource_drift: float = 0.0  # DTW distance normalized to 0..1
    entropy_drift: float = 0.0
    duration_drift: float = 0.0  # z-score of duration vs baseline

    def to_dict(self) -> dict:
        return {
            "baseline_name": self.baseline_name,
            "call_frequency_drift": self.call_frequency_drift,
            "network_drift": self.network_drift,
            "resource_drift": self.resource_drift,
            "entropy_drift": self.entropy_drift,
            "duration_drift": self.duration_drift,
        }


@dataclass
class AnalysisStats:
    """Aggregate statistics for a behavioral analysis run."""
    events_analyzed: int = 0
    network_calls_analyzed: int = 0
    dns_queries_analyzed: int = 0
    fs_ops_analyzed: int = 0
    spawns_analyzed: int = 0
    duration_ms: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_rule: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "events_analyzed": self.events_analyzed,
            "network_calls_analyzed": self.network_calls_analyzed,
            "dns_queries_analyzed": self.dns_queries_analyzed,
            "fs_ops_analyzed": self.fs_ops_analyzed,
            "spawns_analyzed": self.spawns_analyzed,
            "duration_ms": self.duration_ms,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_rule": self.findings_by_rule,
        }


@dataclass
class AnalysisResult:
    """Complete result of a behavioral analysis run."""
    analysis_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    target: str = ""
    engine_version: str = "0.1.0"
    findings: list[Finding] = field(default_factory=list)
    profile: BehavioralProfile | None = None
    drift_results: list[DriftResult] = field(default_factory=list)
    overall_verdict: BehavioralVerdict = BehavioralVerdict.CLEAN
    stats: AnalysisStats = field(default_factory=AnalysisStats)

    def to_dict(self) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "timestamp": self.timestamp,
            "target": self.target,
            "engine_version": self.engine_version,
            "findings": [f.to_dict() for f in self.findings],
            "profile": self.profile.to_dict() if self.profile else None,
            "drift_results": [d.to_dict() for d in self.drift_results],
            "overall_verdict": self.overall_verdict.value,
            "stats": self.stats.to_dict(),
        }
