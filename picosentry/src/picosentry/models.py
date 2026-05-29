"""
Scanner data models — deterministic by construction.

- Findings are frozen dataclasses (immutable)
- No uuid4/random in output — scan_id is sha256(target + corpus_version + timestamp_rounded_to_hour)
- No timestamps in finding bodies — timestamp lives on ScanResult only
- Sorted output: findings sorted by (rule_id, package, file, line)
- to_dict() uses sorted keys, no random IDs
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


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
    """A single deterministic finding from a detector rule.

    Immutable by design. Same input + same rule = same Finding.
    No prose summaries — the consumer formats.
    """
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

    def fingerprint(self) -> tuple:
        """Deterministic fingerprint for baseline matching.

        Two findings match if they have the same fingerprint:
        (rule_id, package, file). This is used for --baseline
        to suppress known findings.
        """
        return (self.rule_id, self.package, self.file)

    def sort_key(self) -> tuple:
        """Deterministic sort key for stable ordering."""
        return (self.rule_id, self.package, self.file, self.line or 0)

    def to_dict(self) -> dict:
        """Deterministic dict — sorted keys, no random IDs, no timestamps."""
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "package": self.package,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
        if self.references:
            d["references"] = self.references
        return d


@dataclass
class BaselineResult:
    """Result of applying baseline filtering to a scan.

    Tracks how many findings were suppressed and what remains.
    Deterministic: same baseline + same findings = same result.
    """
    original_count: int = 0
    suppressed_count: int = 0
    remaining: list[Finding] = field(default_factory=list)

    @property
    def new_count(self) -> int:
        return len(self.remaining)


def load_baseline(path: Path) -> set:
    """Load a baseline file and return set of finding fingerprints.

    A baseline is a previous scan JSON output. Findings matching
    (rule_id, package, file) tuples from the baseline are "known"
    and will be suppressed.

    Also supports simple ignore format: one rule_id per line,
    optionally with package pattern (rule_id:package_pattern).
    Lines starting with # are comments. Blank lines are skipped.
    """
    text = path.read_text(encoding="utf-8")

    # Try JSON format first (previous scan output)
    try:
        data = json.loads(text)
        if "findings" in data:
            fingerprints = set()
            for f in data["findings"]:
                key = (f.get("rule_id", ""), f.get("package", ""), f.get("file", ""))
                fingerprints.add(key)
            return fingerprints
    except json.JSONDecodeError:
        pass

    # Simple ignore format: one entry per line
    # Format: RULE_ID or RULE_ID:package_pattern or RULE_ID:package_pattern:file_pattern
    fingerprints = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        rule_id = parts[0].strip()
        package = parts[1].strip() if len(parts) > 1 else ""
        file_path = parts[2].strip() if len(parts) > 2 else ""
        fingerprints.add((rule_id, package, file_path))

    return fingerprints


def apply_baseline(result: ScanResult, baseline_fingerprints: set) -> BaselineResult:
    """Filter findings against a baseline, suppressing known findings.

    Args:
        result: Original scan result with all findings.
        baseline_fingerprints: Set of (rule_id, package, file) tuples from baseline.

    Returns:
        BaselineResult with suppressed/remaining counts and filtered findings.
    """
    remaining = []
    suppressed = 0
    for f in result.findings:
        fp = f.fingerprint()
        # Check exact match first
        if fp in baseline_fingerprints:
            suppressed += 1
            continue
        # Check partial matches (rule_id only, or rule_id+package_pattern)
        matched = False
        for rule_id, package, file_path in baseline_fingerprints:
            if rule_id == fp[0]:
                # rule_id match — check if package/file also match
                if (not package or package == fp[1]) and (not file_path or file_path == fp[2]):
                    matched = True
                    break
        if matched:
            suppressed += 1
        else:
            remaining.append(f)

    return BaselineResult(
        original_count=len(result.findings),
        suppressed_count=suppressed,
        remaining=remaining,
    )


@dataclass
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
            "findings_by_severity": dict(sorted(self.findings_by_severity.items())),
            "findings_by_rule": dict(sorted(self.findings_by_rule.items())),
        }


@dataclass
class ScanResult:
    """Complete result of a supply chain scan.

    Deterministic: same target + same corpus = same scan_id.
    Findings are sorted by (rule_id, package, file, line).
    """
    target: str = ""
    engine_version: str = "0.5.0"
    corpus_version: str = ""  # Set by ScanEngine from corpus hash
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    def recompute_stats(self) -> None:
        """Recompute stats from current findings list (after filtering)."""
        by_sev: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        self.stats.findings_by_severity = dict(sorted(by_sev.items()))
        self.stats.findings_by_rule = dict(sorted(by_rule.items()))

    @property
    def scan_id(self) -> str:
        """Deterministic scan ID: sha256(target + corpus_version + engine_version)."""
        raw = f"{self.target}:{self.corpus_version}:{self.engine_version}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        """Deterministic dict for JSON serialization — sorted keys, no random IDs."""
        sorted_findings = sorted(self.findings, key=lambda f: f.sort_key())
        return dict(sorted({
            "scan_id": self.scan_id,
            "engine_version": self.engine_version,
            "corpus_version": self.corpus_version,
            "target": self.target,
            "findings": [f.to_dict() for f in sorted_findings],
            "stats": self.stats.to_dict(),
        }.items()))

    def to_json(self, indent: int = 2) -> str:
        """Deterministic JSON — sorted keys, no random content."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)

    def to_ml_context(self, token_budget: int = 4096) -> str:
        """Compact structured output for LLM tool results.

        Token-budgeted, no narrative, no severity word inflation.
        Designed to be safe to inject into an agent's context without
        polluting reasoning or causing hallucinated fixes.
        """
        sorted_findings = sorted(self.findings, key=lambda f: f.sort_key())
        lines = [
            f"scan_id={self.scan_id}",
            f"corpus_version={self.corpus_version}",
            f"target={self.target}",
            f"findings={len(sorted_findings)}",
            "",
        ]
        for f in sorted_findings:
            line = f"[{f.severity.value}] {f.rule_id} {f.package} {f.file}"
            if f.line:
                line += f":{f.line}"
            line += f" | {f.evidence}"
            lines.append(line)

        output = "\n".join(lines)
        if len(output) > token_budget * 4:  # rough token estimate
            output = output[:token_budget * 4] + "\n[TRUNCATED]"
        return output
