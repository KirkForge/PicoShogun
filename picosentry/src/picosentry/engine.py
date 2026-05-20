"""
Scanner engine — deterministic, offline, pure-function rules.

Orchestrates detector rules, collects findings, produces ScanResult.
Same input + same corpus = same output. No global state. No HTTP at scan time.
"""
from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from .models import Finding, ScanResult, ScanStats, Severity

logger = logging.getLogger("picosentry.engine")

# A detector rule is a pure function: (target_path, corpus_dir) → List[Finding]
DetectorRule = Callable[[Path, Path], List[Finding]]


class ScanEngine:
    """
    Deterministic supply chain scanner engine.

    Register detector rules, then scan a target path.
    Each rule runs independently — composable, no side-effects between rules.
    Rules receive (target_path, corpus_dir) — no HTTP, no global state.
    """

    def __init__(self, corpus_dir: Optional[Path] = None) -> None:
        self._rules: Dict[str, DetectorRule] = {}
        self._corpus_dir = corpus_dir or Path(__file__).parent / "corpus"
        self._corpus_version = self._compute_corpus_version()

    def _compute_corpus_version(self) -> str:
        """Compute deterministic corpus version from corpus file hashes.

        sha256 of all corpus files (sorted by path) → first 12 hex chars.
        Same corpus content = same version. Corpus changes = different version.
        """
        h = hashlib.sha256()
        corpus_files = sorted(self._corpus_dir.rglob("*.json"))
        if not corpus_files:
            return "0.1.0-empty"
        for f in corpus_files:
            try:
                h.update(f.read_bytes())
            except OSError:
                continue
        return h.hexdigest()[:12]

    def register(self, rule_id: str, rule: DetectorRule) -> "ScanEngine":
        """Register a detector rule. Returns self for chaining."""
        self._rules[rule_id] = rule
        return self

    def unregister(self, rule_id: str) -> None:
        """Remove a detector rule."""
        self._rules.pop(rule_id, None)

    def list_rules(self) -> List[str]:
        """Return sorted list of registered rule IDs."""
        return sorted(self._rules.keys())

    def scan(
        self,
        target: str | Path,
        rules: Optional[Sequence[str]] = None,
    ) -> ScanResult:
        """
        Run a deterministic scan on target path.

        Args:
            target: Filesystem path to scan (project root, node_modules, etc.)
            rules: Optional subset of rule IDs to run. None = all rules.

        Returns:
            ScanResult with sorted findings and aggregate stats.
        """
        target_path = Path(target).resolve()
        if not target_path.exists():
            logger.error("Scan target does not exist: %s", target_path)
            return ScanResult(target=str(target_path))

        selected_rules = (
            {k: v for k, v in self._rules.items() if k in rules}
            if rules
            else dict(self._rules)
        )

        if not selected_rules:
            logger.warning("No detector rules selected for scan")
            return ScanResult(target=str(target_path))

        logger.info(
            "Starting scan: target=%s rules=%s corpus=%s",
            target_path,
            list(selected_rules.keys()),
            self._corpus_dir,
        )

        start_ms = _now_ms()
        all_findings: List[Finding] = []
        packages_scanned = 0

        # Count packages if node_modules or similar structure
        nm_path = target_path / "node_modules"
        if nm_path.is_dir():
            packages_scanned = sum(
                1 for d in nm_path.iterdir() if d.is_dir() and not d.name.startswith(".")
            )

        for rule_id in sorted(selected_rules.keys()):
            rule_fn = selected_rules[rule_id]
            try:
                findings = rule_fn(target_path, self._corpus_dir)
                all_findings.extend(findings)
                logger.debug("Rule %s: %d findings", rule_id, len(findings))
            except Exception:
                logger.exception("Rule %s raised an exception", rule_id)

        duration = _now_ms() - start_ms

        # Count files scanned (best-effort)
        if target_path.is_dir():
            files_scanned = sum(
                1 for _ in target_path.rglob("*") if _.is_file()
            )
        else:
            files_scanned = 1

        # Build stats
        by_severity: Dict[str, int] = {}
        by_rule: Dict[str, int] = {}
        for f in all_findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

        stats = ScanStats(
            packages_scanned=packages_scanned,
            files_scanned=files_scanned,
            duration_ms=int(duration),
            findings_by_severity=by_severity,
            findings_by_rule=by_rule,
        )

        result = ScanResult(
            target=str(target_path),
            corpus_version=self._corpus_version,
            findings=all_findings,
            stats=stats,
        )

        logger.info(
            "Scan complete: %d findings in %dms",
            len(all_findings),
            int(duration),
        )

        return result


def create_default_engine(corpus_dir: Optional[Path] = None) -> ScanEngine:
    """Create a ScanEngine with all built-in detector rules registered."""
    from .rules.post_install import detect_post_install_scripts
    from .rules.obfuscation import detect_obfuscation
    from .rules.dep_confusion import detect_dep_confusion
    from .rules.typosquat import detect_typosquat
    from .rules.manifest import detect_manifest_issues
    from .rules.fork_drift import detect_fork_drift
    from .rules.credential_read import detect_credential_reading
    from .rules.lockfile_drift import detect_lockfile_drift
    from .rules.bundled_shadow import detect_bundled_shadows
    from .rules.maintainer_change import detect_maintainer_changes
    from .rules.provenance import detect_provenance_issues
    from .rules.pnpm_config import scan as detect_pnpm_config
    from .rules.license import detect_license_issues
    from .rules.engine import detect_engine_issues
    from .rules.sideloading import detect_sideloading

    engine = ScanEngine(corpus_dir=corpus_dir)
    engine.register("L2-POST-001", detect_post_install_scripts)
    engine.register("L2-OBFS-001", detect_obfuscation)
    engine.register("L2-DEPC-001", detect_dep_confusion)
    engine.register("L2-TYPO-001", detect_typosquat)
    engine.register("L2-MANI-001", detect_manifest_issues)
    engine.register("L2-FORK-001", detect_fork_drift)
    engine.register("L2-CRED-001", detect_credential_reading)
    engine.register("L2-LOCK-001", detect_lockfile_drift)
    engine.register("L2-BUND-001", detect_bundled_shadows)
    engine.register("L2-PROV-001", detect_provenance_issues)
    engine.register("L2-MAINT-001", detect_maintainer_changes)
    engine.register("L2-PNPM-001", detect_pnpm_config)
    engine.register("L2-LICENSE-001", detect_license_issues)
    engine.register("L2-ENGIN-001", detect_engine_issues)
    engine.register("L2-SIDELOAD-001", detect_sideloading)
    return engine


def _now_ms() -> float:
    return time.monotonic() * 1000