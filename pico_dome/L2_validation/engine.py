"""
L2 Supply Chain Scanner — ScanEngine.

Orchestrates detector rules, collects findings, produces ScanResult.
Deterministic: same input, same output. No probabilistic guessing.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from .models import Finding, ScanResult, ScanStats

logger = logging.getLogger("pico_dome.L2.engine")

# Type alias: a detector rule is a callable that takes a target path
# and returns a list of Findings.
DetectorRule = Callable[[Path], list[Finding]]


class ScanEngine:
    """
    Deterministic supply chain scanner engine.

    Register detector rules, then scan a target path.
    Each rule runs independently — composable, no side-effects between rules.
    """

    def __init__(self) -> None:
        self._rules: dict[str, DetectorRule] = {}

    def register(self, rule_id: str, rule: DetectorRule) -> ScanEngine:
        """Register a detector rule. Returns self for chaining."""
        self._rules[rule_id] = rule
        return self

    def unregister(self, rule_id: str) -> None:
        """Remove a detector rule."""
        self._rules.pop(rule_id, None)

    def list_rules(self) -> list[str]:
        """Return sorted list of registered rule IDs."""
        return sorted(self._rules.keys())

    def scan(
        self,
        target: str | Path,
        rules: Sequence[str] | None = None,
    ) -> ScanResult:
        """
        Run a scan on target path.

        Args:
            target: Filesystem path to scan (project root, node_modules, etc.)
            rules: Optional subset of rule IDs to run. None = all rules.

        Returns:
            ScanResult with all findings and aggregate stats.
        """
        target_path = Path(target).resolve()
        if not target_path.exists():
            logger.error("Scan target does not exist: %s", target_path)
            return ScanResult(
                target=str(target_path),
                findings=[],
                stats=ScanStats(),
            )

        selected_rules = (
            {k: v for k, v in self._rules.items() if k in rules}
            if rules
            else dict(self._rules)
        )

        if not selected_rules:
            logger.warning("No detector rules selected for scan")
            return ScanResult(
                target=str(target_path),
                findings=[],
                stats=ScanStats(),
            )

        logger.info(
            "Starting scan: target=%s rules=%s",
            target_path,
            list(selected_rules.keys()),
        )

        start_ms = _now_ms()
        all_findings: list[Finding] = []
        packages_scanned = 0
        files_scanned = 0

        # Count packages if node_modules or similar structure
        nm_path = target_path / "node_modules"
        if nm_path.is_dir():
            packages_scanned = sum(
                1 for d in nm_path.iterdir() if d.is_dir() and not d.name.startswith(".")
            )

        for rule_id, rule_fn in selected_rules.items():
            try:
                findings = rule_fn(target_path)
                all_findings.extend(findings)
                logger.debug(
                    "Rule %s: %d findings", rule_id, len(findings)
                )
            except Exception:
                logger.exception("Rule %s raised an exception", rule_id)

        duration = _now_ms() - start_ms

        # Count files scanned (best-effort)
        files_scanned = sum(1 for _ in target_path.rglob("*") if _.is_file()) if target_path.is_dir() else 1

        # Build stats
        by_severity: dict[str, int] = {}
        by_rule: dict[str, int] = {}
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
            findings=all_findings,
            stats=stats,
        )

        logger.info(
            "Scan complete: %d findings in %dms",
            len(all_findings),
            int(duration),
        )

        return result


def create_default_engine() -> ScanEngine:
    """Create a ScanEngine with all built-in detector rules registered."""
    from .rules.dep_confusion import detect_dep_confusion
    from .rules.fork_drift import detect_fork_drift
    from .rules.manifest import detect_manifest_issues
    from .rules.obfuscation import detect_obfuscation
    from .rules.post_install import detect_post_install_scripts
    from .rules.typosquat import detect_typosquat

    engine = ScanEngine()
    engine.register("L2-POST-001", detect_post_install_scripts)
    engine.register("L2-OBFS-001", detect_obfuscation)
    engine.register("L2-DEPC-001", detect_dep_confusion)
    engine.register("L2-TYPO-001", detect_typosquat)
    engine.register("L2-MANI-001", detect_manifest_issues)
    engine.register("L2-FORK-001", detect_fork_drift)
    return engine


def _now_ms() -> float:
    return time.monotonic() * 1000
