"""
PicoSentry — deterministic supply-chain scanner for npm/pnpm.

Same inputs + same corpus version = same output. Every time.
No HTTP at scan time. No probabilistic heuristics. No narrative in findings.

Usage:
    from picosentry import ScanEngine, create_default_engine
    result = create_default_engine().scan("./my-project")
    print(result.to_json())
"""
from .engine import ScanEngine, create_default_engine
from .models import Finding, ScanResult, ScanStats, Severity, Confidence, BaselineResult, load_baseline, apply_baseline

__version__ = "0.5.0"
__all__ = [
    "ScanEngine",
    "create_default_engine",
    "Finding",
    "ScanResult",
    "ScanStats",
    "Severity",
    "Confidence",
    "BaselineResult",
    "load_baseline",
    "apply_baseline",
]