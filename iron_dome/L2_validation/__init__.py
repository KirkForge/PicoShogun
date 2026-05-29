"""
L2 Validation — Supply Chain Scanner.

Deterministic, zero-trust package scanning for CI/CD.
Same input, same output. No LLMs. No guessing.
"""
from .engine import ScanEngine, create_default_engine
from .models import Confidence, Finding, ScanResult, ScanStats, Severity

__all__ = [
    "Confidence",
    "Finding",
    "ScanEngine",
    "ScanResult",
    "ScanStats",
    "Severity",
    "create_default_engine",
]
