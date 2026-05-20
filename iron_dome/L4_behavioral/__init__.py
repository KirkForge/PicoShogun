"""
L4 Behavioral Analysis — deterministic profiling from L3 sandbox traces.

No ML. No probabilistic guessing. DTW for curves, Shannon entropy for exfil,
threshold rules for timing. Same trace + same baseline = same verdict.
"""
from .models import (
    AnalysisResult,
    AnalysisStats,
    Baseline,
    BehavioralProfile,
    BehavioralVerdict,
    Confidence,
    DNSQuery,
    DriftResult,
    FilesystemOp,
    Finding,
    NetworkCall,
    ProcessSpawn,
    ResourceSample,
    RuleID,
    Severity,
    TimingPoint,
)

__all__ = [
    "AnalysisResult",
    "AnalysisStats",
    "Baseline",
    "BehavioralProfile",
    "BehavioralVerdict",
    "Confidence",
    "DNSQuery",
    "DriftResult",
    "FilesystemOp",
    "Finding",
    "NetworkCall",
    "ProcessSpawn",
    "ResourceSample",
    "RuleID",
    "Severity",
    "TimingPoint",
]
