"""
Dynamic Time Warping (DTW) for L4 resource curve comparison.

Deterministic: same curves, same distance. No ML.
Used for L4-BASE-003 to detect resource curve drift.
"""
from __future__ import annotations

import math
from typing import List, Tuple


def dtw_distance(
    series_a: List[float],
    series_b: List[float],
) -> float:
    """
    Compute the DTW distance between two time series.

    Uses the classic O(n*m) dynamic programming algorithm.
    For resource curves, we normalize internally to keep
    distances comparable across different workloads.

    Args:
        series_a: First time series (e.g., CPU usage over time).
        series_b: Second time series (e.g., baseline CPU curve).

    Returns:
        DTW distance (lower = more similar).
    """
    if not series_a or not series_b:
        return float("inf")

    n = len(series_a)
    m = len(series_b)

    # DTW matrix
    dtw = [[0.0] * (m + 1) for _ in range(n + 1)]

    # Initialize edges to infinity
    for i in range(1, n + 1):
        dtw[i][0] = float("inf")
    for j in range(1, m + 1):
        dtw[0][j] = float("inf")
    dtw[0][0] = 0.0

    # Fill matrix
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = abs(series_a[i - 1] - series_b[j - 1])
            dtw[i][j] = cost + min(
                dtw[i - 1][j],      # insertion
                dtw[i][j - 1],      # deletion
                dtw[i - 1][j - 1],  # match
            )

    return dtw[n][m]


def normalized_dtw_distance(
    series_a: List[float],
    series_b: List[float],
) -> float:
    """
    Compute DTW distance normalized to [0, 1] range.

    Normalizes by dividing by (len(a) + len(b)) / 2 to make
    distances comparable across different-length series.

    Args:
        series_a: First time series.
        series_b: Second time series.

    Returns:
        Normalized DTW distance in [0, 1]. 0.0 = identical shape.
    """
    if not series_a or not series_b:
        return 1.0

    raw = dtw_distance(series_a, series_b)
    norm_factor = (len(series_a) + len(series_b)) / 2.0

    if norm_factor == 0:
        return 1.0

    return min(raw / norm_factor, 1.0)


def extract_resource_curve(
    samples: List[dict],
    metric: str = "cpu_percent",
) -> List[float]:
    """
    Extract a time series from resource samples.

    Args:
        samples: List of resource sample dicts with timestamp_ms and metric fields.
        metric: Which metric to extract ('cpu_percent' or 'memory_mb').

    Returns:
        Time series of the specified metric values.
    """
    if not samples:
        return []

    return [s.get(metric, 0.0) for s in samples]


def compare_resource_curves(
    observed: List[float],
    baseline: List[float],
    threshold: float = 0.3,
) -> Tuple[float, bool]:
    """
    Compare an observed resource curve against a baseline using DTW.

    Args:
        observed: Observed resource usage curve.
        baseline: Baseline (expected) resource usage curve.
        threshold: Normalized DTW distance threshold for drift detection.

    Returns:
        Tuple of (normalized_distance, is_drift).
    """
    if not observed or not baseline:
        return 1.0, True  # Missing data = max drift

    distance = normalized_dtw_distance(observed, baseline)
    return distance, distance > threshold
