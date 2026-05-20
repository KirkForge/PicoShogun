"""
Shannon entropy computation for L4 behavioral analysis.

Deterministic: same bytes, same entropy. No ML, no approximation.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import List


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence.

    Entropy = -sum(p_i * log2(p_i)) where p_i = count(byte_i) / len(data)

    Range: 0.0 (constant data) to 8.0 (uniform random).
    >7.0 bits/byte suggests encrypted/compressed exfiltration.

    Args:
        data: Raw bytes to analyze.

    Returns:
        Shannon entropy in bits per byte (0.0 to 8.0).
    """
    if not data:
        return 0.0

    length = len(data)
    if length == 1:
        return 0.0

    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def shannon_entropy_string(text: str) -> float:
    """
    Compute Shannon entropy of a string (character-level).

    Args:
        text: String to analyze.

    Returns:
        Shannon entropy in bits per character.
    """
    if not text:
        return 0.0

    length = len(text)
    if length == 1:
        return 0.0

    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def entropy_of_chunks(chunks: List[bytes]) -> List[float]:
    """
    Compute Shannon entropy for each chunk independently.

    Useful for detecting entropy spikes in a data stream.

    Args:
        chunks: List of byte sequences.

    Returns:
        List of entropy values, one per chunk.
    """
    return [shannon_entropy(chunk) for chunk in chunks]


def normalized_entropy(data: bytes, baseline_entropy: float = 0.0) -> float:
    """
    Compute normalized entropy relative to a baseline.

    If baseline is 0, returns raw entropy.
    Otherwise returns the z-score-like deviation: (entropy - baseline) / 8.0

    Args:
        data: Raw bytes to analyze.
        baseline_entropy: Baseline entropy to compare against.

    Returns:
        Normalized deviation (0.0 = no drift, 1.0 = max drift).
    """
    if baseline_entropy <= 0:
        return shannon_entropy(data)

    ent = shannon_entropy(data)
    drift = abs(ent - baseline_entropy) / 8.0
    return min(drift, 1.0)


def detect_entropy_spikes(
    data: bytes,
    window_size: int = 256,
    threshold: float = 7.0,
) -> List[int]:
    """
    Detect positions where entropy exceeds a threshold in a sliding window.

    Used for L4-ENTROPY-002: entropy spikes vs baseline.

    Args:
        data: Raw bytes to scan.
        window_size: Size of the sliding window in bytes.
        threshold: Entropy threshold in bits/byte (default 7.0).

    Returns:
        List of byte offsets where entropy exceeds the threshold.
    """
    if len(data) < window_size:
        ent = shannon_entropy(data)
        return [0] if ent > threshold else []

    spikes: List[int] = []
    for offset in range(0, len(data) - window_size + 1, window_size // 2):
        window = data[offset:offset + window_size]
        ent = shannon_entropy(window)
        if ent > threshold:
            spikes.append(offset)

    return spikes
