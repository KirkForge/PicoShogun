"""
L4 Behavioral Profiler — converts L3 sandbox traces into BehavioralProfiles.

Takes a SandboxResult from L3 and extracts timing, network, DNS, filesystem,
process, resource, and entropy measurements into a BehavioralProfile that
L4 detector rules can operate on.
"""
from __future__ import annotations

import contextlib
import logging
from datetime import datetime

from ..L3_execution.models import SandboxEvent, SandboxResult
from .entropy import shannon_entropy
from .models import (
    BehavioralProfile,
    DNSQuery,
    FilesystemOp,
    NetworkCall,
    ProcessSpawn,
    ResourceSample,
    TimingPoint,
)

logger = logging.getLogger("pico_dome.L4.profiler")


def _parse_timestamp_ms(timestamp: str | None) -> float | None:
    """Parse an ISO timestamp string to milliseconds since epoch.

    Falls back to None if parsing fails.
    """
    if not timestamp:
        return None
    try:
        # Handle ISO format with or without trailing 'Z'
        ts = timestamp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        return dt.timestamp() * 1000.0
    except (ValueError, TypeError):
        return None


def profile_from_sandbox_result(
    result: SandboxResult,
    package: str = "",
    egress_data: bytes | None = None,
) -> BehavioralProfile:
    """
    Convert an L3 SandboxResult into a BehavioralProfile.

    Args:
        result: The L3 sandbox execution result.
        package: Package name being analyzed.
        egress_data: Optional raw egress data for entropy analysis.

    Returns:
        BehavioralProfile ready for L4 rule analysis.
    """
    profile = BehavioralProfile(
        package=package or " ".join(result.command),
        command=list(result.command),
        duration_ms=result.duration_ms,
        peak_memory_mb=result.peak_memory_mb,
        cpu_time_seconds=result.cpu_time_seconds,
        total_cpu_time_ms=result.cpu_time_seconds * 1000,
    )

    for event in result.events:
        _classify_event(event, profile)

    # Compute egress entropy if data provided
    if egress_data:
        profile.egress_entropy = shannon_entropy(egress_data)
    elif profile.total_bytes_sent > 0:
        # If we have network data but no raw bytes, estimate from call sizes
        raw_bytes = b""
        for nc in profile.network_calls:
            raw_bytes += nc.host.encode() + b":"
        if raw_bytes:
            profile.egress_entropy = shannon_entropy(raw_bytes)

    # Compute DNS entropy from query names
    if profile.dns_queries:
        all_domains = " ".join(d.domain for d in profile.dns_queries)
        profile.dns_entropy = shannon_entropy(all_domains.encode())

    # Compute call frequencies
    freq: dict[str, int] = {}
    for tp in profile.timing_points:
        op = tp.operation
        freq[op] = freq.get(op, 0) + 1
    profile.call_frequencies = freq

    # Detect sleep intervals (gaps > 500ms between operations)
    if len(profile.timing_points) >= 2:
        profile.timing_points.sort(key=lambda t: t.timestamp_ms)
        for i in range(1, len(profile.timing_points)):
            gap = profile.timing_points[i].timestamp_ms - profile.timing_points[i - 1].timestamp_ms
            if gap > 500:
                profile.sleep_intervals.append(gap)

    return profile


def profile_from_trace(
    package: str,
    command: list[str],
    events: list[dict],
    duration_ms: int = 0,
    egress_data: bytes | None = None,
) -> BehavioralProfile:
    """
    Create a BehavioralProfile from a raw trace (list of event dicts).

    This is the generic entry point for programmatic use when you
    don't have an L3 SandboxResult object.

    Args:
        package: Package name.
        command: Command that was run.
        events: List of event dicts with keys: timestamp_ms, operation, detail, etc.
        duration_ms: Total run duration.
        egress_data: Raw egress bytes for entropy.

    Returns:
        BehavioralProfile ready for L4 rule analysis.
    """
    profile = BehavioralProfile(
        package=package,
        command=command,
        duration_ms=duration_ms,
    )

    for ev in events:
        ts = ev.get("timestamp_ms", 0.0)
        op = ev.get("operation", "unknown")
        detail = ev.get("detail", "")
        path = ev.get("path")

        profile.timing_points.append(TimingPoint(
            timestamp_ms=ts,
            operation=op,
            duration_ms=ev.get("duration_ms", 0.0),
        ))

        if op in ("connect", "network", "outbound"):
            host, _, port_str = detail.partition(":")
            port = 0
            with contextlib.suppress(ValueError, TypeError):
                port = int(port_str)
            profile.network_calls.append(NetworkCall(
                host=host,
                port=port,
                protocol=ev.get("protocol", "tcp"),
                bytes_sent=ev.get("bytes_sent", 0),
                bytes_received=ev.get("bytes_received", 0),
                timestamp_ms=ts,
            ))
            profile.total_bytes_sent += ev.get("bytes_sent", 0)
            profile.total_bytes_received += ev.get("bytes_received", 0)

        elif op in ("dns", "dns_lookup"):
            profile.dns_queries.append(DNSQuery(
                domain=detail,
                query_type=ev.get("query_type", "A"),
                response_size=ev.get("response_size", 0),
                timestamp_ms=ts,
            ))

        elif op in ("fs_write", "fs_read", "write", "read", "rename",
                     "unlink", "chmod", "mkdir"):
            profile.fs_ops.append(FilesystemOp(
                operation=op,
                path=path or detail,
                size_bytes=ev.get("size_bytes", 0),
                timestamp_ms=ts,
            ))

        elif op in ("spawn", "exec"):
            profile.spawns.append(ProcessSpawn(
                command=detail,
                args=ev.get("args", []),
                exit_code=ev.get("exit_code"),
                timestamp_ms=ts,
            ))

        elif op in ("cpu", "memory", "resource"):
            profile.resource_samples.append(ResourceSample(
                timestamp_ms=ts,
                cpu_percent=ev.get("cpu_percent", 0.0),
                memory_mb=ev.get("memory_mb", 0.0),
                net_bytes_sent=ev.get("net_bytes_sent", 0),
                net_bytes_recv=ev.get("net_bytes_recv", 0),
            ))

    # Entropy computations
    if egress_data:
        profile.egress_entropy = shannon_entropy(egress_data)
    if profile.dns_queries:
        all_domains = " ".join(d.domain for d in profile.dns_queries)
        profile.dns_entropy = shannon_entropy(all_domains.encode())

    # Call frequencies
    freq: dict[str, int] = {}
    for tp in profile.timing_points:
        freq[tp.operation] = freq.get(tp.operation, 0) + 1
    profile.call_frequencies = freq

    # Sleep intervals
    if len(profile.timing_points) >= 2:
        profile.timing_points.sort(key=lambda t: t.timestamp_ms)
        for i in range(1, len(profile.timing_points)):
            gap = profile.timing_points[i].timestamp_ms - profile.timing_points[i - 1].timestamp_ms
            if gap > 500:
                profile.sleep_intervals.append(gap)

    return profile


def _classify_event(event: SandboxEvent, profile: BehavioralProfile) -> None:
    """Classify an L3 SandboxEvent and add it to the profile."""
    # Parse ISO timestamp to ms, fall back to sequential approximation
    ts_approx = _parse_timestamp_ms(event.timestamp) or len(profile.timing_points) * 10.0

    profile.timing_points.append(TimingPoint(
        timestamp_ms=ts_approx,
        operation=event.operation,
        duration_ms=0.0,
    ))

    op = event.operation
    detail = event.detail

    if op in ("connect", "network"):
        # Parse host:port from detail, fall back to event.address
        raw_address = event.address or detail
        host, _, port_str = raw_address.partition(":")
        port = 0
        with contextlib.suppress(ValueError, TypeError):
            port = int(port_str)
        profile.network_calls.append(NetworkCall(
            host=host, port=port, timestamp_ms=ts_approx,
        ))

    elif op in ("dns", "dns_lookup"):
        profile.dns_queries.append(DNSQuery(
            domain=detail, timestamp_ms=ts_approx,
        ))

    elif op in ("fs_write", "fs_read"):
        profile.fs_ops.append(FilesystemOp(
            operation=op, path=event.path or detail, timestamp_ms=ts_approx,
        ))

    elif op in ("spawn", "exec"):
        profile.spawns.append(ProcessSpawn(
            command=detail, timestamp_ms=ts_approx,
        ))

    elif op in ("syscall",):
        # Generic syscall — just track as timing point
        pass
