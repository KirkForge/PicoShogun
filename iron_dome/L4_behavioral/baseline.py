"""
L4 Baseline Loader — loads and manages behavioral baselines.

Baselines define expected behavior for known-good workloads.
Same profile + same baseline = same drift score. Deterministic.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from .models import Baseline

logger = logging.getLogger("iron_dome.L4.baseline")


def _get_yaml():
    """Lazy import yaml — only needed when loading .yml/.yaml baseline files."""
    try:
        import yaml
        return yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required to load YAML baseline files. "
            "Install it with: pip install pyyaml"
        ) from None

# Shipped baselines directory
_BASELINES_DIR = Path(__file__).parent / "baselines"

# Built-in default baselines
DEFAULT_BASELINES = {
    "npm-install": Baseline(
        name="npm-install",
        description="Typical npm install workload",
        version="1.0",
        call_frequencies={
            "fs_read": {"mean": 500.0, "stddev": 200.0},
            "fs_write": {"mean": 100.0, "stddev": 50.0},
            "dns": {"mean": 5.0, "stddev": 3.0},
            "connect": {"mean": 10.0, "stddev": 5.0},
            "spawn": {"mean": 2.0, "stddev": 1.0},
        },
        network_hosts=["registry.npmjs.org"],
        dns_domains=["registry.npmjs.org", "cdn.npmjs.org"],
        avg_bytes_sent=5000,
        avg_bytes_received=500000,
        avg_duration_ms=15000,
        std_duration_ms=5000,
        avg_peak_memory_mb=150.0,
        std_peak_memory_mb=50.0,
        avg_cpu_time_ms=2000.0,
        std_cpu_time_ms=1000.0,
        avg_egress_entropy=3.5,
        std_egress_entropy=0.5,
        resource_curve=[
            {"t": 0.0, "cpu": 50.0, "mem": 80.0},
            {"t": 0.1, "cpu": 80.0, "mem": 100.0},
            {"t": 0.3, "cpu": 60.0, "mem": 120.0},
            {"t": 0.5, "cpu": 30.0, "mem": 140.0},
            {"t": 0.7, "cpu": 20.0, "mem": 145.0},
            {"t": 1.0, "cpu": 5.0, "mem": 150.0},
        ],
    ),
    "pip-install": Baseline(
        name="pip-install",
        description="Typical pip install workload",
        version="1.0",
        call_frequencies={
            "fs_read": {"mean": 300.0, "stddev": 100.0},
            "fs_write": {"mean": 80.0, "stddev": 30.0},
            "dns": {"mean": 3.0, "stddev": 2.0},
            "connect": {"mean": 8.0, "stddev": 4.0},
            "spawn": {"mean": 1.0, "stddev": 0.5},
        },
        network_hosts=["pypi.org", "files.pythonhosted.org"],
        dns_domains=["pypi.org", "files.pythonhosted.org"],
        avg_bytes_sent=3000,
        avg_bytes_received=300000,
        avg_duration_ms=10000,
        std_duration_ms=3000,
        avg_peak_memory_mb=100.0,
        std_peak_memory_mb=30.0,
        avg_cpu_time_ms=1500.0,
        std_cpu_time_ms=800.0,
        avg_egress_entropy=3.0,
        std_egress_entropy=0.4,
        resource_curve=[
            {"t": 0.0, "cpu": 40.0, "mem": 60.0},
            {"t": 0.1, "cpu": 70.0, "mem": 80.0},
            {"t": 0.3, "cpu": 50.0, "mem": 90.0},
            {"t": 0.5, "cpu": 25.0, "mem": 95.0},
            {"t": 0.7, "cpu": 15.0, "mem": 98.0},
            {"t": 1.0, "cpu": 3.0, "mem": 100.0},
        ],
    ),
    "pytest": Baseline(
        name="pytest",
        description="Typical pytest run workload",
        version="1.0",
        call_frequencies={
            "fs_read": {"mean": 1000.0, "stddev": 500.0},
            "fs_write": {"mean": 50.0, "stddev": 20.0},
            "dns": {"mean": 0.5, "stddev": 0.5},
            "connect": {"mean": 1.0, "stddev": 1.0},
            "spawn": {"mean": 5.0, "stddev": 3.0},
        },
        network_hosts=[],
        dns_domains=[],
        avg_bytes_sent=500,
        avg_bytes_received=5000,
        avg_duration_ms=20000,
        std_duration_ms=10000,
        avg_peak_memory_mb=200.0,
        std_peak_memory_mb=80.0,
        avg_cpu_time_ms=5000.0,
        std_cpu_time_ms=3000.0,
        avg_egress_entropy=2.5,
        std_egress_entropy=0.3,
        resource_curve=[
            {"t": 0.0, "cpu": 30.0, "mem": 100.0},
            {"t": 0.2, "cpu": 90.0, "mem": 150.0},
            {"t": 0.5, "cpu": 85.0, "mem": 180.0},
            {"t": 0.8, "cpu": 60.0, "mem": 190.0},
            {"t": 1.0, "cpu": 10.0, "mem": 200.0},
        ],
    ),
    "make-build": Baseline(
        name="make-build",
        description="Typical make/build workload",
        version="1.0",
        call_frequencies={
            "fs_read": {"mean": 2000.0, "stddev": 800.0},
            "fs_write": {"mean": 500.0, "stddev": 200.0},
            "dns": {"mean": 0.2, "stddev": 0.2},
            "connect": {"mean": 0.5, "stddev": 0.5},
            "spawn": {"mean": 50.0, "stddev": 20.0},
        },
        network_hosts=[],
        dns_domains=[],
        avg_bytes_sent=200,
        avg_bytes_received=2000,
        avg_duration_ms=30000,
        std_duration_ms=15000,
        avg_peak_memory_mb=300.0,
        std_peak_memory_mb=100.0,
        avg_cpu_time_ms=15000.0,
        std_cpu_time_ms=8000.0,
        avg_egress_entropy=2.0,
        std_egress_entropy=0.2,
        resource_curve=[
            {"t": 0.0, "cpu": 20.0, "mem": 150.0},
            {"t": 0.1, "cpu": 95.0, "mem": 200.0},
            {"t": 0.3, "cpu": 90.0, "mem": 250.0},
            {"t": 0.5, "cpu": 85.0, "mem": 280.0},
            {"t": 0.8, "cpu": 70.0, "mem": 295.0},
            {"t": 1.0, "cpu": 5.0, "mem": 300.0},
        ],
    ),
}


def load_baseline(name: str) -> Baseline | None:
    """
    Load a baseline by name.

    Checks built-in defaults first, then baselines directory.

    Args:
        name: Baseline name (e.g., 'npm-install', 'pip-install').

    Returns:
        Baseline object or None if not found.
    """
    # Check built-in defaults
    if name in DEFAULT_BASELINES:
        return DEFAULT_BASELINES[name]

    # Check baselines directory for YAML/JSON files
    for ext in (".yml", ".yaml", ".json"):
        path = _BASELINES_DIR / f"{name}{ext}"
        if path.exists():
            return _load_baseline_file(path)

    return None


def load_all_baselines() -> dict[str, Baseline]:
    """Load all available baselines (built-in + from directory)."""
    baselines = dict(DEFAULT_BASELINES)

    if _BASELINES_DIR.is_dir():
        for path in _BASELINES_DIR.iterdir():
            if path.suffix in (".yml", ".yaml", ".json"):
                bl = _load_baseline_file(path)
                if bl:
                    baselines[bl.name] = bl

    return baselines


def _load_baseline_file(path: Path) -> Baseline | None:
    """Load a baseline from a YAML or JSON file."""
    try:
        content = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            data = json.loads(content)
        else:
            yaml = _get_yaml()
            data = yaml.safe_load(content)
        return _parse_baseline(data)
    except Exception:
        logger.exception("Failed to load baseline from %s", path)
        return None


def _parse_baseline(data: dict) -> Baseline:
    """Parse a baseline dict into a Baseline object."""
    return Baseline(
        name=data.get("name", "unnamed"),
        description=data.get("description", ""),
        version=str(data.get("version", "1.0")),
        call_frequencies=data.get("call_frequencies", {}),
        network_hosts=data.get("network_hosts", []),
        dns_domains=data.get("dns_domains", []),
        avg_bytes_sent=data.get("avg_bytes_sent", 0),
        avg_bytes_received=data.get("avg_bytes_received", 0),
        avg_duration_ms=data.get("avg_duration_ms", 0),
        std_duration_ms=data.get("std_duration_ms", 0),
        avg_peak_memory_mb=data.get("avg_peak_memory_mb", 0.0),
        std_peak_memory_mb=data.get("std_peak_memory_mb", 0.0),
        avg_cpu_time_ms=data.get("avg_cpu_time_ms", 0.0),
        std_cpu_time_ms=data.get("std_cpu_time_ms", 0.0),
        avg_egress_entropy=data.get("avg_egress_entropy", 0.0),
        std_egress_entropy=data.get("std_egress_entropy", 0.0),
        resource_curve=data.get("resource_curve", []),
    )


def save_baseline(baseline: Baseline, path: str | Path) -> Path:
    """Save a baseline to a YAML file."""
    yaml = _get_yaml()
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(yaml.dump(baseline.to_dict(), default_flow_style=False), encoding="utf-8")
    return p
