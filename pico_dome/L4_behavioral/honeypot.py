"""
L4 Honeypot System — canary files, DNS, and env tokens.

Plants decoys before L3 sandbox run, detects touches after.
Deterministic: same canaries, same detection. No guessing.
"""
from __future__ import annotations

import logging
import secrets
from pathlib import Path

logger = logging.getLogger("pico_dome.L4.honeypot")


def _random_token(length: int = 16) -> str:
    """Generate a random hex token for canary identification."""
    return secrets.token_hex(length)


def generate_canary_filename(prefix: str = "secret", suffix: str = ".txt") -> str:
    """Generate a canary filename that looks tempting to malware."""
    tempting_names = [
        "passwords", "credentials", "api_keys", "secrets", "config",
        "database", "backup", "private_key", "aws_credentials",
        ".env", "ssh_key", "token", "admin", "root",
    ]
    base = secrets.choice(tempting_names)
    token = _random_token(8)
    return f"{prefix}_{base}_{token}{suffix}"


def generate_canary_domain(subdomain: str = "") -> str:
    """Generate a canary DNS domain (for exfil detection)."""
    token = _random_token(8)
    if subdomain:
        return f"{subdomain}.{token}.canary.picoshogun.local"
    return f"{token}.canary.picoshogun.local"


def generate_canary_env_key(prefix: str = "AWS") -> str:
    """Generate a canary environment variable name."""
    tempting_prefixes = [
        "AWS_SECRET", "DATABASE_URL", "API_KEY", "SECRET_KEY",
        "PRIVATE_KEY", "TOKEN", "PASSWORD", "CREDENTIAL",
    ]
    base = secrets.choice(tempting_prefixes)
    token = _random_token(4).upper()
    return f"{base}_{token}"


def plant_canary_files(
    target_dir: str | Path,
    count: int = 3,
) -> list[Path]:
    """Plant canary files in a directory."""
    target = Path(target_dir)
    target.mkdir(parents=True, exist_ok=True)

    canary_paths: list[Path] = []
    canary_dirs = ["", ".config", ".ssh", ".aws", ".env.d"]

    for i in range(count):
        dirname = canary_dirs[i % len(canary_dirs)]
        canary_dir = target / dirname if dirname else target
        canary_dir.mkdir(parents=True, exist_ok=True)

        filename = generate_canary_filename()
        filepath = canary_dir / filename
        token = _random_token(32)
        filepath.write_text(
            f"# SecDev canary token: {token}\n"
            f"# This file is a decoy. Access indicates potential data theft.\n"
            f"CANARY_TOKEN={token}\n",
            encoding="utf-8",
        )
        canary_paths.append(filepath)
        logger.debug("Planted canary file: %s", filepath)

    return canary_paths


def plant_canary_env(
    env_vars: dict[str, str] | None = None,
    count: int = 3,
) -> dict[str, str]:
    """Generate canary environment variable entries."""
    if env_vars is None:
        env_vars = {}

    for _ in range(count):
        key = generate_canary_env_key()
        token = _random_token(16)
        env_vars[key] = f"canary://{token}.picoshogun.local"

    return env_vars


def plant_canary_dns(count: int = 3) -> list[str]:
    """Generate canary DNS domain names."""
    domains: list[str] = []
    for _ in range(count):
        domains.append(generate_canary_domain())
    return domains


def check_canary_file_access(
    canary_paths: list[str],
    fs_ops: list[dict],
) -> list[str]:
    """Check if any canary files were accessed in sandbox trace."""
    canary_strs = {str(p) for p in canary_paths}
    canary_names = {Path(p).name if isinstance(p, (str, Path)) else p for p in canary_paths}

    touched: list[str] = []
    for op in fs_ops:
        op_path = op.get("path", "")
        op_name = Path(op_path).name if op_path else ""

        if op_path in canary_strs or op_name in canary_names:
            touched.append(op_path)

    return touched


def check_canary_dns(
    canary_domains: list[str],
    dns_queries: list[dict],
) -> list[str]:
    """Check if any canary domains were queried in sandbox trace."""
    canary_set = set(canary_domains)
    touched: list[str] = []

    for q in dns_queries:
        domain = q.get("domain", "")
        if domain in canary_set or any(domain.endswith(f".{c}") for c in canary_set):
            touched.append(domain)

    return touched


def check_canary_env(
    canary_env_keys: list[str],
    env_reads: list[dict],
) -> list[str]:
    """Check if any canary env vars were read in sandbox trace."""
    canary_set = set(canary_env_keys)
    touched: list[str] = []

    for r in env_reads:
        key = r.get("key", r.get("detail", ""))
        if key in canary_set:
            touched.append(key)

    return touched
