"""
L2-CRED-001: Credential-reading script detection.

Flags packages whose install scripts or source code read credentials,
environment variables, or sensitive files (.npmrc, .aws/, .ssh/, .env).

Pure function: (target_path, corpus_dir) → List[Finding]
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from ..models import Confidence, Finding, Severity

# Patterns that indicate credential or secret access.
CREDENTIAL_PATTERNS = (
    # Environment variables that hold secrets
    re.compile(r"process\.env\.(?:AWS_|GITHUB_|NPM_|TOKEN|SECRET|KEY|PASS|AUTH|CREDENTIAL)", re.IGNORECASE),
    # Direct file reads of sensitive paths
    re.compile(r"""(?:readFileSync|readFile|fs\.read|cat\s+|type\s+)['"].*?(?:\.npmrc|\.env|\.aws|\.ssh|\.gitconfig|id_rsa|id_ed25519)""", re.IGNORECASE),
    # Path references to credential directories
    re.compile(r"""['"/](?:\.npmrc|\.env|\.aws[/\\]|\.ssh[/\\])['"/]""", re.IGNORECASE),
    # Hardcoded credential patterns
    re.compile(r"(?:password|passwd|secret|token|api_key|apikey|access_key)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
    # process.env without specific var (suspicious blanket access)
    re.compile(r"process\.env(?!\.\w)", re.IGNORECASE),
    # Exfiltration patterns: sending env vars over network
    re.compile(r"(?:curl|wget|fetch|http\.get|http\.post|request|axios|got)\s*.*process\.env", re.IGNORECASE),
)

# JS/TS extensions to scan
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx"}

# Max file size to scan
MAX_FILE_BYTES = 512_000

SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".map", ".lock",
})


def _load_package_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {}


def _scan_scripts_for_creds(pkg: dict, pkg_json: Path) -> List[Finding]:
    """Check package.json scripts for credential-reading patterns."""
    findings: List[Finding] = []
    scripts = pkg.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    for script_key, script_value in sorted(scripts.items()):
        script_str = str(script_value)

        # Check for credential exfiltration patterns in scripts
        has_env_read = "process.env" in script_str or "$" in script_str
        has_network = any(p in script_str for p in ("curl", "wget", "fetch", "http://", "https://", "nc ", "ncat"))

        if has_env_read and has_network:
            findings.append(
                Finding(
                    rule_id="L2-CRED-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=(
                        f"Install script '{script_key}' reads environment variables "
                        "and makes network requests — potential credential exfiltration"
                    ),
                    evidence=f"scripts.{script_key} = {script_str[:200]}",
                    remediation=(
                        f"Remove or audit the '{script_key}' script. "
                        "Use --ignore-scripts during install. "
                        "Never allow install scripts to read env vars and make network calls."
                    ),
                    references=[
                        "https://blog.vlt.sh/blog/postinstall-harm",
                        "https://github.com/npm/npm/issues/17152",
                    ],
                )
            )
        elif has_env_read:
            # Reading env vars without network — still suspicious
            env_vars = re.findall(r"process\.env\.\w+", script_str)
            shell_vars = re.findall(r"\$\{?\w+\}?", script_str)
            all_vars = env_vars + shell_vars
            sensitive = any(
                kw in " ".join(all_vars).upper()
                for kw in ("TOKEN", "SECRET", "KEY", "PASS", "AUTH", "CREDENTIAL", "AWS", "NPM", "GITHUB")
            )
            if sensitive:
                findings.append(
                    Finding(
                        rule_id="L2-CRED-001",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        package=pkg_label,
                        file=str(pkg_json),
                        message=(
                            f"Install script '{script_key}' reads sensitive environment variables"
                        ),
                        evidence=f"scripts.{script_key} = {script_str[:200]}",
                        remediation=(
                            f"Review the '{script_key}' script for credential access. "
                            "Consider --ignore-scripts or audit before install."
                        ),
                        references=[
                            "https://blog.vlt.sh/blog/postinstall-harm",
                        ],
                    )
                )

    return findings


def _scan_source_for_creds(file_path: Path, pkg_label: str) -> List[Finding]:
    """Scan a JS/TS source file for credential-reading patterns."""
    findings: List[Finding] = []

    if file_path.suffix in SKIP_EXTENSIONS:
        return findings

    try:
        size = file_path.stat().st_size
    except OSError:
        return findings

    if size > MAX_FILE_BYTES:
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    for pattern in CREDENTIAL_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[:match.start()].count("\n") + 1
            matched_text = match.group(0)[:120]

            # Determine severity based on pattern
            severity = Severity.MEDIUM
            confidence = Confidence.MEDIUM

            # Network + env = CRITICAL
            if "process.env" in matched_text and any(
                p in matched_text for p in ("curl", "wget", "fetch", "http")
            ):
                severity = Severity.CRITICAL
                confidence = Confidence.HIGH
            elif any(
                kw in matched_text.upper()
                for kw in ("TOKEN", "SECRET", "KEY", "PASS", "AWS", "NPM_")
            ):
                severity = Severity.HIGH
                confidence = Confidence.HIGH

            findings.append(
                Finding(
                    rule_id="L2-CRED-001",
                    severity=severity,
                    confidence=confidence,
                    package=pkg_label,
                    file=str(file_path),
                    line=line_num,
                    message=f"Credential-reading pattern detected: {matched_text[:60]}",
                    evidence=matched_text,
                    remediation=(
                        "Review this code path. If it reads credentials unnecessarily, "
                        "remove it. If legitimate, ensure credentials are not logged or transmitted."
                    ),
                    references=[
                        "https://blog.vlt.sh/blog/postinstall-harm",
                        "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_variables_in_url",
                    ],
                )
            )

    return findings


def detect_credential_reading(target: Path, corpus_dir: Path) -> List[Finding]:
    """
    Detect credential-reading patterns in install scripts and source code.
    No network calls. Pure filesystem scan.
    """
    findings: List[Finding] = []

    # Check root package.json scripts
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = _load_package_json(root_pkg)
        if pkg:
            findings.extend(_scan_scripts_for_creds(pkg, root_pkg))

    # Check node_modules
    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue

            pkg_json = child / "package.json"
            if pkg_json.is_file():
                pkg = _load_package_json(pkg_json)
                if pkg:
                    pkg_label = f"{pkg.get('name', child.name)}@{pkg.get('version', 'unknown')}"
                    findings.extend(_scan_scripts_for_creds(pkg, pkg_json))

                    # Scan JS/TS files in the package for credential patterns
                    for ext in JS_EXTENSIONS:
                        for src_file in child.rglob(f"*{ext}"):
                            findings.extend(_scan_source_for_creds(src_file, pkg_label))

            # Scoped packages
            if child.name.startswith("@") and child.is_dir():
                for scoped_child in sorted(child.iterdir()):
                    if not scoped_child.is_dir():
                        continue
                    scoped_pkg = scoped_child / "package.json"
                    if scoped_pkg.is_file():
                        pkg = _load_package_json(scoped_pkg)
                        if pkg:
                            pkg_label = f"{pkg.get('name', scoped_child.name)}@{pkg.get('version', 'unknown')}"
                            findings.extend(_scan_scripts_for_creds(pkg, scoped_pkg))

                            for ext in JS_EXTENSIONS:
                                for src_file in scoped_child.rglob(f"*{ext}"):
                                    findings.extend(_scan_source_for_creds(src_file, pkg_label))

    return findings