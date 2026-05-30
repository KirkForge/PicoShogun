"""
L2-POST-001: Post-install script detection.

Flags packages that declare install, postinstall, or preinstall scripts
in their package.json. These are the #1 vector for supply chain attacks.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity

logger = logging.getLogger("pico_dome.L2.rules.post_install")

# Scripts that execute code at install time — the primary attack vector.
DANGEROUS_SCRIPT_KEYS = (
    "install",
    "postinstall",
    "preinstall",
    "prepare",
    "prepack",
)


def _scan_package_json(pkg_json: Path) -> list[Finding]:
    """Scan a single package.json for dangerous install scripts."""
    findings: list[Finding] = []
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return findings

    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    pkg_name = data.get("name", pkg_json.parent.name)
    pkg_version = data.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    for key in DANGEROUS_SCRIPT_KEYS:
        if key in scripts:
            script_value = scripts[key]
            findings.append(
                Finding(
                    rule_id="L2-POST-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.EXACT,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=f"Package declares '{key}' lifecycle script",
                    evidence=f"scripts.{key} = {script_value!r}",
                    remediation=(
                        f"Review the '{key}' script in {pkg_label}. "
                        "If not essential, remove it. Consider using "
                        "--ignore-scripts during install."
                    ),
                    references=[
                        "https://github.com/npm/npm/issues/17152",
                        "https://blog.vlt.sh/blog/postinstall-harm",
                    ],
                )
            )

    return findings


def detect_post_install_scripts(target: Path) -> list[Finding]:
    """
    Detect packages with install/postinstall/preinstall scripts.

    Scans root package.json and every node_modules/*/package.json.
    """
    findings: list[Finding] = []

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        findings.extend(_scan_package_json(root_pkg))

    # node_modules packages
    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            pkg_json = child / "package.json"
            if pkg_json.is_file():
                findings.extend(_scan_package_json(pkg_json))

            # Scoped packages: node_modules/@scope/pkg
            if child.name.startswith("@") and child.is_dir():
                for scoped_child in sorted(child.iterdir()):
                    if not scoped_child.is_dir():
                        continue
                    scoped_pkg = scoped_child / "package.json"
                    if scoped_pkg.is_file():
                        findings.extend(_scan_package_json(scoped_pkg))

    return findings
