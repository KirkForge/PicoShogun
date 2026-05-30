"""
L2-MANI-001/002: Package manifest integrity checks.

L2-MANI-001: Version range attacks — *, >=0.0.0, empty constraints.
L2-MANI-002: Optional dependencies with post-install scripts.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity

logger = logging.getLogger("pico_dome.L2.rules.manifest")

# Patterns that indicate an overly permissive version range.
WILDCARD_VERSIONS = ("*", "", "latest", ">=0.0.0", ">=1", ">=0")


def _load_package_json(path: Path) -> dict:
    """Load and parse a package.json."""
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {}


def _check_version_ranges(pkg: dict, pkg_json: Path) -> list[Finding]:
    """L2-MANI-001: Flag overly permissive version constraints."""
    findings: list[Finding] = []
    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    for dep_key in ("dependencies", "devDependencies"):
        deps = pkg.get(dep_key, {})
        if not isinstance(deps, dict):
            continue

        for dep_name, version_spec in sorted(deps.items()):
            if not isinstance(version_spec, str):
                continue

            spec_stripped = version_spec.strip()

            # Wildcard or empty version
            if spec_stripped in WILDCARD_VERSIONS:
                findings.append(
                    Finding(
                        rule_id="L2-MANI-001",
                        severity=Severity.HIGH,
                        confidence=Confidence.EXACT,
                        package=pkg_label,
                        file=str(pkg_json),
                        message=(
                            f"Dependency '{dep_name}' uses wildcard/empty "
                            f"version constraint: '{version_spec}'"
                        ),
                        evidence=f"{dep_key}.{dep_name} = '{version_spec}'",
                        remediation=(
                            f"Pin '{dep_name}' to an exact version (e.g., "
                            f"'1.2.3') or a narrow range ('^1.2.3')."
                        ),
                        references=[
                            "https://semver.org/",
                            "https://docs.npmjs.com/cli/v10/configuring-npm/package-json",
                        ],
                    )
                )
            elif spec_stripped.startswith(">=") and " <" not in spec_stripped:
                # Open-ended >= ranges without an upper bound
                findings.append(
                    Finding(
                        rule_id="L2-MANI-001",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        package=pkg_label,
                        file=str(pkg_json),
                        message=(
                            f"Dependency '{dep_name}' uses open-ended >= "
                            f"range: '{version_spec}'"
                        ),
                        evidence=f"{dep_key}.{dep_name} = '{version_spec}'",
                        remediation=(
                            f"Add an upper bound to '{dep_name}' version range "
                            f"or use caret/tilde ranges."
                        ),
                        references=[
                            "https://semver.org/",
                        ],
                    )
                )

    return findings


def _check_optional_with_scripts(pkg: dict, pkg_json: Path) -> list[Finding]:
    """L2-MANI-002: Optional deps with install scripts are a risk vector."""
    findings: list[Finding] = []
    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    optional_deps = pkg.get("optionalDependencies", {})
    if not isinstance(optional_deps, dict) or not optional_deps:
        return findings

    scripts = pkg.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    install_scripts = {
        k for k in scripts
        if k in ("install", "postinstall", "preinstall")
    }

    if install_scripts and optional_deps:
        findings.append(
            Finding(
                rule_id="L2-MANI-002",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                package=pkg_label,
                file=str(pkg_json),
                message=(
                    f"Package has both optionalDependencies and install "
                    f"scripts ({', '.join(sorted(install_scripts))})"
                ),
                evidence=(
                    f"optionalDependencies: {list(optional_deps.keys())[:5]}, "
                    f"scripts: {list(install_scripts)}"
                ),
                remediation=(
                    "Separate optional native modules into their own packages. "
                    "Use --ignore-scripts and rebuild selectively."
                ),
                references=[
                    "https://github.com/npm/npm/issues/17152",
                ],
            )
        )

    return findings


def detect_manifest_issues(target: Path) -> list[Finding]:
    """
    Detect package manifest integrity issues.

    Scans root package.json and every node_modules/*/package.json.
    """
    findings: list[Finding] = []

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = _load_package_json(root_pkg)
        if pkg:
            findings.extend(_check_version_ranges(pkg, root_pkg))
            findings.extend(_check_optional_with_scripts(pkg, root_pkg))

    # node_modules packages
    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            pkg_json = child / "package.json"
            if pkg_json.is_file():
                pkg = _load_package_json(pkg_json)
                if pkg:
                    findings.extend(_check_version_ranges(pkg, pkg_json))
                    findings.extend(_check_optional_with_scripts(pkg, pkg_json))

            # Scoped packages
            if child.name.startswith("@") and child.is_dir():
                for scoped in sorted(child.iterdir()):
                    if not scoped.is_dir():
                        continue
                    sp = scoped / "package.json"
                    if sp.is_file():
                        pkg = _load_package_json(sp)
                        if pkg:
                            findings.extend(_check_version_ranges(pkg, sp))
                            findings.extend(_check_optional_with_scripts(pkg, sp))

    return findings
