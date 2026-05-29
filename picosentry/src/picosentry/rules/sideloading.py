"""
L2-SIDELOAD-001: Detect non-registry dependency protocols.

Flags dependencies that use git://, git+ssh://, git+https://, file://,
link:, or github: protocols instead of registry versions. These bypass
npm integrity guarantees and are a known supply chain attack vector.

Pure function: (target_path, corpus_dir) → List[Finding]
"""
from __future__ import annotations

import json
from pathlib import Path

from ..models import Confidence, Finding, Severity

# Dependency fields that may contain version specifiers
DEP_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)

# Protocol patterns and their risk levels
PROTOCOL_PATTERNS: list[tuple[str, str, Severity, str]] = [
    # (prefix, description, severity, remediation_hint)
    (
        "git+ssh://",
        "git+ssh:// dependency — bypasses registry integrity, uses SSH",
        Severity.CRITICAL,
        "Replace with a registry version. SSH URLs bypass npm integrity checks and can point to any repo.",
    ),
    (
        "git://",
        "git:// dependency — bypasses registry integrity, unencrypted protocol",
        Severity.CRITICAL,
        "Replace with a registry version. git:// is unencrypted and bypasses npm integrity checks.",
    ),
    (
        "git+https://",
        "git+https:// dependency — bypasses registry integrity",
        Severity.HIGH,
        "Replace with a registry version if possible. git+https:// bypasses npm registry integrity.",
    ),
    (
        "git+http://",
        "git+http:// dependency — unencrypted, bypasses registry integrity",
        Severity.CRITICAL,
        "Replace with a registry version. git+http:// is unencrypted and bypasses integrity checks.",
    ),
    (
        "github:",
        "github: shorthand dependency — bypasses registry integrity",
        Severity.HIGH,
        "Replace with a registry version. github: shorthand bypasses npm registry integrity checks.",
    ),
    (
        "file:",
        "file: dependency — local path reference, not reproducible",
        Severity.MEDIUM,
        "file: dependencies are not reproducible across machines. Use registry versions for production.",
    ),
    (
        "link:",
        "link: dependency — symlink reference, not portable",
        Severity.MEDIUM,
        "link: dependencies create symlinks and are not portable. Use registry versions for production.",
    ),
]


def _extract_protocol_deps(pkg_data: dict, pkg_name: str) -> list[Finding]:
    """Extract all non-registry dependencies from a package.json."""
    findings: list[Finding] = []

    for field in DEP_FIELDS:
        deps = pkg_data.get(field)
        if not isinstance(deps, dict):
            continue

        for dep_name, version_spec in deps.items():
            if not isinstance(version_spec, str):
                continue

            for prefix, description, severity, remediation in PROTOCOL_PATTERNS:
                if version_spec.startswith(prefix):
                    findings.append(Finding(
                        rule_id="L2-SIDELOAD-001",
                        package=dep_name,
                        severity=severity,
                        confidence=Confidence.EXACT,
                        file="package.json",
                        line=None,
                        message=description,
                        evidence=f"{field}.{dep_name} = {version_spec!r}",
                        remediation=remediation,
                        references=[
                            "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#git-urls-as-dependencies",
                            "https://blog.vlt.sh/blog/postinstall-harm",
                        ],
                    ))
                    break  # Only flag once per dependency (first matching protocol)

    return findings


def detect_sideloading(target: Path, corpus_dir: Path) -> list[Finding]:
    """
    Detect dependencies using non-registry protocols.

    Scans root package.json for git://, file://, link:, github: protocols.
    These bypass npm registry integrity and are a supply chain attack vector.
    """
    findings: list[Finding] = []

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        try:
            data = json.loads(root_pkg.read_text(encoding="utf-8", errors="replace"))
            pkg_name = data.get("name", root_pkg.parent.name)
            findings.extend(_extract_protocol_deps(data, pkg_name))
        except (json.JSONDecodeError, OSError):
            pass

    # node_modules packages (transitive sideloading)
    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            pkg_json = child / "package.json"
            if pkg_json.is_file():
                try:
                    data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
                    pkg_name = data.get("name", child.name)
                    findings.extend(_extract_protocol_deps(data, pkg_name))
                except (json.JSONDecodeError, OSError):
                    pass

            # Scoped packages
            if child.name.startswith("@") and child.is_dir():
                for scoped_child in sorted(child.iterdir()):
                    if not scoped_child.is_dir():
                        continue
                    scoped_pkg = scoped_child / "package.json"
                    if scoped_pkg.is_file():
                        try:
                            data = json.loads(scoped_pkg.read_text(encoding="utf-8", errors="replace"))
                            pkg_name = data.get("name", str(scoped_child.name))
                            findings.extend(_extract_protocol_deps(data, pkg_name))
                        except (json.JSONDecodeError, OSError):
                            pass

    return findings
