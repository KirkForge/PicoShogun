"""
L2-DEPC-001: Dependency confusion detection.

Flags packages that appear in both internal/private registries and
the public npm registry. Attackers squat internal package names on npm
to inject malicious code via install resolution order.

Pure function: (target_path, corpus_dir) → List[Finding]
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Set

from ..models import Confidence, Finding, Severity

# Common internal package name patterns that indicate private registries.
INTERNAL_PREFIXES = (
    "@company/",
    "@internal/",
    "@corp/",
    "@acme/",
    "@myorg/",
    "@private/",
)

# Indicators in .npmrc that a private registry is configured.
NPMRC_REGISTRY_PATTERN = "registry="


def _load_package_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {}


def _get_all_deps(pkg: dict) -> Set[str]:
    deps: Set[str] = set()
    for key in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bundledDependencies",
    ):
        section = pkg.get(key)
        if isinstance(section, dict):
            deps.update(section.keys())
    return deps


def _has_private_registry(target: Path) -> bool:
    npmrc = target / ".npmrc"
    if npmrc.is_file():
        try:
            content = npmrc.read_text(encoding="utf-8", errors="replace")
            if NPMRC_REGISTRY_PATTERN in content:
                return True
        except OSError:
            pass
    return False


def detect_dep_confusion(target: Path, corpus_dir: Path) -> List[Finding]:
    """
    Detect dependency confusion vectors.
    No network calls. Pure filesystem scan.
    """
    findings: List[Finding] = []

    root_pkg = target / "package.json"
    if not root_pkg.is_file():
        return findings

    pkg = _load_package_json(root_pkg)
    if not pkg:
        return findings

    all_deps = _get_all_deps(pkg)
    if not all_deps:
        return findings

    has_private = _has_private_registry(target)

    # Flag internal-scoped packages that lack registry configuration.
    for dep_name in sorted(all_deps):
        is_internal = any(dep_name.startswith(p) for p in INTERNAL_PREFIXES)

        if is_internal and not has_private:
            findings.append(
                Finding(
                    rule_id="L2-DEPC-001",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    package=dep_name,
                    file=str(root_pkg),
                    message=(
                        f"Internal-scoped dependency '{dep_name}' declared "
                        "without private registry configuration in .npmrc"
                    ),
                    evidence=f"dependency: {dep_name}",
                    remediation=(
                        f"Add a registry override for '{dep_name}' in .npmrc "
                        "to prevent npm from resolving it from the public registry."
                    ),
                    references=[
                        "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                        "https://docs.npmjs.com/cli/v10/configuring-npm/npmrc",
                    ],
                )
            )

    # If private registry is configured, warn about deps that could resolve from public npm.
    if has_private:
        for dep_name in sorted(all_deps):
            if dep_name.startswith("@"):
                scope = dep_name.split("/")[0]
                npmrc = target / ".npmrc"
                try:
                    npmrc_text = npmrc.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    npmrc_text = ""

                if f"{scope}:registry" not in npmrc_text:
                    findings.append(
                        Finding(
                            rule_id="L2-DEPC-001",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            package=dep_name,
                            file=str(npmrc),
                            message=(
                                f"Scoped dependency '{dep_name}' may resolve "
                                "from public npm instead of private registry"
                            ),
                            evidence=f"dependency: {dep_name}, scope: {scope}",
                            remediation=(
                                f"Add '{scope}:registry=<your-private-registry>' "
                                "to .npmrc to ensure correct resolution."
                            ),
                            references=[
                                "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
                            ],
                        )
                    )

    return findings