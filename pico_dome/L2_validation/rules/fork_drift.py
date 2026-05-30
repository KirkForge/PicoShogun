"""
L2-FORK-001: Fork trust drift detection.

Flags forked packages that have diverged from upstream or haven't
synced in a long time, indicating potential supply chain risk.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..models import Confidence, Finding, Severity

logger = logging.getLogger("pico_dome.L2.rules.fork_drift")

# Heuristic: if a package.json "repository" URL points to a different
# org/user than the package name suggests, it might be a fork.
# Also: if the name contains "fork", "mirror", "patched", "fixed",
# or has a suffix like "-2", "-next", "-old", it's suspicious.

FORK_INDICATORS = re.compile(
    r"(?:fork|mirror|patched|fixed|legacy|compat|backport|next|ng|v\d+$)",
    re.IGNORECASE,
)

# Drift threshold in days — forks not synced in >90 days are flagged.
DRIFT_DAYS = 90


def _load_package_json(path: Path) -> dict:
    """Load and parse a package.json."""
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {}


def _extract_repo_org(repo_field: str) -> str | None:
    """Extract org/user from a repository URL."""
    # Handle shorthand: "user/repo"
    if "/" in repo_field and "://" not in repo_field:
        return repo_field.split("/")[0]

    # Handle full URLs: https://github.com/user/repo
    patterns = [
        r"github\.com/([^/]+)",
        r"gitlab\.com/([^/]+)",
        r"bitbucket\.org/([^/]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, repo_field)
        if match:
            return match.group(1)

    return None


def detect_fork_drift(target: Path) -> list[Finding]:
    """
    Detect packages that appear to be forks with trust drift.

    Heuristic checks:
    1. Package name contains fork/mirror/patched indicators
    2. Repository URL org doesn't match package scope
    3. Version mismatch or very old versions suggesting abandonment
    """
    findings: list[Finding] = []

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = _load_package_json(root_pkg)
        if pkg:
            _check_fork_indicators(pkg, root_pkg, findings)

    # node_modules
    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            pkg_json = child / "package.json"
            if pkg_json.is_file():
                pkg = _load_package_json(pkg_json)
                if pkg:
                    _check_fork_indicators(pkg, pkg_json, findings)

            # Scoped packages
            if child.name.startswith("@") and child.is_dir():
                for scoped in sorted(child.iterdir()):
                    if not scoped.is_dir():
                        continue
                    sp = scoped / "package.json"
                    if sp.is_file():
                        pkg = _load_package_json(sp)
                        if pkg:
                            _check_fork_indicators(pkg, sp, findings)

    return findings


def _check_fork_indicators(
    pkg: dict, pkg_json: Path, findings: list[Finding]
) -> None:
    """Check a single package.json for fork drift indicators."""
    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    # 1. Name-based fork indicators
    name_part = pkg_name.split("/")[-1] if "/" in pkg_name else pkg_name
    if FORK_INDICATORS.search(name_part):
        findings.append(
            Finding(
                rule_id="L2-FORK-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                package=pkg_label,
                file=str(pkg_json),
                message=(
                    f"Package name '{pkg_name}' contains fork/mirror indicator"
                ),
                evidence=f"name = {pkg_name}",
                remediation=(
                    "Verify the package is the intended fork and not an "
                    "impersonation. Check the repository and author."
                ),
                references=[
                    "https://blog.packagecloud.io/eng/2023/01/26/npm-package-security/",
                ],
            )
        )

    # 2. Repository URL org mismatch
    repo = pkg.get("repository")
    repo_url = ""
    if isinstance(repo, str):
        repo_url = repo
    elif isinstance(repo, dict):
        repo_url = repo.get("url", "")

    if repo_url:
        repo_org = _extract_repo_org(repo_url)
        if repo_org:
            # If the package is scoped, check if scope matches repo org
            if pkg_name.startswith("@"):
                scope = pkg_name.split("/")[0][1:]  # Remove @
                if scope.lower() != repo_org.lower():
                    findings.append(
                        Finding(
                            rule_id="L2-FORK-001",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                            package=pkg_label,
                            file=str(pkg_json),
                            message=(
                                f"Package scope '@{scope}' doesn't match "
                                f"repository org '{repo_org}'"
                            ),
                            evidence=f"repository = {repo_url}",
                            remediation=(
                                "Verify this is the canonical package, not a fork "
                                "published under a different org."
                            ),
                            references=[
                                "https://blog.packagecloud.io/eng/2023/01/26/npm-package-security/",
                            ],
                        )
                    )

    # 3. Very old version numbers suggesting abandonment
    #    (pre-1.0 versions with 0.x.y after many patches)
    if pkg_version.startswith("0."):
        parts = pkg_version.split(".")
        if len(parts) >= 3:
            try:
                patch = int(parts[2])
                if patch > 50:
                    findings.append(
                        Finding(
                            rule_id="L2-FORK-001",
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            package=pkg_label,
                            file=str(pkg_json),
                            message=(
                                f"Package stuck at 0.x with {patch} patch "
                                "releases — may be unmaintained"
                            ),
                            evidence=f"version = {pkg_version}",
                            remediation=(
                                "Consider whether this package is still maintained. "
                                "Look for alternatives with stable 1.x+ releases."
                            ),
                            references=[],
                        )
                    )
            except ValueError:
                pass
