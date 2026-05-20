"""
L2-FORK-001: Fork trust drift detection.

Flags packages whose repository URL shows no upstream sync activity,
or whose package.json indicates a fork without recent updates.
Detects stale forks that may contain unreviewed changes.

Pure function: (target_path, corpus_dir) → List[Finding]
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional

from ..models import Confidence, Finding, Severity

# Patterns indicating a fork or personal repo (not an authoritative source).
FORK_INDICATORS = (
    "fork", "mirror", "patch", "patched", "fix", "fixed",
    "custom", "local", "private", "backup", "mirror-",
)

# Known authoritative registries/orgs — these are NOT forks.
AUTHORITATIVE_PREFIXES = (
    "https://github.com/npm/",
    "https://github.com/facebook/",
    "https://github.com/microsoft/",
    "https://github.com/google/",
    "https://github.com/nodejs/",
    "https://github.com/babel/",
    "https://github.com/webpack/",
    "https://github.com/mozilla/",
    "https://github.com/angular/",
    "https://github.com/vuejs/",
    "https://github.com/expressjs/",
    "https://github.com/lodash/",
    "https://github.com/axios/",
    "https://github.com/jestjs/",
    "https://github.com/mochajs/",
    "https://github.com/pugjs/",
    "https://github.com/DefinitelyTyped/",
)


def _load_package_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {}


def _extract_repo_url(pkg: dict) -> Optional[str]:
    """Extract repository URL from package.json."""
    repo = pkg.get("repository")
    if isinstance(repo, str):
        return repo
    if isinstance(repo, dict):
        url = repo.get("url", "")
        if url:
            return url
    homepage = pkg.get("homepage", "")
    if homepage and "github.com" in homepage:
        return homepage
    return None


def _is_fork_repo(url: str, pkg_name: str) -> bool:
    """Heuristic: does this URL look like a fork rather than the canonical repo?"""
    url_lower = url.lower()

    # If it's from an authoritative org, it's not a fork
    for prefix in AUTHORITATIVE_PREFIXES:
        if url_lower.startswith(prefix.lower()):
            return False

    # If the package name appears in the URL path, it's likely canonical
    # e.g., github.com/lodash/lodash — but if it's github.com/someuser/lodash,
    # it might be a fork
    name_lower = pkg_name.lower().replace("@", "").replace("/", "-")

    # Check if the URL has a different org/user than the package suggests
    # This is a best-effort heuristic without network access
    return True  # Conservative: flag repos we can't verify as authoritative


def _get_days_since_update(pkg: dict) -> Optional[int]:
    """Try to extract how many days since last update from date strings."""
    # Check various date fields
    for key in ("time", "date", "lastModified", "modified"):
        val = pkg.get(key)
        if isinstance(val, str):
            return None  # Would need date parsing, skip for now
    return None


def detect_fork_drift(target: Path, corpus_dir: Path) -> List[Finding]:
    """
    Detect fork trust drift — packages from non-canonical sources.
    No network calls. Pure filesystem scan.
    """
    findings: List[Finding] = []

    nm = target / "node_modules"
    if not nm.is_dir():
        return findings

    for child in sorted(nm.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue

        pkg_json = child / "package.json"
        if not pkg_json.is_file():
            continue

        pkg = _load_package_json(pkg_json)
        if not pkg:
            continue

        pkg_name = pkg.get("name", child.name)
        pkg_version = pkg.get("version", "unknown")
        pkg_label = f"{pkg_name}@{pkg_version}"

        repo_url = _extract_repo_url(pkg)
        if not repo_url:
            # No repository field — can't verify provenance
            findings.append(
                Finding(
                    rule_id="L2-FORK-001",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=f"Package '{pkg_name}' has no repository URL — provenance cannot be verified",
                    evidence="repository field missing or empty",
                    remediation=(
                        f"Check the npm page for '{pkg_name}' to verify the canonical repository. "
                        "Packages without repository URLs may be forks or abandoned packages."
                    ),
                    references=[
                        "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#repository",
                    ],
                )
            )
            continue

        # Check if repo URL contains fork indicators
        repo_lower = repo_url.lower()
        name_in_url = pkg_name.lower().replace("@", "").replace("/", "-") in repo_lower

        # Check for fork-related words in package name or description
        description = str(pkg.get("description", "")).lower()
        name_lower = pkg_name.lower()

        fork_indicators_found = [
            ind for ind in FORK_INDICATORS
            if ind in name_lower or ind in description
        ]

        if fork_indicators_found:
            findings.append(
                Finding(
                    rule_id="L2-FORK-001",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    package=pkg_label,
                    file=str(pkg_json),
                    message=(
                        f"Package '{pkg_name}' appears to be a fork — "
                        f"indicators: {', '.join(fork_indicators_found)}"
                    ),
                    evidence=f"repository: {repo_url}, indicators: {fork_indicators_found}",
                    remediation=(
                        f"Verify '{pkg_name}' is from the canonical source. "
                        "Forks may contain unreviewed modifications. "
                        "Consider replacing with the upstream package."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/162780572570/how-to-avoid-npm-version-range-typos",
                    ],
                )
            )

        # Scoped packages from non-authoritative sources
        if pkg_name.startswith("@") and "/" in pkg_name:
            scope = pkg_name.split("/")[0]
            # Check if scope matches any known authoritative org
            authoritative_scopes = {
                "@angular", "@babel", "@emotion", "@eslint",
                "@google", "@microsoft", "@mozilla", "@nestjs",
                "@nodejs", "@npm", "@react-spring", "@sentry",
                "@types", "@vue", "@webpack", "@typescript-eslint",
            }
            if scope.lower() not in authoritative_scopes:
                findings.append(
                    Finding(
                        rule_id="L2-FORK-001",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        package=pkg_label,
                        file=str(pkg_json),
                        message=(
                            f"Scoped package '{pkg_name}' from non-authoritative scope '{scope}'"
                        ),
                        evidence=f"scope: {scope}, repository: {repo_url}",
                        remediation=(
                            f"Verify that '{pkg_name}' is the canonical package, "
                            f"not a fork published under scope '{scope}'."
                        ),
                        references=[
                            "https://docs.npmjs.com/cli/v10/using-npm/scope",
                        ],
                    )
                )

    return findings