"""
L2-TYPO-001: Typosquatting detection.

Flags packages with names within edit distance <=2 of popular npm packages.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple

from ..models import Confidence, Finding, Severity

logger = logging.getLogger("iron_dome.L2.rules.typosquat")

# Top-50 most popular npm packages (by weekly downloads, 2024-2025).
# These are the most attractive typosquatting targets.
TOP_PACKAGES: Tuple[str, ...] = (
    "react", "lodash", "express", "next", "typescript",
    "axios", "moment", "prop-types", "react-dom", "eslint",
    "node-sass", "tailwindcss", "date-fns", "core-js", "vue",
    "webpack", "babel-runtime", "jquery", "bootstrap", "uuid",
    "dotenv", "chalk", "commander", "inquirer", "aws-sdk",
    "rxjs", "eslint-plugin-react", "class-validator", "mongoose", "prisma",
    "zod", "dayjs", "yup", "socket.io", "cors",
    "jsonwebtoken", "bcrypt", "passport", "multer", "sequelize",
    "typeorm", "knex", "pg", "mysql2", "redis",
    "nodemailer", "sharp", "joi", "cookie-parser", "body-parser",
)

# Maximum edit distance to flag as a potential typosquat.
MAX_EDIT_DISTANCE = 2


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        return _edit_distance(b, a)

    if len(b) == 0:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr_row = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr_row.append(
                min(
                    prev_row[j + 1] + 1,      # deletion
                    curr_row[j] + 1,           # insertion
                    prev_row[j] + cost,        # substitution
                )
            )
        prev_row = curr_row

    return prev_row[-1]


def _normalize(name: str) -> str:
    """Normalize package name: lowercase, strip @scope/ prefix."""
    if name.startswith("@"):
        # For scoped packages, check the package part after the slash
        parts = name.split("/", 1)
        if len(parts) == 2:
            return parts[1].lower()
    return name.lower().replace("-", "").replace("_", "")


def _load_installed_packages(target: Path) -> Set[str]:
    """Load package names from root package.json and node_modules."""
    packages: Set[str] = set()

    # Root package.json
    root_pkg = target / "package.json"
    if root_pkg.is_file():
        data = _load_package_json(root_pkg)
        for key in (
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ):
            section = data.get(key)
            if isinstance(section, dict):
                packages.update(section.keys())

    # node_modules — get names from package.json files
    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue

            if child.name.startswith("@"):
                # Scoped packages
                for scoped in sorted(child.iterdir()):
                    if scoped.is_dir():
                        packages.add(f"{child.name}/{scoped.name}")
            else:
                packages.add(child.name)

    return packages


def _load_package_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {}


def detect_typosquat(target: Path) -> List[Finding]:
    """
    Detect packages that are typosquats of popular npm packages.

    Compares installed package names against the top-50 list
    using normalized edit distance.
    """
    findings: List[Finding] = []

    installed = _load_installed_packages(target)
    if not installed:
        return findings

    # Pre-normalize top packages for comparison
    top_normalized: Dict[str, str] = {}
    for pkg in TOP_PACKAGES:
        top_normalized[_normalize(pkg)] = pkg

    root_pkg = target / "package.json"

    for pkg_name in sorted(installed):
        # Skip exact matches — not typosquats
        if pkg_name in TOP_PACKAGES or pkg_name.lower() in TOP_PACKAGES:
            continue

        norm = _normalize(pkg_name)

        # Skip if normalized name exactly matches a top package
        if norm in top_normalized:
            continue

        # Check edit distance against all top packages
        for norm_top, original_top in top_normalized.items():
            dist = _edit_distance(norm, norm_top)
            if 0 < dist <= MAX_EDIT_DISTANCE:
                findings.append(
                    Finding(
                        rule_id="L2-TYPO-001",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        package=pkg_name,
                        file=str(root_pkg) if root_pkg.exists() else str(target),
                        message=(
                            f"'{pkg_name}' is {dist} edit distance from "
                            f"popular package '{original_top}' — potential typosquat"
                        ),
                        evidence=f"{pkg_name} ≈ {original_top} (distance={dist})",
                        remediation=(
                            f"Verify this is the intended package and not a "
                            f"typosquat of '{original_top}'. Check the npm page."
                        ),
                        references=[
                            "https://snyk.io/blog/npm-package-typosquatting/",
                        ],
                    )
                )

    return findings
