"""
L2-TYPO-001: Typosquatting detection.

Flags packages whose names are within edit distance ≤2 of popular
npm packages. Attackers register misspelled names to trick developers
into installing malicious code.

Pure function: (target_path, corpus_dir) → List[Finding]

Corpus: npm_top_packages.json (327 packages, offline, versioned).
Falls back to built-in TOP_100 if corpus file is missing.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Set

from ..models import Confidence, Finding, Severity

# Built-in fallback corpus (top-100 npm packages by download count).
# Used when the corpus file is unavailable.
# The canonical corpus is scanner/corpus/npm_top_packages.json (327 packages).
BUILTIN_TOP_100: List[str] = sorted([
    "react", "react-dom", "next", "typescript", "eslint",
    "lodash", "axios", "express", "vue", "angular",
    "webpack", "babel-core", "jest", "mocha", "chalk",
    "commander", "inquirer", "dotenv", "nodemon", "npm",
    "yarn", "gulp", "grunt", "bower", "babel-loader",
    "core-js", "rxjs", "tslib", "prop-types", "styled-components",
    "material-ui", "emotion", "tailwindcss", "postcss", "sass",
    "prettier", "eslint-config-airbnb", "eslint-plugin-react",
    "babel-preset-env", "babel-preset-react", "webpack-dev-server",
    "copy-webpack-plugin", "html-webpack-plugin", "mini-css-extract-plugin",
    "terser-webpack-plugin", "fork-ts-checker-webpack-plugin",
    "css-loader", "style-loader", "file-loader", "url-loader",
    "uuid", "moment", "dayjs", "date-fns", "date-fns-tz",
    "jquery", "bootstrap", "popper.js", "d3", "chart.js",
    "three", "phaser", "pixi.js", "gsap", "hammerjs",
    "socket.io", "ws", "mqtt", "kafkajs", "amqplib",
    "mongoose", "pg", "mysql2", "redis", "ioredis",
    "prisma", "sequelize", "typeorm", "knex", "sqlite3",
    "passport", "jsonwebtoken", "bcrypt", "crypto-js", "helmet",
    "cors", "morgan", "winston", "pino", "debug",
    "bluebird", "q", "rxjs", "zod", "joi",
    "ajv", "class-validator", "yup", "io-ts", "runtypes",
])


def _load_corpus(corpus_dir: Path) -> Set[str]:
    """Load package corpus from file. Falls back to BUILTIN_TOP_100."""
    corpus_file = corpus_dir / "npm_top_packages.json"
    if corpus_file.is_file():
        try:
            data = json.loads(corpus_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return set(data)
        except (json.JSONDecodeError, OSError):
            pass
    return set(BUILTIN_TOP_100)


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein edit distance — O(len(a)*len(b))."""
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (ca != cb)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


def _load_package_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return {}


def _get_all_dep_names(pkg: dict) -> Set[str]:
    names: Set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = pkg.get(key)
        if isinstance(section, dict):
            names.update(section.keys())
    return names


def _check_typosquat(dep_name: str, corpus: Set[str]) -> List[str]:
    """Return list of popular packages within edit distance ≤2."""
    # Skip scoped packages — typosquatting targets unscoped names
    if dep_name.startswith("@"):
        return []

    matches = []
    for popular in sorted(corpus):  # sorted for determinism
        if popular == dep_name:
            continue
        if _edit_distance(dep_name, popular) <= 2:
            matches.append(popular)
    return matches


def detect_typosquat(target: Path, corpus_dir: Path) -> List[Finding]:
    """
    Detect typosquatting — dependency names close to popular packages.
    No network calls. Pure filesystem + corpus scan.
    """
    findings: List[Finding] = []
    corpus = _load_corpus(corpus_dir)

    root_pkg = target / "package.json"
    if not root_pkg.is_file():
        return findings

    pkg = _load_package_json(root_pkg)
    if not pkg:
        return findings

    # Check the package's own name first (malicious packages ARE the typosquat)
    pkg_name = pkg.get("name", "")
    if pkg_name and not pkg_name.startswith("@") and pkg_name not in corpus:
        close_matches = _check_typosquat(pkg_name, corpus)
        if close_matches:
            findings.append(
                Finding(
                    rule_id="L2-TYPO-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    package=pkg_name,
                    file=str(root_pkg),
                    message=(
                        f"Package '{pkg_name}' may be a typosquat of "
                        f"popular package(s): {', '.join(close_matches)}"
                    ),
                    evidence=f"package_name({pkg_name}) is edit_distance ≤ 2 from {close_matches[0]}",
                    remediation=(
                        f"Verify that '{pkg_name}' is the intended package, "
                        f"not a misspelling of '{close_matches[0]}'. "
                        "Check the npm page and author before installing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks-on-npm/",
                    ],
                )
            )

    all_deps = _get_all_dep_names(pkg)

    # Also check node_modules packages
    nm = target / "node_modules"
    if nm.is_dir():
        for child in sorted(nm.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            pkg_json = child / "package.json"
            if pkg_json.is_file():
                dep_data = _load_package_json(pkg_json)
                if dep_data:
                    all_deps.update(_get_all_dep_names(dep_data))

            # Scoped packages
            if child.name.startswith("@") and child.is_dir():
                for scoped_child in sorted(child.iterdir()):
                    if not scoped_child.is_dir():
                        continue
                    scoped_pkg = scoped_child / "package.json"
                    if scoped_pkg.is_file():
                        dep_data = _load_package_json(scoped_pkg)
                        if dep_data:
                            all_deps.update(_get_all_dep_names(dep_data))

    for dep_name in sorted(all_deps):
        # Skip packages that ARE in the corpus — they're legitimate, not typosquats
        if dep_name in corpus:
            continue
        close_matches = _check_typosquat(dep_name, corpus)
        if close_matches:
            findings.append(
                Finding(
                    rule_id="L2-TYPO-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    package=dep_name,
                    file=str(root_pkg),
                    message=(
                        f"Dependency '{dep_name}' may be a typosquat of "
                        f"popular package(s): {', '.join(close_matches)}"
                    ),
                    evidence=f"edit_distance({dep_name}, {close_matches[0]}) ≤ 2",
                    remediation=(
                        f"Verify that '{dep_name}' is the intended package, "
                        f"not a misspelling of '{close_matches[0]}'. "
                        "Check the npm page and author before installing."
                    ),
                    references=[
                        "https://blog.npmjs.org/post/186451959906/typosquatting-on-npm",
                        "https://snyk.io/blog/typosquatting-attacks-on-npm/",
                    ],
                )
            )

    return findings