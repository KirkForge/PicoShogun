"""
SARIF output formatter for scan results.

Produces SARIF v2.1.0 output compatible with GitHub Advanced Security,
GitLab SAST, and Azure DevOps.
"""
from __future__ import annotations

import json
from typing import IO

from ..models import ScanResult


# Map severity levels to SARIF failure levels.
_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

# SARIF rule metadata template.
_SARIF_RULES = [
    {
        "id": "L2-POST-001",
        "name": "PostInstallScript",
        "shortDescription": {"text": "Package declares an install/postinstall lifecycle script"},
        "helpUri": "https://github.com/npm/npm/issues/17152",
        "properties": {"security-severity": "8.0"},
    },
    {
        "id": "L2-OBFS-001",
        "name": "ObfuscatedPayload",
        "shortDescription": {"text": "Obfuscated code detected (eval/Function/hex/base64/unicode)"},
        "helpUri": "https://github.com/nodesource/node-js-sec-best-practices",
        "properties": {"security-severity": "9.0"},
    },
    {
        "id": "L2-DEPC-001",
        "name": "DependencyConfusion",
        "shortDescription": {"text": "Dependency confusion vector detected"},
        "helpUri": "https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4",
        "properties": {"security-severity": "9.0"},
    },
    {
        "id": "L2-TYPO-001",
        "name": "Typosquat",
        "shortDescription": {"text": "Package name is close to a popular package (potential typosquat)"},
        "helpUri": "https://snyk.io/blog/npm-package-typosquatting/",
        "properties": {"security-severity": "7.0"},
    },
    {
        "id": "L2-MANI-001",
        "name": "ManifestIntegrity",
        "shortDescription": {"text": "Package manifest has permissive version constraints or dangerous combinations"},
        "helpUri": "https://docs.npmjs.com/cli/v10/configuring-npm/package-json",
        "properties": {"security-severity": "6.5"},
    },
    {
        "id": "L2-FORK-001",
        "name": "ForkDrift",
        "shortDescription": {"text": "Package appears to be a fork with trust drift from upstream"},
        "helpUri": "https://blog.packagecloud.io/eng/2023/01/26/npm-package-security/",
        "properties": {"security-severity": "5.0"},
    },
]


def format_sarif(result: ScanResult, output: IO[str] | None = None) -> str:
    """
    Format a ScanResult as SARIF v2.1.0.

    Args:
        result: The scan result to format.
        output: Optional writable stream.

    Returns:
        SARIF JSON string.
    """
    results = []
    for finding in result.findings:
        sarif_result = {
            "ruleId": finding.rule_id,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(
                finding.severity.value, "warning"
            ),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        "region": {
                            "startLine": finding.line or 1,
                        },
                    }
                }
            ],
            "properties": {
                "package": finding.package,
                "confidence": finding.confidence.value,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
            },
        }
        results.append(sarif_result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecDev L2 Supply Chain Scanner",
                        "version": result.engine_version,
                        "informationUri": "https://github.com/secdev/iron-dome",
                        "rules": _SARIF_RULES,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": result.timestamp,
                    }
                ],
            }
        ],
    }

    text = json.dumps(sarif, indent=2, ensure_ascii=False)
    if output:
        output.write(text)
        output.write("\n")
    return text
