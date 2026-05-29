"""
SARIF formatter — Static Analysis Results Interchange Format.

Produces SARIF v2.1.0 output compatible with GitHub Advanced Security,
GitLab SAST reports, and Azure DevOps.

Deterministic: same input = same output. No random UUIDs.
"""
import json

from picosentry.models import ScanResult, Severity
from picosentry.rules import RULE_INFO

# SARIF severity mapping
SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def format_sarif(result: ScanResult) -> str:
    """
    Format a ScanResult as SARIF v2.1.0 JSON.

    Compatible with GitHub Code Scanning, GitLab SAST, Azure DevOps.
    Deterministic: sorted keys, no random content.
    """
    rules_seen = {}
    results = []

    for finding in sorted(result.findings, key=lambda f: f.sort_key()):
        # Collect unique rules for the rule definitions
        if finding.rule_id not in rules_seen:
            info = RULE_INFO.get(finding.rule_id, {})
            rules_seen[finding.rule_id] = {
                "id": finding.rule_id,
                "name": info.get("name", finding.rule_id.lower().replace("l2-", "")),
                "shortDescription": {"text": info.get("description", finding.message)},
                "properties": {
                    "security-severity": finding.severity.value,
                    "category": info.get("category", "unknown"),
                },
            }

        result_entry = {
            "ruleId": finding.rule_id,
            "ruleIndex": sorted(rules_seen.keys()).index(finding.rule_id),
            "level": SEVERITY_MAP.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        "region": {"startLine": finding.line or 1},
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

        if finding.references:
            result_entry["properties"]["references"] = finding.references

        results.append(result_entry)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "picosentry",
                        "version": result.engine_version,
                        "informationUri": "https://github.com/55N10E/SecDev_kimi",
                        "rules": [rules_seen[rid] for rid in sorted(rules_seen.keys())],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, sort_keys=True, indent=2)
