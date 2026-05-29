"""
SARIF output formatter for L4 behavioral analysis results.

Produces SARIF v2.1.0 output compatible with GitHub Advanced Security.
"""
from __future__ import annotations

import json
from typing import IO

from ..models import AnalysisResult

_VERDICT_TO_SARIF_LEVEL = {
    "CLEAN": "note",
    "SUSPICIOUS": "warning",
    "MALICIOUS": "error",
}

_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_L4_SARIF_RULES = [
    {
        "id": "L4-TIME-001",
        "name": "SleepEvasion",
        "shortDescription": {"text": "Unnatural delays between operations (sleep evasion)"},
        "properties": {"security-severity": "5.0"},
    },
    {
        "id": "L4-TIME-002",
        "name": "TimingSideChannel",
        "shortDescription": {"text": "Timing variance suggesting side-channel attack"},
        "properties": {"security-severity": "6.0"},
    },
    {
        "id": "L4-TIME-003",
        "name": "BurstAnomaly",
        "shortDescription": {"text": "Sudden burst of operations suggesting exfil or DoS"},
        "properties": {"security-severity": "4.0"},
    },
    {
        "id": "L4-EXFIL-001",
        "name": "DNSExfiltration",
        "shortDescription": {"text": "DNS queries encoding data (exfiltration)"},
        "properties": {"security-severity": "9.0"},
    },
    {
        "id": "L4-EXFIL-002",
        "name": "HTTPSHeaderExfiltration",
        "shortDescription": {"text": "Large outbound data via HTTPS headers"},
        "properties": {"security-severity": "8.0"},
    },
    {
        "id": "L4-EXFIL-003",
        "name": "ErrorChannelExfiltration",
        "shortDescription": {"text": "Data exfiltration via error channels"},
        "properties": {"security-severity": "7.0"},
    },
    {
        "id": "L4-ENTROPY-001",
        "name": "HighEntropyEgress",
        "shortDescription": {"text": "High-entropy egress data (>7.0 bits/byte)"},
        "properties": {"security-severity": "9.0"},
    },
    {
        "id": "L4-ENTROPY-002",
        "name": "EntropySpike",
        "shortDescription": {"text": "Entropy spike vs baseline"},
        "properties": {"security-severity": "7.0"},
    },
    {
        "id": "L4-HONEY-001",
        "name": "CanaryFileAccess",
        "shortDescription": {"text": "Canary file accessed — definitive data theft indicator"},
        "properties": {"security-severity": "10.0"},
    },
    {
        "id": "L4-HONEY-002",
        "name": "CanaryDNSLookup",
        "shortDescription": {"text": "Canary DNS domain queried — definitive exfil indicator"},
        "properties": {"security-severity": "10.0"},
    },
    {
        "id": "L4-HONEY-003",
        "name": "CanaryEnvRead",
        "shortDescription": {"text": "Canary env token read — credential theft detected"},
        "properties": {"security-severity": "10.0"},
    },
    {
        "id": "L4-BASE-001",
        "name": "CallFrequencyDrift",
        "shortDescription": {"text": "Call frequency deviation from baseline"},
        "properties": {"security-severity": "6.0"},
    },
    {
        "id": "L4-BASE-002",
        "name": "NetworkProfileDrift",
        "shortDescription": {"text": "Network profile deviation from baseline"},
        "properties": {"security-severity": "7.0"},
    },
    {
        "id": "L4-BASE-003",
        "name": "ResourceCurveDrift",
        "shortDescription": {"text": "Resource curve deviation from baseline (DTW)"},
        "properties": {"security-severity": "6.0"},
    },
]


def format_sarif(result: AnalysisResult, output: IO[str] | None = None) -> str:
    """Format an AnalysisResult as SARIF v2.1.0."""
    results = []
    for finding in result.findings:
        sarif_result = {
            "ruleId": finding.rule_id,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(finding.severity.value, "warning"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file or result.target},
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
        results.append(sarif_result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecDev L4 Behavioral Analysis",
                        "version": result.engine_version,
                        "informationUri": "https://github.com/secdev/iron-dome",
                        "rules": _L4_SARIF_RULES,
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

    # Add drift results if present
    if result.drift_results:
        sarif["runs"][0]["properties"] = {
            "drift_results": [d.to_dict() for d in result.drift_results],
        }

    text = json.dumps(sarif, indent=2, ensure_ascii=False)
    if output:
        output.write(text)
        output.write("\n")
    return text
