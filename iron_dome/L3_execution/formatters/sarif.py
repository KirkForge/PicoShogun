"""SARIF v2.1.0 output formatter for sandbox results."""
from __future__ import annotations

import json
from typing import IO

from ..models import SandboxResult, Verdict

_SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_VERDICT_MAP = {
    "ALLOW": "note",
    "DENY": "error",
    "AUDIT": "warning",
}

_SARIF_RULES = [
    {"id": "L3-SYS-001", "name": "ForbiddenSyscall", "shortDescription": {"text": "Blocked dangerous syscall"}, "properties": {"security-severity": "9.0"}},
    {"id": "L3-NET-001", "name": "OutboundBlocked", "shortDescription": {"text": "Outbound network connection blocked"}, "properties": {"security-severity": "8.0"}},
    {"id": "L3-NET-002", "name": "DNSExfil", "shortDescription": {"text": "DNS exfiltration attempt flagged"}, "properties": {"security-severity": "7.0"}},
    {"id": "L3-FS-001", "name": "WriteDenied", "shortDescription": {"text": "Filesystem write denied"}, "properties": {"security-severity": "8.0"}},
    {"id": "L3-FS-002", "name": "ReadDenied", "shortDescription": {"text": "Filesystem read denied"}, "properties": {"security-severity": "5.0"}},
    {"id": "L3-PROC-001", "name": "SpawnDenied", "shortDescription": {"text": "Process spawn denied"}, "properties": {"security-severity": "9.0"}},
    {"id": "L3-PROC-002", "name": "SignalDenied", "shortDescription": {"text": "Process signal denied"}, "properties": {"security-severity": "8.0"}},
    {"id": "L3-RES-001", "name": "CPUExceeded", "shortDescription": {"text": "CPU limit exceeded"}, "properties": {"security-severity": "7.0"}},
    {"id": "L3-RES-002", "name": "MemoryExceeded", "shortDescription": {"text": "Memory limit exceeded"}, "properties": {"security-severity": "7.0"}},
    {"id": "L3-RES-003", "name": "WallTimeExceeded", "shortDescription": {"text": "Wall-time limit exceeded"}, "properties": {"security-severity": "5.0"}},
]


def format_sarif(result: SandboxResult, output: IO[str] | None = None) -> str:
    results = []
    for event in result.events:
        level = _VERDICT_MAP.get(event.verdict.value, "warning")
        results.append({
            "ruleId": event.rule_id.value if hasattr(event.rule_id, "value") else str(event.rule_id),
            "level": level,
            "message": {"text": event.detail},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": event.path or ""},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "operation": event.operation,
                "verdict": event.verdict.value,
                "address": event.address,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecDev L3 Execution Sandbox",
                    "version": result.policy.version if result.policy else "1.0",
                    "informationUri": "https://github.com/secdev/iron-dome",
                    "rules": _SARIF_RULES,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": result.overall_verdict == Verdict.ALLOW,
                "startTimeUtc": result.timestamp,
                "exitCode": result.exit_code,
            }],
        }],
    }

    text = json.dumps(sarif, indent=2, ensure_ascii=False)
    if output:
        output.write(text)
        output.write("\n")
    return text
