"""
L3 Verdict Engine — evaluates operations against policy rules.

Deterministic: same policy + same operation = same verdict.
"""
from __future__ import annotations

import fnmatch
import logging
from datetime import datetime, timezone

from .models import (
    Policy,
    PolicyRule,
    RuleID,
    SandboxEvent,
    Verdict,
)

logger = logging.getLogger("iron_dome.L3.verdict")


class VerdictEngine:
    """
    Evaluate operations against a deny-by-default policy.

    Rules are evaluated in order. First matching rule wins.
    If no rule matches, the default is DENY.
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate_syscall(self, syscall_name: str) -> SandboxEvent:
        """Evaluate a syscall against the policy."""
        for rule in self.policy.rules:
            if rule.rule_id != RuleID.L3_SYS_001:
                continue
            if self._matches(syscall_name, rule.patterns):
                return self._make_event(rule, "syscall", syscall_name)

        # Default: allow syscalls not explicitly blocked
        return SandboxEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=RuleID.L3_SYS_001,
            verdict=Verdict.ALLOW,
            operation="syscall",
            detail=syscall_name,
        )

    def evaluate_network(self, host: str, port: int) -> SandboxEvent:
        """Evaluate an outbound network connection."""
        for rule in self.policy.rules:
            if rule.rule_id != RuleID.L3_NET_001:
                continue
            # Check if host matches any allowlist pattern
            if self._host_allowed(host):
                return SandboxEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    rule_id=RuleID.L3_NET_001,
                    verdict=Verdict.ALLOW,
                    operation="connect",
                    detail=f"{host}:{port}",
                    address=f"{host}:{port}",
                )
            return self._make_event(
                rule, "connect", f"{host}:{port}", address=f"{host}:{port}"
            )

        # No rule matched — deny by default
        return SandboxEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=RuleID.L3_NET_001,
            verdict=Verdict.DENY,
            operation="connect",
            detail=f"{host}:{port}",
            address=f"{host}:{port}",
        )

    def evaluate_dns(self, domain: str) -> SandboxEvent:
        """Evaluate a DNS lookup against DNS allowlist."""
        for rule in self.policy.rules:
            if rule.rule_id != RuleID.L3_NET_002:
                continue
            if self._host_allowed(domain, allowlist=self.policy.dns_allowlist):
                return SandboxEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    rule_id=RuleID.L3_NET_002,
                    verdict=Verdict.ALLOW,
                    operation="dns",
                    detail=domain,
                )
            return self._make_event(rule, "dns", domain)

        return SandboxEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=RuleID.L3_NET_002,
            verdict=Verdict.AUDIT,
            operation="dns",
            detail=domain,
        )

    def evaluate_fs_write(self, path: str) -> SandboxEvent:
        """Evaluate a filesystem write operation."""
        for rule in self.policy.rules:
            if rule.rule_id != RuleID.L3_FS_001:
                continue
            if self._path_allowed(path, self.policy.filesystem_write_allowlist):
                return SandboxEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    rule_id=RuleID.L3_FS_001,
                    verdict=Verdict.ALLOW,
                    operation="fs_write",
                    detail=path,
                    path=path,
                )
            return self._make_event(rule, "fs_write", path, path=path)

        return SandboxEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=RuleID.L3_FS_001,
            verdict=Verdict.DENY,
            operation="fs_write",
            detail=path,
            path=path,
        )

    def evaluate_fs_read(self, path: str) -> SandboxEvent:
        """Evaluate a filesystem read operation."""
        for rule in self.policy.rules:
            if rule.rule_id != RuleID.L3_FS_002:
                continue
            if self._path_allowed(path, self.policy.filesystem_read_allowlist):
                return SandboxEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    rule_id=RuleID.L3_FS_002,
                    verdict=Verdict.ALLOW,
                    operation="fs_read",
                    detail=path,
                    path=path,
                )
            return self._make_event(rule, "fs_read", path, path=path)

        return SandboxEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=RuleID.L3_FS_002,
            verdict=Verdict.DENY,
            operation="fs_read",
            detail=path,
            path=path,
        )

    def evaluate_spawn(self, command: str) -> SandboxEvent:
        """Evaluate a process spawn request."""
        for rule in self.policy.rules:
            if rule.rule_id != RuleID.L3_PROC_001:
                continue
            if self._command_allowed(command):
                return SandboxEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    rule_id=RuleID.L3_PROC_001,
                    verdict=Verdict.ALLOW,
                    operation="spawn",
                    detail=command,
                )
            return self._make_event(rule, "spawn", command)

        return SandboxEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=RuleID.L3_PROC_001,
            verdict=Verdict.DENY,
            operation="spawn",
            detail=command,
        )

    def compute_overall_verdict(self, events: list[SandboxEvent]) -> Verdict:
        """
        Compute overall verdict from a list of events.
        DENY overrides everything. AUDIT overrides ALLOW.
        """
        if not events:
            return Verdict.ALLOW

        has_deny = False
        has_audit = False
        for event in events:
            if event.verdict == Verdict.DENY:
                has_deny = True
            elif event.verdict == Verdict.AUDIT:
                has_audit = True

        if has_deny:
            return Verdict.DENY
        if has_audit:
            return Verdict.AUDIT
        return Verdict.ALLOW

    # ─── Private helpers ──────────────────────────────────────────────

    @staticmethod
    def _matches(value: str, patterns: list[str]) -> bool:
        """Check if value matches any fnmatch pattern."""
        return any(fnmatch.fnmatch(value, p) for p in patterns)

    def _host_allowed(self, host: str, allowlist: list[str] | None = None) -> bool:
        """Check if host is in the network allowlist."""
        wl = allowlist if allowlist is not None else self.policy.network_allowlist
        if not wl:
            return False
        return any(fnmatch.fnmatch(host, p) for p in wl)

    @staticmethod
    def _path_allowed(path: str, allowlist: list[str]) -> bool:
        """Check if path starts with or matches any allowlist entry."""
        if not allowlist:
            return False
        return any(path.startswith(allowed) or fnmatch.fnmatch(path, allowed) for allowed in allowlist)

    def _command_allowed(self, command: str) -> bool:
        """Check if command is in the process allowlist."""
        import os
        basename = os.path.basename(command.split()[0]) if command else ""
        for allowed in self.policy.process_allowlist:
            if fnmatch.fnmatch(basename, allowed) or fnmatch.fnmatch(command, allowed):
                return True
        return False

    @staticmethod
    def _make_event(
        rule: PolicyRule,
        operation: str,
        detail: str,
        path: str | None = None,
        address: str | None = None,
    ) -> SandboxEvent:
        return SandboxEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule_id=rule.rule_id,
            verdict=rule.action,
            operation=operation,
            detail=detail,
            path=path,
            address=address,
        )
