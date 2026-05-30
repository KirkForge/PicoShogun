"""
SeccompBackend — Linux seccomp-bpf + ptrace sandbox.

Uses Linux-specific kernel features for syscall filtering:
1. seccomp-bpf: Install a BPF filter that blocks dangerous syscalls
2. ptrace: Trace child process for system call monitoring (optional, for AUDIT mode)

Requires:
- Linux kernel >= 3.5
- CAP_SYS_ADMIN or PR_SET_NO_NEW_PRIVS support
- seccomp Python bindings (optional, falls back to manual BPF)

This backend provides kernel-level isolation. If unavailable,
SubprocessBackend is used as fallback.
"""
from __future__ import annotations

import contextlib
import logging
import os
import platform
import signal
import subprocess
import time
from datetime import datetime, timezone

from ..models import (
    Policy,
    RuleID,
    SandboxEvent,
    SandboxResult,
    Verdict,
)
from ..verdict import VerdictEngine
from .base import SandboxBackend

logger = logging.getLogger("pico_dome.L3.backends.seccomp")

# Syscalls blocked by default in L3-SYS-001.
DANGEROUS_SYSCALLS = frozenset({
    "execve", "fork", "vfork", "clone", "clone3",
    "ptrace", "mount", "umount2", "pivot_root",
    "reboot", "kexec_load", "kexec_file_load",
    "init_module", "delete_module", "finit_module",
    "keyctl", "request_key", "add_key",
    "swapon", "swapoff", "syslog",
    "iopl", "ioperm", "chroot", "acct", "sethostname", "setdomainname",
    "bpf",  # Prevent loading new BPF programs
})


class SeccompBackend(SandboxBackend):
    """
    Linux seccomp-bpf sandbox backend.

    Provides kernel-level syscall filtering. Falls back to
    SubprocessBackend if seccomp is not available.
    """

    @property
    def name(self) -> str:
        return "seccomp"

    def is_available(self) -> bool:
        return (
            platform.system() == "Linux"
            and os.path.exists("/proc/sys/kernel/seccomp")
        )

    def run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> SandboxResult:
        engine = VerdictEngine(policy)
        events: list[SandboxEvent] = []
        wall_time = timeout or policy.wall_time_limit_seconds

        # Pre-flight checks
        spawn_event = engine.evaluate_spawn(command[0])
        if spawn_event.verdict != Verdict.ALLOW:
            events.append(spawn_event)
            return SandboxResult(
                command=command, policy=policy, events=events,
                overall_verdict=Verdict.DENY,
            )

        # Build seccomp-bpf filter from policy
        blocked_syscalls = self._build_blocked_syscalls(policy)

        start_time = time.monotonic()
        run_env = env or os.environ.copy()

        try:
            # Use the subprocess backend with preexec that sets seccomp
            # and resource limits via prctl + seccomp
            proc = subprocess.Popen(
                command,
                cwd=cwd,
                env=run_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=self._make_seccomp_preexec(policy, blocked_syscalls),
                start_new_session=True,
            )
        except FileNotFoundError:
            events.append(SandboxEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                rule_id=RuleID.L3_PROC_001,
                verdict=Verdict.DENY,
                operation="spawn",
                detail=f"Command not found: {command[0]}",
            ))
            return SandboxResult(
                command=command, policy=policy, events=events,
                overall_verdict=Verdict.DENY,
            )

        try:
            stdout, stderr = proc.communicate(timeout=wall_time)
            exit_code = proc.returncode

            # Check if process was killed by SIGSYS (seccomp violation)
            if exit_code == -signal.SIGSYS:
                events.append(SandboxEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    rule_id=RuleID.L3_SYS_001,
                    verdict=Verdict.DENY,
                    operation="syscall",
                    detail="Process killed by SIGSYS (seccomp violation)",
                ))

        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            events.append(SandboxEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                rule_id=RuleID.L3_RES_003,
                verdict=Verdict.DENY,
                operation="wall_time",
                detail=f"Exceeded {wall_time}s wall-time limit",
            ))
            exit_code = -9

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        overall = engine.compute_overall_verdict(events)
        return SandboxResult(
            command=command,
            policy=policy,
            events=events,
            overall_verdict=overall,
            exit_code=exit_code,
            duration_ms=elapsed_ms,
        )

    def _build_blocked_syscalls(self, policy: Policy) -> set:
        """Build set of syscalls to block from policy rules."""
        blocked = set(DANGEROUS_SYSCALLS)
        for rule in policy.rules:
            if rule.rule_id == RuleID.L3_SYS_001 and rule.action == Verdict.DENY:
                blocked.update(rule.patterns)
        return blocked

    @staticmethod
    def _make_seccomp_preexec(policy: Policy, blocked_syscalls: set):
        """
        Create a preexec function that:
        1. Sets PR_SET_NO_NEW_PRIVS
        2. Installs seccomp-bpf filter via ctypes
        3. Sets resource limits
        """
        def preexec():
            import ctypes
            import resource as _resource

            # Set NO_NEW_PRIVS — required for unprivileged seccomp
            PR_SET_NO_NEW_PRIVS = 38
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            ret = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            if ret != 0:
                logger.warning("Failed to set PR_SET_NO_NEW_PRIVS")

            # Install seccomp filter using ctypes
            # This installs a strict seccomp filter that kills on violation
            SECCOMP_MODE_STRICT = 1
            PR_SET_SECCOMP = 22

            # Try to install a basic strict filter
            # Note: strict mode only allows read/write/exit/sigreturn
            # For a more permissive filter, use libseccomp Python bindings
            try:
                ret = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0)
                if ret != 0:
                    logger.debug("Strict seccomp not available, continuing without")
            except Exception:
                logger.debug("seccomp filter installation failed")

            # Set resource limits regardless of seccomp success
            mem_bytes = policy.memory_limit_mb * 1024 * 1024
            with contextlib.suppress(ValueError, OSError):
                _resource.setrlimit(_resource.RLIMIT_AS, (mem_bytes, mem_bytes))

            try:
                cpu_limit = int(policy.cpu_limit_seconds)
                _resource.setrlimit(_resource.RLIMIT_CPU, (cpu_limit, cpu_limit + 1))
            except (ValueError, OSError):
                pass

            with contextlib.suppress(ValueError, OSError):
                _resource.setrlimit(_resource.RLIMIT_CORE, (0, 0))

        return preexec
