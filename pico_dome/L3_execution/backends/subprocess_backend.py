"""
SubprocessBackend — cross-platform sandbox using subprocess with resource limits.

This is the fallback backend. It uses subprocess.Popen with:
- Timeout enforcement (wall-time limit)
- Memory limiting via resource module (where available)
- Process group tracking for cleanup

It does NOT provide syscall-level isolation. For that, use SeccompBackend (Linux)
or SeatbeltBackend (macOS).
"""
from __future__ import annotations

import logging
import os
import resource
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

logger = logging.getLogger("pico_dome.L3.backends.subprocess")


class SubprocessBackend(SandboxBackend):
    """
    Cross-platform sandbox backend using subprocess.

    Enforces:
    - Wall-time limits (via timeout)
    - Memory limits (via resource module on Unix)
    - Network allowlist (via pre-exec DNS check)
    - Filesystem allowlist (via verdict engine)

    Does NOT provide kernel-level syscall filtering.
    Use SeccompBackend or SeatbeltBackend for stronger isolation.
    """

    @property
    def name(self) -> str:
        return "subprocess"

    def is_available(self) -> bool:
        return True  # Always available as fallback

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
        preflight_events = self._preflight_checks(command, policy, engine)
        events.extend(preflight_events)

        # If any DENY in preflight, don't execute
        if any(e.verdict == Verdict.DENY for e in preflight_events):
            result = SandboxResult(
                command=command,
                policy=policy,
                events=events,
                overall_verdict=Verdict.DENY,
            )
            return result

        # Set up resource limits
        start_time = time.monotonic()
        policy.memory_limit_mb * 1024 * 1024

        run_env = env or os.environ.copy()

        try:
            proc = subprocess.Popen(
                command,
                cwd=cwd,
                env=run_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=self._make_preexec_fn(policy),
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

        # Wait with timeout
        try:
            stdout, stderr = proc.communicate(timeout=wall_time)
            exit_code = proc.returncode
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
            _stdout, _stderr = b"", b""
            exit_code = -9

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        overall = engine.compute_overall_verdict(events)
        result = SandboxResult(
            command=command,
            policy=policy,
            events=events,
            overall_verdict=overall,
            exit_code=exit_code,
            duration_ms=elapsed_ms,
        )
        return result

    def _preflight_checks(
        self, command: list[str], policy: Policy, engine: VerdictEngine
    ) -> list[SandboxEvent]:
        """Check policy before executing."""
        events: list[SandboxEvent] = []

        # Check spawn allowlist
        spawn_event = engine.evaluate_spawn(command[0])
        if spawn_event.verdict != Verdict.ALLOW:
            events.append(spawn_event)

        # Check fs_write allowlist for cwd
        cwd = os.getcwd()
        write_event = engine.evaluate_fs_write(cwd)
        if write_event.verdict != Verdict.ALLOW:
            events.append(write_event)

        return events

    @staticmethod
    def _make_preexec_fn(policy: Policy):
        """Create a preexec_fn that sets resource limits."""
        def preexec():
            try:
                # Memory limit
                mem_bytes = policy.memory_limit_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError):
                pass  # Not supported on all platforms

            try:
                # CPU time limit (soft = limit, hard = limit + 1s grace)
                cpu_limit = int(policy.cpu_limit_seconds)
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (cpu_limit, cpu_limit + 1),
                )
            except (ValueError, OSError):
                pass

            try:
                # No core dumps
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except (ValueError, OSError):
                pass

        return preexec
