"""
SeatbeltBackend — macOS sandbox-exec sandbox.

Uses macOS's sandbox-exec (Seatbelt) framework for process isolation.
Generates a Seatbelt profile from the policy and runs the command
under that profile.

Requires: macOS
"""
from __future__ import annotations

import logging
import os
import platform
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from typing import List, Optional

from ..models import (
    Policy,
    RuleID,
    SandboxEvent,
    SandboxResult,
    Verdict,
)
from ..verdict import VerdictEngine
from .base import SandboxBackend

logger = logging.getLogger("iron_dome.L3.backends.seatbelt")


class SeatbeltBackend(SandboxBackend):
    """
    macOS sandbox-exec backend.

    Generates a Seatbelt (sandbox-exec) profile from the policy
    and runs the command under that profile.
    """

    @property
    def name(self) -> str:
        return "seatbelt"

    def is_available(self) -> bool:
        return platform.system() == "Darwin" and os.path.exists("/usr/bin/sandbox-exec")

    def run(
        self,
        command: List[str],
        policy: Policy,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> SandboxResult:
        engine = VerdictEngine(policy)
        events: List[SandboxEvent] = []
        wall_time = timeout or policy.wall_time_limit_seconds

        # Pre-flight spawn check
        spawn_event = engine.evaluate_spawn(command[0])
        if spawn_event.verdict != Verdict.ALLOW:
            events.append(spawn_event)
            return SandboxResult(
                command=command, policy=policy, events=events,
                overall_verdict=Verdict.DENY,
            )

        # Generate Seatbelt profile
        profile_path = self._write_seatbelt_profile(policy)

        start_time = time.monotonic()
        run_env = env or os.environ.copy()

        try:
            sandbox_cmd = [
                "/usr/bin/sandbox-exec",
                "-f", str(profile_path),
                "--",
            ] + command

            proc = subprocess.Popen(
                sandbox_cmd,
                cwd=cwd,
                env=run_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

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
            exit_code = -9

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

        finally:
            try:
                os.unlink(profile_path)
            except OSError:
                pass

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        # If exit code indicates sandbox violation
        if exit_code != 0 and not any(e.verdict == Verdict.DENY for e in events):
            events.append(SandboxEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                rule_id=RuleID.L3_SYS_001,
                verdict=Verdict.AUDIT,
                operation="sandbox",
                detail=f"Process exited with code {exit_code}, possible policy violation",
            ))

        overall = engine.compute_overall_verdict(events)
        return SandboxResult(
            command=command,
            policy=policy,
            events=events,
            overall_verdict=overall,
            exit_code=exit_code,
            duration_ms=elapsed_ms,
        )

    def _write_seatbelt_profile(self, policy: Policy) -> str:
        """Generate a macOS Seatbelt profile from the policy."""
        lines = [
            "(version 1)",
            "(deny default)",
        ]

        # Network allowlist
        for host in policy.network_allowlist:
            lines.append(f'(allow network-outbound (remote ip "{host}"))')

        # Filesystem read allowlist
        for path in policy.filesystem_read_allowlist:
            lines.append(f'(allow file-read* (subpath "{path}"))')

        # Filesystem write allowlist
        for path in policy.filesystem_write_allowlist:
            lines.append(f'(allow file-write* (subpath "{path}"))')

        # Process allowlist
        for cmd in policy.process_allowlist:
            lines.append(f'(allow process-exec (literal "{cmd}"))')

        # Required system paths (always allow for basic operation)
        lines.extend([
            '(allow file-read* (subpath "/usr"))',
            '(allow file-read* (subpath "/System"))',
            '(allow file-read* (subpath "/dev"))',
            '(allow file-read* (subpath "/tmp"))',
            '(allow sysctl-read)',
            '(allow mach-lookup)',
            '(allow signal)',
        ])

        content = "\n".join(lines) + "\n"

        fd, path = tempfile.mkstemp(suffix=".sb", prefix="secdev_l3_")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path
