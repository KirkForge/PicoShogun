"""
L3 Execution Sandbox — Engine.

Selects the best available backend and runs commands under policy.
"""
from __future__ import annotations

import logging
import platform

from .backends.base import SandboxBackend
from .backends.subprocess_backend import SubprocessBackend
from .models import Policy, SandboxResult

logger = logging.getLogger("iron_dome.L3.engine")


def _detect_backend() -> SandboxBackend:
    """Auto-detect the best available sandbox backend."""
    system = platform.system()

    if system == "Linux":
        try:
            from .backends.seccomp_backend import SeccompBackend
            backend = SeccompBackend()
            if backend.is_available():
                logger.info("Using seccomp-bpf backend (Linux)")
                return backend
        except ImportError:
            pass

    elif system == "Darwin":
        try:
            from .backends.seatbelt_backend import SeatbeltBackend
            backend = SeatbeltBackend()
            if backend.is_available():
                logger.info("Using seatbelt backend (macOS)")
                return backend
        except ImportError:
            pass

    logger.info("Using subprocess backend (fallback)")
    return SubprocessBackend()


# Module-level singleton
_default_backend: SandboxBackend | None = None


def get_backend() -> SandboxBackend:
    """Get the default sandbox backend (lazy init)."""
    global _default_backend
    if _default_backend is None:
        _default_backend = _detect_backend()
    return _default_backend


def set_backend(backend: SandboxBackend) -> None:
    """Override the default backend."""
    global _default_backend
    _default_backend = backend


def sandbox_run(
    command: list[str],
    policy: Policy | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
    env: dict | None = None,
    backend: SandboxBackend | None = None,
) -> SandboxResult:
    """
    Run a command under sandbox policy.

    Args:
        command: Command and arguments to execute.
        policy: Sandbox policy (None = default deny-by-default).
        timeout: Override wall-time limit (seconds).
        cwd: Working directory for the command.
        env: Environment variables.
        backend: Override backend (None = auto-detect).

    Returns:
        SandboxResult with events and overall verdict.
    """
    from .policy_loader import load_policy

    if policy is None:
        policy = load_policy()  # Default policy

    be = backend or get_backend()
    result = be.run(command, policy, timeout=timeout, cwd=cwd, env=env)

    logger.info(
        "Sandbox run %s: verdict=%s exit=%d duration=%dms events=%d",
        result.run_id,
        result.overall_verdict.value,
        result.exit_code,
        result.duration_ms,
        len(result.events),
    )

    return result
