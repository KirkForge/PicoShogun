"""
SandboxBackend — abstract base class for execution backends.

Each backend implements platform-specific sandboxing:
- Linux: seccomp-bpf + ptrace
- macOS: seatbelt (sandbox-exec)
- Fallback: subprocess with resource limits
"""
from __future__ import annotations

import abc
from typing import List, Optional

from ..models import Policy, SandboxResult


class SandboxBackend(abc.ABC):
    """
    Abstract base for sandbox execution backends.

    A backend takes a command and a policy, runs the command under
    the constraints of the policy, and returns a SandboxResult
    with all observed events and the overall verdict.
    """

    @abc.abstractmethod
    def run(
        self,
        command: List[str],
        policy: Policy,
        timeout: Optional[float] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> SandboxResult:
        """
        Execute command under sandbox policy.

        Args:
            command: Command and arguments to execute.
            policy: Sandbox policy to enforce.
            timeout: Override wall-time limit (seconds).
            cwd: Working directory for the command.
            env: Environment variables (None = inherit parent).

        Returns:
            SandboxResult with events and overall verdict.
        """
        ...

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is available on the current platform."""
        ...

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable name of this backend."""
        ...
