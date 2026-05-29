"""
L3 Execution Sandbox — deterministic, zero-trust process sandboxing.

Runs commands under deny-by-default policies using:
- seccomp-bpf + ptrace (Linux)
- seatbelt/sandbox-exec (macOS)
- subprocess with resource limits (fallback)
"""
from .engine import get_backend, sandbox_run, set_backend
from .models import (
    Policy,
    PolicyRule,
    RuleID,
    SandboxEvent,
    SandboxResult,
    Severity,
    Verdict,
)
from .policy_generator import generate_policy_from_findings
from .policy_loader import load_policy, write_default_policy
from .verdict import VerdictEngine

__all__ = [
    "Policy",
    "PolicyRule",
    "RuleID",
    "SandboxEvent",
    "SandboxResult",
    "Severity",
    "Verdict",
    "VerdictEngine",
    "sandbox_run",
    "get_backend",
    "set_backend",
    "load_policy",
    "write_default_policy",
    "generate_policy_from_findings",
]
