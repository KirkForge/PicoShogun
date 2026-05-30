"""Sandbox backends — platform-specific execution isolation."""
from .base import SandboxBackend
from .subprocess_backend import SubprocessBackend

__all__ = ["SandboxBackend", "SubprocessBackend"]
