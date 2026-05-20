"""L2 Validation detector rules."""
from .post_install import detect_post_install_scripts
from .obfuscation import detect_obfuscation
from .dep_confusion import detect_dep_confusion
from .typosquat import detect_typosquat
from .manifest import detect_manifest_issues
from .fork_drift import detect_fork_drift

__all__ = [
    "detect_post_install_scripts",
    "detect_obfuscation",
    "detect_dep_confusion",
    "detect_typosquat",
    "detect_manifest_issues",
    "detect_fork_drift",
]
