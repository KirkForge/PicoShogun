"""Scanner rules — deterministic, offline, pure-function detectors.

Each rule is a pure function: (target_path, corpus_dir) → List[Finding]
No HTTP. No global state. No randomness. Same input = same output.
"""
from .post_install import detect_post_install_scripts
from .obfuscation import detect_obfuscation
from .dep_confusion import detect_dep_confusion
from .typosquat import detect_typosquat
from .manifest import detect_manifest_issues
from .fork_drift import detect_fork_drift
from .credential_read import detect_credential_reading
from .lockfile_drift import detect_lockfile_drift
from .bundled_shadow import detect_bundled_shadows
from .provenance import detect_provenance_issues
from .maintainer_change import detect_maintainer_changes
from .pnpm_config import scan as detect_pnpm_config
from .license import detect_license_issues
from .engine import detect_engine_issues
from .sideloading import detect_sideloading

__all__ = [
    "detect_post_install_scripts",
    "detect_obfuscation",
    "detect_dep_confusion",
    "detect_typosquat",
    "detect_manifest_issues",
    "detect_fork_drift",
    "detect_credential_reading",
    "detect_lockfile_drift",
    "detect_bundled_shadows",
    "detect_provenance_issues",
    "detect_maintainer_changes",
    "detect_pnpm_config",
    "detect_license_issues",
    "detect_engine_issues",
    "detect_sideloading",
]

# Rule metadata registry — description, default severity, category
RULE_INFO = {
    "L2-POST-001": {
        "name": "post_install",
        "description": "Install scripts with network/credential access",
        "severity": "CRITICAL",
        "category": "execution",
    },
    "L2-OBFS-001": {
        "name": "obfuscation_eval",
        "description": "eval() calls in install scripts",
        "severity": "CRITICAL",
        "category": "obfuscation",
    },
    "L2-OBFS-002": {
        "name": "obfuscation_hex",
        "description": "Hex-encoded strings in install scripts",
        "severity": "HIGH",
        "category": "obfuscation",
    },
    "L2-OBFS-003": {
        "name": "obfuscation_base64",
        "description": "Base64 + exec patterns in install scripts",
        "severity": "CRITICAL",
        "category": "obfuscation",
    },
    "L2-OBFS-004": {
        "name": "obfuscation_unicode",
        "description": "Unicode escape sequences in install scripts",
        "severity": "HIGH",
        "category": "obfuscation",
    },
    "L2-DEPC-001": {
        "name": "dep_confusion",
        "description": "Internal dependencies without private registry configuration",
        "severity": "HIGH",
        "category": "dependency",
    },
    "L2-TYPO-001": {
        "name": "typosquat",
        "description": "Package names within edit distance ≤2 of top-327 npm packages",
        "severity": "HIGH",
        "category": "typosquat",
    },
    "L2-MANI-001": {
        "name": "manifest_version_range",
        "description": "Dangerous version ranges (*, latest, x ranges)",
        "severity": "MEDIUM",
        "category": "manifest",
    },
    "L2-MANI-002": {
        "name": "manifest_optional_scripts",
        "description": "Optional dependencies with install scripts",
        "severity": "HIGH",
        "category": "manifest",
    },
    "L2-FORK-001": {
        "name": "fork_drift",
        "description": "Missing repository URL or fork indicators",
        "severity": "MEDIUM",
        "category": "provenance",
    },
    "L2-CRED-001": {
        "name": "credential_read",
        "description": "Install scripts reading .npmrc, .aws/, .ssh/, env vars",
        "severity": "HIGH",
        "category": "credential",
    },
    "L2-LOCK-001": {
        "name": "lockfile_drift",
        "description": "Missing lockfile, missing deps, pnpm dangerouslyAllowAllBuilds",
        "severity": "MEDIUM",
        "category": "lockfile",
    },
    "L2-BUND-001": {
        "name": "bundled_shadow",
        "description": "bundledDependencies shadows (event-stream attack vector)",
        "severity": "HIGH",
        "category": "dependency",
    },
    "L2-PROV-001": {
        "name": "provenance",
        "description": "Missing repo, no integrity hash, scripts without provenance",
        "severity": "LOW",
        "category": "provenance",
    },
    "L2-MAINT-001": {
        "name": "maintainer_change",
        "description": "Publisher/author mismatch, anonymous scripts, bus factor, domain transfer",
        "severity": "MEDIUM",
        "category": "maintainer",
    },
    "L2-PNPM-001": {
        "name": "pnpm_config",
        "description": "dangerouslyAllowAllBuilds, missing .npmrc, overrides, patchedDependencies",
        "severity": "MEDIUM",
        "category": "lockfile",
    },
    "L2-LICENSE-001": {
        "name": "license",
        "description": "Missing, unlicensed, copyleft (GPL/AGPL), or unrecognized license fields",
        "severity": "MEDIUM",
        "category": "compliance",
    },
    "L2-ENGIN-001": {
        "name": "engine_constraints",
        "description": "Missing, overly permissive, or suspicious Node.js engine constraints",
        "severity": "MEDIUM",
        "category": "compatibility",
    },
    "L2-SIDELOAD-001": {
        "name": "protocol_sideloading",
        "description": "Dependencies using git://, file://, link:, github: protocols that bypass registry integrity",
        "severity": "HIGH",
        "category": "dependency",
    },
}

# Total detector rules
RULE_COUNT = len(RULE_INFO)