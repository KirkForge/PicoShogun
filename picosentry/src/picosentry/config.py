"""
PicoSentry configuration — .picosentry.yml file loader.

Config file is optional. CLI flags override config file values.
Search order: target_dir/.picosentry.yml → target_dir/.picosentry.yaml
              → target_dir/picosentry.config.yml

Deterministic: config file is part of scan inputs. Same config = same output.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger("picosentry.config")

# Supported config file names (in order of precedence)
CONFIG_NAMES = [".picosentry.yml", ".picosentry.yaml", "picosentry.config.yml"]

# Current config schema version
CONFIG_VERSION = 1


class PicoSentryConfig:
    """
    Configuration loaded from .picosentry.yml or CLI flags.

    Config file values are defaults; CLI flags override them.

    Deterministic: same config file + same CLI flags = same effective config.
    """

    def __init__(self) -> None:
        self.format: str = "table"
        self.output: Optional[str] = None
        self.rules: Optional[List[str]] = None  # None means "all rules"
        self.corpus: Optional[str] = None
        self.no_color: bool = False
        self.token_budget: int = 4096
        self.exit_code: bool = False
        self.severity_threshold: Optional[str] = None
        self.fail_on: Optional[str] = None
        self.quiet: bool = False
        self.summary: bool = False
        self.baseline: Optional[str] = None
        self.baseline_update: bool = False
        # Config-file-only settings
        self.severity_overrides: Dict[str, str] = {}  # rule_id → severity
        self.ignore_paths: List[str] = []  # glob patterns to skip
        self.ignore_packages: List[str] = []  # package names to skip

    def merge_cli(self, args: Any) -> "PicoSentryConfig":
        """Merge CLI args into this config. CLI flags override config file values.

        Only override if the CLI arg was explicitly set (not just the default).
        """
        merged = PicoSentryConfig()
        # Copy config file values
        merged.format = self.format
        merged.output = self.output
        merged.rules = self.rules
        merged.corpus = self.corpus
        merged.no_color = self.no_color
        merged.token_budget = self.token_budget
        merged.exit_code = self.exit_code
        merged.severity_threshold = self.severity_threshold
        merged.fail_on = self.fail_on
        merged.quiet = self.quiet
        merged.summary = self.summary
        merged.baseline = self.baseline
        merged.baseline_update = self.baseline_update
        merged.severity_overrides = dict(self.severity_overrides)
        merged.ignore_paths = list(self.ignore_paths)
        merged.ignore_packages = list(self.ignore_packages)

        # Override with CLI args if explicitly set
        # argparse doesn't track "was this explicitly set?" well,
        # so we check against defaults
        if hasattr(args, "format") and args.format != "table":
            merged.format = args.format
        if hasattr(args, "output") and args.output is not None:
            merged.output = args.output
        if hasattr(args, "rules") and args.rules is not None:
            merged.rules = args.rules
        if hasattr(args, "corpus") and args.corpus is not None:
            merged.corpus = args.corpus
        if hasattr(args, "no_color") and args.no_color:
            merged.no_color = True
        if hasattr(args, "token_budget") and args.token_budget != 4096:
            merged.token_budget = args.token_budget
        if hasattr(args, "exit_code") and args.exit_code:
            merged.exit_code = True
        if hasattr(args, "severity_threshold") and args.severity_threshold is not None:
            merged.severity_threshold = args.severity_threshold
        if hasattr(args, "fail_on") and args.fail_on is not None:
            merged.fail_on = args.fail_on
            merged.exit_code = True  # fail_on implies exit_code
        if hasattr(args, "quiet") and args.quiet:
            merged.quiet = True
        if hasattr(args, "summary") and args.summary:
            merged.summary = True
        if hasattr(args, "baseline") and args.baseline is not None:
            merged.baseline = args.baseline
        if hasattr(args, "baseline_update") and args.baseline_update:
            merged.baseline_update = True

        return merged

    def apply_severity_overrides(self, findings: list) -> list:
        """Apply severity overrides from config to findings.

        Returns new list with overridden severities.
        Deterministic: same overrides + same findings = same output.
        """
        if not self.severity_overrides:
            return findings

        from .models import Severity

        overridden = []
        for f in findings:
            if f.rule_id in self.severity_overrides:
                new_sev = self.severity_overrides[f.rule_id]
                try:
                    sev_enum = Severity(new_sev.upper())
                    f = f.__class__(
                        rule_id=f.rule_id,
                        severity=sev_enum,
                        confidence=f.confidence,
                        package=f.package,
                        file=f.file,
                        message=f.message,
                        evidence=f.evidence,
                        remediation=f.remediation,
                        references=f.references,
                        line=f.line,
                    )
                except ValueError:
                    logger.warning(
                        "Invalid severity override for %s: %s (expected CRITICAL/HIGH/MEDIUM/LOW/INFO)",
                        f.rule_id, new_sev,
                    )
            overridden.append(f)
        return overridden

    def should_ignore_package(self, package_name: str) -> bool:
        """Check if a package should be ignored based on config."""
        return package_name in self.ignore_packages

    def should_ignore_path(self, file_path: str) -> bool:
        """Check if a file path should be ignored based on config glob patterns.

        Simple glob matching: * matches any sequence, ? matches single char.
        """
        if not self.ignore_paths:
            return False
        from fnmatch import fnmatch
        return any(fnmatch(file_path, pat) for pat in self.ignore_paths)


def load_config(target_dir: Path) -> PicoSentryConfig:
    """Load configuration from target directory.

    Searches for .picosentry.yml, .picosentry.yaml, or picosentry.config.yml
    in the target directory. Returns default config if no file found.

    Deterministic: same directory = same config (or default).
    """
    config = PicoSentryConfig()

    config_path = _find_config(target_dir)
    if config_path is None:
        return config

    logger.info("Loading config from %s", config_path)

    try:
        import yaml
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except ImportError:
        # YAML not available — try JSON fallback
        try:
            import json
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse config file %s: %s", config_path, e)
            return config
    except Exception as e:
        logger.warning("Failed to parse config file %s: %s", config_path, e)
        return config

    if not isinstance(data, dict):
        logger.warning("Config file %s is not a mapping, ignoring", config_path)
        return config

    # Parse config fields
    if "version" in data and data["version"] != CONFIG_VERSION:
        logger.warning(
            "Config version %s != expected %s, some fields may be ignored",
            data["version"], CONFIG_VERSION,
        )

    if "format" in data:
        config.format = data["format"]
    if "output" in data:
        config.output = data["output"]
    if "rules" in data:
        config.rules = data["rules"]
    if "corpus" in data:
        config.corpus = data["corpus"]
    if "no_color" in data:
        config.no_color = bool(data["no_color"])
    if "token_budget" in data:
        config.token_budget = int(data["token_budget"])
    if "exit_code" in data:
        config.exit_code = bool(data["exit_code"])
    if "severity_threshold" in data:
        config.severity_threshold = data["severity_threshold"]
    if "fail_on" in data:
        config.fail_on = data["fail_on"]
    if "quiet" in data:
        config.quiet = bool(data["quiet"])
    if "summary" in data:
        config.summary = bool(data["summary"])
    if "baseline" in data:
        # Resolve relative paths against config file directory
        baseline_path = data["baseline"]
        if not Path(baseline_path).is_absolute():
            baseline_path = str(config_path.parent / baseline_path)
        config.baseline = baseline_path
    if "baseline_update" in data:
        config.baseline_update = bool(data["baseline_update"])

    # Config-file-only settings
    if "severity_overrides" in data:
        config.severity_overrides = {
            str(k): str(v) for k, v in data["severity_overrides"].items()
        }
    if "ignore_paths" in data:
        config.ignore_paths = [str(p) for p in data["ignore_paths"]]
    if "ignore_packages" in data:
        config.ignore_packages = [str(p) for p in data["ignore_packages"]]

    return config


def _find_config(target_dir: Path) -> Optional[Path]:
    """Search for config file in target directory.

    Returns first match in precedence order:
    .picosentry.yml → .picosentry.yaml → picosentry.config.yml
    """
    for name in CONFIG_NAMES:
        candidate = target_dir / name
        if candidate.is_file():
            return candidate
    return None