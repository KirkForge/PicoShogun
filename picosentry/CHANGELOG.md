# Changelog

All notable changes to PicoSentry will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-05-15

### Added
- **Configuration file support** (`.picosentry.yml` / `.picosentry.yaml` / `picosentry.config.yml`)
  - All CLI flags can be set in a config file in the target directory
  - Config file values are defaults; CLI flags override them
  - `severity_overrides`: downgrade/upgrade rule severity (e.g., `L2-PROV-001: INFO`)
  - `ignore_packages`: skip findings for specific package names
  - `ignore_paths`: skip findings matching glob patterns (e.g., `vendor/**`)
  - `rules`: filter which rules run (same as `--rules` CLI flag)
  - `baseline`: set default baseline file path (resolved relative to config file)
  - All other CLI flags: `format`, `no_color`, `exit_code`, `fail_on`, `quiet`, `summary`, `token_budget`
  - Config version: `version: 1` (future-proofing)
  - Search order: `.picosentry.yml` → `.picosentry.yaml` → `picosentry.config.yml`
  - Graceful fallback: missing/invalid config → use defaults (no crash)
- **Config integration tests**: 56 new tests (47 config unit + 9 integration)
- **CI workflow fix**: removed stale `picosentry/` subdirectory paths (repo root IS the project)

### Fixed
- **pyproject.toml version**: synced to match `__init__.py` (was 0.3.0, now 0.5.0)
- **CI workflow**: removed `working-directory: picosentry` and `cd picosentry` references

## [0.4.0] - 2026-05-15

### Added
- **Baseline filtering** (`--baseline` / `--baseline-update`): suppress known findings in CI
  - `--baseline baseline.json` — suppress findings matching a previous scan output
  - `--baseline ignore.txt` — simple ignore format (one rule_id per line, `#` comments)
  - `--baseline-update` — write updated baseline with current findings merged in
  - Baseline matches by (rule_id, package, file) fingerprint
  - Partial matches: rule_id-only suppresses all findings for that rule; rule_id+package suppresses all files for that package
  - 16 new tests for baseline loading, filtering, and CLI integration
- **Finding.fingerprint()** method for deterministic baseline matching
- **BaselineResult** dataclass for tracking suppressed/new finding counts
- **load_baseline()** and **apply_baseline()** functions in models.py

## [0.3.0] - 2026-05-15

### Added
- **L2-SIDELOAD-001**: Protocol sideloading detection
  - `git+ssh://` dependencies → CRITICAL (bypasses integrity + unencrypted)
  - `git://` dependencies → CRITICAL (bypasses integrity, unencrypted)
  - `git+http://` dependencies → CRITICAL (unencrypted + bypasses integrity)
  - `git+https://` dependencies → HIGH (bypasses registry integrity)
  - `github:` shorthand → HIGH (bypasses registry integrity)
  - `file:` / `file://` dependencies → MEDIUM (not reproducible across machines)
  - `link:` dependencies → MEDIUM (symlink, not portable)
  - Scans root package.json + node_modules (including @scoped packages)
  - All 4 dependency fields: dependencies, devDependencies, optionalDependencies, peerDependencies
- 23 new tests for L2-SIDELOAD-001
- 15 detector rules (was 14)
- 174 tests passing (was 151)

### Unreleased (in progress)
- GitHub Actions workflow for PicoSentry self-scan (SARIF upload)

## [0.2.0] - 2026-05-15

### Added
- **`--quiet` / `-q` flag**: CI-friendly summary mode. Shows finding count, severity breakdown, and rule counts without detailed findings.
- **`--summary` flag**: One-line output for CI notifications (Slack, Teams, etc.). Example: `PicoSentry: 3 HARD PINCH, 1 SOFT PINCH`
- 6 new CLI integration tests for `--quiet` and `--summary`

### Unreleased (in progress)
- GitHub Actions workflow for PicoSentry self-scan (SARIF upload)

## [0.2.0] - 2026-05-15

### Added
- **L2-ENGIN-001**: Engine constraint detection
  - Missing engines field (LOW without scripts, HIGH with install scripts)
  - Overly permissive engine ranges (`*`, `>=0.0.0`, `any`) → MEDIUM
  - Exact version pins (`18.17.0`) → INFO
  - npm engine without node → LOW (incomplete constraint)
  - Empty engines object → treated as missing
- **`--quiet` / `-q` flag**: CI-friendly summary mode. Shows finding count, severity breakdown, and rule counts without detailed findings.
- **`--summary` flag**: One-line output for CI notifications (Slack, Teams, etc.). Example: `PicoSentry: 3 HARD PINCH, 1 SOFT PINCH`
- 18 new tests (12 engine + 6 CLI)
- 14 detector rules (was 13)
- 151 tests passing (was 133)

## [0.1.0] - 2026-05-15

### Changed — Product Rename
- **Renamed from `supply-chain-scanner` to `picosentry`** — module, CLI, package name, all imports
- **Claw pinch branding**: Human-facing table output uses lobster-themed severity labels
  - CRITICAL/HIGH → HARD PINCH
  - MEDIUM → SOFT PINCH
  - LOW/INFO → NUDGE
  - Clean scan: "No pinches. All clear. 🦞"
- **Machine formats** (JSON, SARIF, ml-context) use standard severity labels for CI/CD compatibility
- SARIF tool driver name: `picosentry` (was `secdev-scanner`)
- CLI entry point: `picosentry` (was `supply-chain-scanner`)
- Python module: `picosentry` (was `scanner`)
- Package name: `picosentry` (was `supply-chain-scanner`)
- Version reset to 0.1.0 for product rename

### Carried Forward from scanner v0.3.0
- 13 detector rules: POST-001, OBFS-001..004, DEPC-001, TYPO-001, MANI-001/002, FORK-001, CRED-001, LOCK-001, BUND-001, PROV-001, MAINT-001, PNPM-001, LICENSE-001
- 4 output formats: JSON, SARIF 2.1.0, table (claw pinch branding), ml-context
- 133 tests passing
- Deterministic: `sha256(scan_a) == sha256(scan_b)` on identical inputs + corpus
- Offline at scan time — no HTTP calls during scanning
- IoC regression: event-stream@3.3.6, Shai-Hulud, nx typosquat, left-pad, crossenv, ua-parser-js, colors.js
- pnpm-lock.yaml v6/v9 parser
- 327-package offline typosquat corpus

## [scanner 0.3.0] - 2026-05-14

### Added
- **L2-LICENSE-001**: License compliance detection
- **`supply-chain-scanner diff`** command for determinism verification
- **`--verbose`** flag on `diff` command
- Deterministic comparison excludes `duration_ms`
- 107 → 133 tests, 12 → 13 rules

## [scanner 0.2.0] - 2026-05-14

### Added
- **L2-POST-001**: child_process detection, risk-tag remediation
- SARIF validation tests, CLI integration tests
- GitHub Actions CI (multi-version Python)
- `--rules`, `--output`, `--token-budget` CLI flags
- `rules --json`, `version`, `update` commands
- LICENSE file (MIT)

### Fixed
- `hashlib` import in `_cmd_update`
- `--no-color` strips ALL ANSI codes

## [scanner 0.1.0] - 2026-05-14

### Added
- Initial release — extracted from SecDev_kimi `iron_dome/L2_validation/`
- 12 detector rules, 4 output formats, deterministic, offline
- CLI: `supply-chain-scanner scan`, `rules`, `version`, `update`
- Pip-installable (src layout)
- IoC regression tests, pnpm lock parser, typosquat corpus
- `--severity-threshold` and `--fail-on` CLI flags