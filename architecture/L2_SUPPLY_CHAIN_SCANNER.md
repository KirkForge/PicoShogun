# L2 Supply Chain Scanner — Architecture Plan

## Problem

GitHub, npm, pnpm supply chain attacks are accelerating. Compromised forks, post-install scripts, dependency confusion, typosquatting, obfuscated payloads — all bypass traditional SAST. Current tools are either cloud-dependent (Snyk) or pattern-matching only (npm audit). Nobody does **deterministic, local, zero-trust** package scanning.

## Product

**PicoShogun Supply Chain Scanner** — a deterministic injection detection engine that runs locally, produces verifiable results, and integrates into CI/CD.

### Core Principles
1. **Deterministic** — same input, same output. No LLM, no probabilistic guessing.
2. **Local-first** — no cloud calls, no telemetry. Runs on the build machine.
3. **Zero-trust** — every package is hostile until proven clean.
4. **Composable** — each detector is a standalone rule. Add new rules without touching core.
5. **Fast** — scan a node_modules in <30s. Fail the build fast.

## Scope

### In Scope (L2 Scanner)
- Post-install/pre-install script detection
- Obfuscated payload detection (eval, Function, hex strings, base64)
- Dependency confusion (internal vs public namespace)
- Typosquatting detection (edit distance)
- Package manifest integrity (version range attacks, optional deps)
- Fork trust drift (divergence from upstream)
- SARIF + JSON output for CI/CD integration
- REST API endpoint for PicoShogun platform
- CLI tool for local/CI use

### Out of Scope (Future Layers)
- L3: Runtime sandboxing (seccomp, namespaces)
- L4: Behavioral analysis (honeypots, timing)
- L5: LLM prompt injection guardrails
- Package remediation (just detection, not fixing)
- Registry-side scanning (we scan what's already installed/committed)

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│                  CLI / API                    │
│  picoshogun scan ./project --format sarif        │
│  POST /api/v1/scans                          │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│              ScanEngine                      │
│  Orchestrates detectors, collects findings   │
│  Produces ScanResult with metadata           │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│           Detector Pipeline                  │
│  Each detector: find(rule) → [Finding]      │
│  Detectors are independent, composable       │
└──┬──────┬──────┬──────┬──────┬──────┬───────┘
   │      │      │      │      │      │
   ▼      ▼      ▼      ▼      ▼      ▼
┌─────┐┌─────┐┌─────┐┌─────┐┌─────┐┌─────┐
│Post ││Obfus││Dep   ││Typo ││Mani ││Fork │
│Inst ││Pkg  ││Conf ││Squat││fest ││Drift│
└─────┘└─────┘└─────┘└─────┘└─────┘└─────┘
```

## Data Model

```python
@dataclass
class Finding:
    rule_id: str          # e.g. "L2-POST-INSTALL-001"
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: str        # EXACT | HIGH | MEDIUM | LOW
    package: str           # "lodash@4.17.21"
    file: str              # "node_modules/lodash/postinstall.js"
    line: Optional[int]    # 42
    message: str           # Human-readable description
    evidence: str          # The matched string/code
    remediation: str        # What to do about it
    references: List[str]  # CVEs, blog posts, etc.

@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    target: str           # path or URL scanned
    engine_version: str
    findings: List[Finding]
    stats: ScanStats      # packages_scanned, files_scanned, duration_ms
```

## Detector Catalog

| ID | Name | What It Catches | Language |
|----|------|-----------------|----------|
| L2-POST-001 | PostInstallScript | `scripts.install`, `scripts.postinstall` in package.json | JS/TS |
| L2-OBFS-001 | EvalCall | `eval(`, `new Function(`, `Function(` | JS/TS |
| L2-OBFS-002 | HexString | `\x4c\x6f\x61\x64` style hex encoding | JS/TS |
| L2-OBFS-003 | Base64Exec | `atob(` + `eval(` or `Buffer.from(` + `eval(` | JS/TS |
| L2-OBFS-004 | UnicodeEscape | `\u0065\u0076\u0061\u006c` (eval in unicode) | JS/TS |
| L2-DEPC-001 | DepConfusion | Package name exists on both internal and public registry | JS/TS/Py |
| L2-TYPO-001 | Typosquat | Edit distance ≤2 from top-100 npm packages | JS/TS |
| L2-MANI-001 | VersionRange | `>=0.0.0`, `*`, empty version constraints | JS/TS |
| L2-MANI-002 | OptionalDeps | Packages in optionalDependencies with post-install | JS/TS |
| L2-FORK-001 | ForkDrift | Fork with no upstream sync in >90 days | any |

## File Structure

```
pico_dome/
├── L1_perimeter/
│   └── ddos_shield.py          # existing
├── L2_validation/
│   ├── __init__.py
│   ├── engine.py               # ScanEngine orchestrator
│   ├── models.py               # Finding, ScanResult, ScanStats
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── post_install.py     # L2-POST-001
│   │   ├── obfuscation.py      # L2-OBFS-001 through 004
│   │   ├── dep_confusion.py    # L2-DEPC-001
│   │   ├── typosquat.py        # L2-TYPO-001
│   │   ├── manifest.py         # L2-MANI-001, 002
│   │   └── fork_drift.py       # L2-FORK-001
│   ├── formatters/
│   │   ├── __init__.py
│   │   ├── json_fmt.py         # JSON output
│   │   ├── sarif.py             # SARIF for GitHub/GitLab
│   │   └── table.py             # Human-readable table
│   └── cli.py                   # picoshogun-scan CLI entry point
├── L3_execution/                # future
├── L4_behavioral/               # future
└── L5_prompt_shield/            # future
```

## Integration Points

1. **API**: `POST /api/v1/scans` — accepts project path or tarball, returns ScanResult
2. **CLI**: `picoshogun L2 scan --project ./project`
3. **CI/CD**: Exit code 0=clean, 1=findings, 2=error. SARIF output for GitHub Security tab.
4. **Webhook**: Scan complete → AlertHub → Discord/Slack/Email notification

## Success Metrics
- Scan 1000 packages in <30 seconds
- Zero false positives on top-100 npm packages (baseline)
- Detect all known post-install attack patterns from 2024-2026
- SARIF output accepted by GitHub Advanced Security