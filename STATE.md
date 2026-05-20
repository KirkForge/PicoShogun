# Shogun — PicoSentry

**Version:** 0.1.0 (picosentry) | **Last Updated:** 2026-05-15 | **Git:** `86a2b92`
**Scanner Status:** 13/13 rules implemented | 133/133 tests passing | Deterministic ✅
**Scanner Lines:** 5,200+ (27 Python files) + corpus (327 packages)
**Layout:** picosentry/ (src layout: src/picosentry/)
**Corpus Versioning:** SHA-256 hash-based (changes when corpus changes)

---

## Product Rename — 2026-05-15

**PicoSentry** is the new name. The scanner module has been renamed from `scanner`/`supply-chain-scanner` to `picosentry`.

### What Changed
- **Module:** `scanner/` → `picosentry/` (src layout: `src/picosentry/`)
- **CLI:** `supply-chain-scanner` → `picosentry`
- **Package:** `pip install picosentry` (was `supply-chain-scanner`)
- **Python import:** `from picosentry import ...` (was `from scanner import ...`)
- **SARIF driver:** `picosentry` (was `secdev-scanner`)
- **Version:** Reset to `0.1.0` for product rename (was `0.3.0` as scanner)
- **Table branding:** 🦞 PicoSentry header, HARD PINCH / SOFT PINCH / NUDGE severity labels
- **Clean scan message:** "No pinches. All clear. 🦞"
- **Machine formats** (JSON, SARIF, ml-context): Use standard severity labels (CRITICAL/HIGH/MEDIUM/LOW/INFO)

### Commands
```bash
picosentry scan ./project [--format json|sarif|table|ml-context]
picosentry scan ./project --severity-threshold high --fail-on critical
picosentry diff scan_a.json scan_b.json [--verbose]
picosentry rules [--json]
picosentry version
picosentry update  # Only command with network access
```

### Rule Catalog (13 detectors)

| ID | Rule | Detects | Severity |
|----|------|---------|----------|
| L2-POST-001 | post_install | Install scripts with network/credential access | CRITICAL/HIGH |
| L2-OBFS-001..004 | obfuscation | eval(), hex strings, base64+exec, unicode escapes | CRITICAL/HIGH |
| L2-DEPC-001 | dep_confusion | Internal deps without private registry | HIGH |
| L2-TYPO-001 | typosquat | Edit distance ≤2 from top-327 npm packages | HIGH |
| L2-MANI-001/002 | manifest | Dangerous version ranges, optional deps with scripts | MEDIUM/HIGH |
| L2-FORK-001 | fork_drift | Missing repo URL, fork indicators | MEDIUM |
| L2-CRED-001 | credential_read | Install scripts reading .npmrc, .aws/, .ssh/, env vars | HIGH |
| L2-LOCK-001 | lockfile_drift | Missing lockfile, missing deps, pnpm dangerouslyAllowAllBuilds | MEDIUM/HIGH |
| L2-BUND-001 | bundled_shadow | bundledDependencies shadows (event-stream vector) | HIGH |
| L2-PROV-001 | provenance | Missing repo, no integrity hash, scripts without provenance | LOW/MEDIUM |
| L2-MAINT-001 | maintainer_change | Author/maintainer field changes, abandoned packages | MEDIUM/HIGH |
| L2-PNPM-001 | pnpm_config | dangerouslyAllowAllBuilds, missing .npmrc, overrides, patchedDependencies | MEDIUM/CRITICAL |
| L2-LICENSE-001 | license | Missing, UNLICENSED, copyleft (GPL/AGPL/LGPL), unrecognized license | MEDIUM/HIGH/LOW |

### IoC Regression Tests
- event-stream@3.3.6, Shai-Hulud worm, nx typosquat, left-pad, crossenv, ua-parser-js@7.7.8, colors.js@1.4.2

### Determinism Guarantee
`sha256(scan_a) == sha256(scan_b)` on identical inputs + corpus version. No random IDs, no timestamps in findings.

---

## What's Archived (not deleted, decoupled)
- Orchestrator, intelligence engine, alert hub, scheduler, plugin system, WebSocket bus
- Anomaly detector, L3/L4/L5, cron generator, frontend HTML
- All still in git history, just no longer the product focus