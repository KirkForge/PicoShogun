# Pico Series — State of Play

**Updated:** 2026-05-30 (post-session)
**Series:** PicoSentry → PicoDome → PicoWatch → PicoShogun

---

## GitHub Repo Naming Status

| Product   | GitHub Repo          | Local Dir                      | Renamed on GitHub? |
|-----------|---------------------|--------------------------------|---------------------|
| PicoSentry| KirkForge/PicoSentry| /Madlab/Clean-Live/PicoSentry  | ✅ Yes              |
| PicoDome  | KirkForge/PicoDome  | /Madlab/Clean-Live/PicoDome    | ✅ Yes              |
| PicoWatch | KirkForge/PicoWatch | /Madlab/Clean-Live/PicoWatch   | ✅ Yes              |
| PicoShogun| KirkForge/PicoShogun| /Madlab/Clean-Live/PicoShogun | ✅ Yes              |

All local dirs, remotes, and package names aligned. `.venv` symlinks point to sandbox.

---

## Codebase Naming Cleanup — Completed

| Repo        | Old package dir    | New package dir    | Status |
|-------------|-------------------|--------------------|--------|
| PicoSentry  | `picosentry/`     | `picosentry/`      | ✅ Clean |
| PicoDome    | `irondome/`       | `picodome/`        | ✅ Renamed |
| PicoWatch   | `picowatch/`      | `picowatch/`       | ✅ Clean |
| PicoShogun  | `iron_dome/`      | `pico_dome/`       | ✅ Renamed |

---

## License Alignment — Completed

All four repos: **BUSL-1.1** with LICENSE, LICENSE-SUMMARY.md, and COMMERCIAL-LICENSE.md. Change Date: 3 years → Apache-2.0.

---

## CI / Infra Status

- **GitHub Actions billing:** Rate limited, resets June 1
- **gitleaks:** Installed and working
- **trufflehog:** Installed and working
- **All repos on `main`** — `master` branches deleted
- **All repos pass pre-push CI gate** (gitleaks + trufflehog)

---

## PicoSentry — Review-Ready ✅

Two external reviews passed. All flags addressed. 1390 tests green, ruff clean, wheel builds, deterministic SHA-256 verified.

| Metric | Value |
|--------|-------|
| Version | 0.16.0 |
| License | BUSL-1.1 |
| Tests | 1390 passing, 8 skipped (slow), 7 skipped (PyJWT) |
| Runtime deps | Zero (pyyaml optional) |
| CLI | `picosentry` ✅ |
| CI | Full matrix (3.10–3.13, Windows), lint, typecheck, determinism, self-scan, pip-audit, wheel smoke test |
| Reviews | Opus 4.8 ✅ + GPT-5.5 ✅ — all flags fixed |

**Next step:** Final read-through, `git tag v0.16.0 && git push --tags` after Actions billing resets.

---

## PicoDome — Publish-Ready ✅

Three external code reviews closed. Seccomp saga resolved end-to-end. 1459 tests, ruff/mypy clean.

| Metric | Value |
|--------|-------|
| Version | 0.5.0 |
| Tests | 1459 passing, 12 skipped (sandbox-dep) |
| Runtime deps | Zero (pyyaml, libseccomp optional) |
| Detection rules | 10 L3 + 15 L4 (27 total) |
| CLI | `picodome` ✅ |
| CI | ruff ✅, mypy ✅, compile ✅, wheel ✅ |
| Reviews | Opus 4.8 (3 rounds) ✅ + GPT 5.5 ✅ |

**Next step:** Tag v0.5.0 whenever ready.

---

## PicoWatch — Polish-Ready ✅

Two external reviews (Opus 4.8 + GPT-5.5) passed. All flags addressed across 3 rounds. 258 tests, ruff/mypy clean, wheel builds with bundled rules corpus.

| Metric | Value |
|--------|-------|
| Version | 0.7.0 |
| Tests | 258 passing |
| Detection rules | 59 L5 + 32 L6 (91 total) |
| Runtime deps | pyyaml (optional: fastapi, uvicorn, opentelemetry) |
| CLI | `picowatch` ✅ |
| Reviews | Opus 4.8 ✅ + GPT-5.5 ✅ — all flags fixed |

**Next step:** Tag v0.7.0 whenever ready.

---

## PicoShogun — Session 1 Fixes Applied ✅

All 13 items from the session plan completed. 44 tests passing, ruff clean.

| Metric | Value |
|--------|-------|
| Version | **0.1.0** (was 2.16.0 — honest pre-1.0 alpha) |
| Tests | 44 passing (was 20) |
| Ruff | ✅ Clean |
| Broken endpoints | ✅ All 15+ fixed |
| Security bugs | ✅ All 3 fixed (PBKDF2 timing, shell=True, hardcoded IP) |

### Fixes applied this session:

1. **15+ broken API endpoints** — `register`, `login`, `list_plugins`, `list_webhooks`, `create_webhook`, `scheduler/*`, `acknowledge_alert`, `export_project`, `get_logs`, `status` key mismatches, `run_project` kwargs
2. **`/status` key mismatches** — `total_projects` → `projects_total`, `active_projects` → `projects_active`, `started_at` → `uptime_seconds`
3. **PBKDF2 timing leak** — `services/auth.py` now uses `hmac.compare_digest()` instead of `==`
4. **Scheduler result type** — `result.get("status")` → `result.get("success")`
5. **Vendored `picosentry/` removed** — entire directory + `[tool.picosentry]` from pyproject.toml
6. **`orchestrator/master.py` removed** — deprecated, superseded by `services/orchestrator.py`
7. **Honest version** — 2.16.0 → 0.1.0 across pyproject.toml, `__init__.py`, `api/server.py` (3 places), `observability.py` (3 places), `backup.py`, test
8. **`shell=True` fixed** — `scripts/daily_worker.py` now uses `shlex.split()`
9. **Hardcoded IP fixed** — `scripts/test_auth.py` uses `PICOSHOGUN_TEST_URL` env var
10. **Discord notifier marked honestly** — plugin docs say "LOG-ONLY, does not send to Discord"
11. **Obsolete license classifier removed** — `License :: Other/Proprietary License` gone
12. **Test coverage expanded** — 20 → 44 tests (auth, scheduler, webhooks, SSRF, metrics, services)
13. **Ruff/mypy clean**

### Additional fixes found during session:

- **Prometheus triple-pico prefix** — `picopicopicoshogun_` → `picoshogun_` in `services/metrics.py`
- **DB schema mismatches** — `scheduled_jobs` table now has `cron_expression`, `params`, `enabled` (was `schedule`, `active`, no params); `webhooks` table has `retries`
- **`/logs` endpoint** — `LogManager.get_logs()` doesn't exist → returns `get_stats()`

### Remaining known issues / next session work:

- **PicoShogun `pico_dome/` vendored code** — still bundled, should be dependency or removed
- **PicoShogun test coverage** — 44 tests is better but still light for ~14k LOC; need integration tests
- **PicoShogun `daily_worker.py` INFRA tasks** — still reference hardcoded paths, need env vars
- **PicoShogun `observability.py` version strings** — now 0.1.0 but hardcoded; should read from `__init__.__version__`
- **PicoShogun `services/webhooks.py` `WebhookManager.create()`** — takes `(name, url, events, secret)` but API sends `(url, events, secret)` — name defaults to "default"
- **PicoShogun `backup.py` version** — metadata says `"2.0.0"`, now `"0.1.0"` but should derive from package
- **PicoDome license gate** — accepts any `shogun-` key (placeholder until Shogun ships)
- **PicoWatch `RateLimiter._clients`** — grows unboundedly, no LRU/TTL eviction
- **PicoWatch audit HMAC key** — hardcoded, tamper-detection only
- **PicoWatch output guard PII** — `valid=False, score=0.0` can confuse API users
- **Dopaflow** — needs AI-slop cleanup
- **55NDeep-Plugin** — needs honest docs rewrite

---

## Publish Roadmap Summary

| Product | Publishable Beta | Ready for 1.0 | Key Gap |
|---------|-----------------|----------------|---------|
| PicoSentry | ✅ Done — tag v0.16.0 | ~2 weeks | Security review |
| PicoDome | ✅ Done — tag v0.5.0 | ~4 weeks | K8s deployment evidence |
| PicoWatch | ✅ Done — tag v0.7.0 | ~4 weeks | Real LLM traffic testing |
| PicoShogun | 🟡 1 more session | ~6+ weeks | Remove pico_dome vendored code, integration tests, daily_worker env vars |

---

## Product Identity — Pico Security Series

| Product    | Layer          | Purpose                                    |
|------------|----------------|--------------------------------------------|
| PicoSentry | L2 Supply-chain| Deterministic npm/pnpm dependency scanner  |
| PicoDome   | L3/L4 Runtime  | Deterministic runtime sandbox & behavioral analysis |
| PicoWatch  | L5-L7 LLM Defense| LLM prompt injection detection & defense  |
| PicoShogun | Command Centre  | Orchestration, firewall, monitoring        |

---

## User Preferences (Important)

- **Honest docs only** — no inflated claims, no "enterprise" on scaffolded features, no 9/10 readiness scores
- **Git auth:** SSH only, never reference PATs
- **Git identity:** Henrik Kirk <285947470+KirkForge@users.noreply.github.com>
- **Commit format:** type(scope): message
- **License:** BUSL-1.1 across Pico series
- **GitHub repo names:** PicoSentry, PicoDome, PicoWatch, PicoShogun
- **Package naming:** `picosentry`, `picodome`, `picowatch`, `picoshogun` (no old names)

---

## Known Issues / Tech Debt

- **PicoShogun `pico_dome/` vendored code** — still bundled, should be dependency or removed
- **PicoShogun test coverage** — 44 tests still light for ~14k LOC
- **PicoShogun `daily_worker.py`** — hardcoded paths, needs env vars
- **PicoShogun `observability.py`** — version strings hardcoded, should read from `__version__`
- **PicoDome license gate** — accepts any `shogun-` key (placeholder until Shogun ships)
- **PicoDome SLSA L3 provenance** — generated but hermetic builds not yet achieved
- **PicoWatch `RateLimiter._clients`** — grows unboundedly, no LRU/TTL eviction
- **PicoWatch audit HMAC key** — hardcoded, tamper-detection only
- **PicoWatch output guard PII** — `valid=False, score=0.0` can confuse API users
- **Dopaflow** — needs AI-slop cleanup
- **55NDeep-Plugin** — needs honest docs rewrite

---

## Session Handoff Notes (for next session)

- **PicoSentry** — publish-ready, tag v0.16.0 after Actions billing resets
- **PicoDome** — publish-ready, tag v0.5.0 whenever
- **PicoWatch** — polish-ready, all review flags fixed, tag v0.7.0 whenever
- **PicoShogun** — session 1 fixes applied and committed. Remaining: remove pico_dome vendored code, integration tests, daily_worker env vars, observability version dynamic read

---

## PicoShogun — Session Plan (Next Session)

**Local dir:** `/Madlab/Clean-Live/PicoShogun`
**Git identity:** Henrik Kirk <285947470+KirkForge@users.noreply.github.com>
**Commit format:** type(scope): message

**Priority order:**

1. **Remove `pico_dome/` vendored code** — make it a proper dependency or remove entirely
2. **Integration tests** — test actual API flows end-to-end (auth → project run → alerts)
3. **`daily_worker.py` env vars** — replace hardcoded paths with env vars
4. **`observability.py` dynamic version** — read from `picoshogun.__version__`
5. **`webhooks.py` API alignment** — ensure create() params match what the API sends
6. **`backup.py` version** — derive from package version
7. **Final ruff/mypy/test run** — clean sweep
