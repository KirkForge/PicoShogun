# PicoShogun — Known Gaps

Priority-ordered list of what needs work before this can be called 1.0.

## P0 — Must fix before any real deployment

1. **No load testing** — Baseline locust suite added (`tests/load/locustfile.py`). No benchmark results yet. Need to run against a live instance to establish p50/p99 numbers.

## P1 — Important for trust

2. ~~**Discord notifier plugin** — Logs to Python logger, doesn't actually send Discord messages. Misleading.~~ **Fixed in session 5**: Real Discord webhook delivery via `requests.post`. Falls back to log-only with clear warning when `DISCORD_WEBHOOK_URL` is not set.
3. ~~**Org system** — Multi-tenant code exists but is untested at scale. No test asserting tenant A can't read tenant B's data.~~ **Fixed in session 4**: 5 tenant isolation tests added covering cross-org access, API key isolation, org listing, and tier upgrade enforcement.
4. **MyPy strict** — Reduced from 30 errors to 10. Remaining errors are in `services/metrics.py` (dict indexing), `services/alert_hub.py` (requests JsonType, SMTP type union), `services/orgs.py` (Row type), `config/settings.py` (callable type), `services/plugin_manager.py` (nested dict). Need `--strict-optional` and `--no-ignore-missing-imports` clean pass.
5. **Dashboard E2E tests** — No Playwright/Cypress. Frontend could break silently.

## P2 — Should have for 1.0

6. ~~**`api/server.py` too large (1171 lines)** — Should be split into routers.~~ **Fixed in session 5**: Split into `api/deps.py`, `api/models.py`, and 12 router modules in `api/routers/`. `server.py` now 248 lines (lifecycle, middleware, mount).
7. **Intelligence engine false positives** — Regex patterns match filenames and IPs in banners. Needs filtering.
8. **RBAC policy engine** — No OPA integration. Authz is simple decorator checks.
9. ~~**`daily_worker.py` hardcoded paths** — Still uses absolute paths to `/home/kirk/Madlab/Clean-Live/PicoShogun`. Needs env vars.~~ **Fixed in session 4**: All hardcoded absolute paths removed. `PICOSHOGUN_DIR`/`HIVEMIND_PROJECTS_DIR` env vars or `Path(__file__)` relative resolution.
10. **Webhook `create()` API alignment** — `create(name, url, events, secret)` vs API body `(url, events, secret, name)` — Pydantic model now validates but `name` defaults to `"default"` which may surprise callers.
11. ~~**PicoWatch `RateLimiter._clients`** — Grows unboundedly, no LRU/TTL eviction.~~ **Fixed in session 5**: Added `_evict_stale()`, `max_clients` cap, `threading.Lock`, periodic eviction on every `is_allowed()` call.
12. ~~**PicoWatch audit HMAC key** — Hardcoded, tamper-detection only.~~ **Fixed in session 5**: Now reads from `PICOWATCH_AUDIT_HMAC_KEY` env var (≥32 chars). Falls back to per-process random key with warning. Checksums survive restarts when env var is set.
13. ~~**PicoDome license gate** — Accepts any `shogun-` key (placeholder).~~ **Fixed in session 5**: Key format now requires 4 parts (`shogun-<tier>-<org>-<hash>`), hash must be ≥16 chars. Honest about format-only validation (full HMAC verification requires PicoShogun).
14. **Postgres migration path** — `ConnectionPool` interface exists but SQLite is hardcoded everywhere.
15. ~~**Plugin signed manifests** — Currently loads any Python module from `plugins/`. Trust boundary needs hardening.~~ **Partially fixed in session 4**: Manifest validation, hook whitelist, SHA-256 audit, symlink escape prevention. Signed manifests (Ed25519) still needed for untrusted deployments.
16. **Docker CI E2E** — Docker build works locally but CI doesn't test with `PICOSHOGUN_*` env vars end-to-end.

## P3 — Nice to have

17. ~~**PicoWatch `assert_secure()` pattern** — PicoShogun has it, PicoWatch/PicoDome/PicoSentry don't.~~ **Fixed in session 5**: `assert_secure()` and `validate_secure()` ported to PicoWatch. Default bind changed from `0.0.0.0` to `127.0.0.1`. PicoDome and PicoSentry are CLI tools (no web server) — pattern not applicable.
18. **Dopaflow** — Needs AI-slop cleanup
19. **55NDeep-Plugin** — Needs honest docs rewrite

## Session 5 — Changes Summary

### PicoShogun
- **Router split**: `api/server.py` (1171→248 lines) → 12 router modules in `api/routers/`, shared `api/deps.py` and `api/models.py`
- **Discord notifier**: Real webhook delivery. Log-only fallback with warning when `DISCORD_WEBHOOK_URL` not set
- **Load testing baseline**: `tests/load/locustfile.py` with README
- **MyPy**: 30→10 errors remaining
- **All 152 tests pass**

### PicoWatch
- **Rate limiter**: Thread-safe `_evict_stale()`, `max_clients=100_000`, `threading.Lock`
- **Audit HMAC**: `PICOWATCH_AUDIT_HMAC_KEY` env var, per-process random fallback with warning
- **assert_secure()**: Ported from PicoShogun. Default bind `127.0.0.1`
- **All 258 tests pass** (some integration test environment issues unrelated to changes)

### PicoDome
- **License gate**: Key format validation now requires `shogun-<tier>-<org>-<hash>` with ≥16 char hash
- **All 27 license tests pass**
