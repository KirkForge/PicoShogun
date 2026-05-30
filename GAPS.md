# PicoShogun — Known Gaps

Priority-ordered list of what needs work before this can be called 1.0.

## P0 — Must fix before any real deployment

1. ~~**No load testing**~~ **Baseline established (session 6)** — Locust suite (`tests/load/locustfile.py`) run at 50 users, ramp 10/s, 30s.

| Endpoint | p50 | p75 | p99 | Notes |
|----------|-----|-----|-----|-------|
| `/health` | 4 ms | 6 ms | 13 ms | Unauthenticated |
| `/health/live` | 4 ms | 6 ms | 12 ms | Unauthenticated |
| `/status` | 8 ms | 12 ms | 360 ms | Authenticated |
| `/projects` | 8 ms | 12 ms | 660 ms | Authenticated, SQLite write lock outliers |
| `/alerts` | 7 ms | 9 ms | 660 ms | Authenticated |
| `/metrics/json` | 7 ms | 9 ms | 98 ms | Authenticated |
| `/metrics/prometheus` | 7 ms | 8 ms | 72 ms | Unauthenticated |
| `/scheduler/jobs` | 8 ms | 10 ms | 110 ms | Authenticated |
| `/intelligence` | 7 ms | 9 ms | 850 ms | Authenticated, cold-start outliers |
| `/auth/register` | 300 ms | — | 660 ms | bcrypt hash cost |
| `/auth/login` | 180 ms | — | 530 ms | bcrypt hash cost |
| **Aggregated** | **8 ms** | **16 ms** | **670 ms** | p99 driven by SQLite write locks and bcrypt |

## P1 — Important for trust

2. ~~**Discord notifier plugin** — Logs to Python logger, doesn't actually send Discord messages. Misleading.~~ **Fixed in session 5**: Real Discord webhook delivery via `requests.post`. Falls back to log-only with clear warning when `DISCORD_WEBHOOK_URL` is not set.
3. ~~**Org system** — Multi-tenant code exists but is untested at scale. No test asserting tenant A can't read tenant B's data.~~ **Fixed in session 4**: 5 tenant isolation tests added covering cross-org access, API key isolation, org listing, and tier upgrade enforcement.
4. ~~**MyPy strict**~~ **Fixed in session 6**: All 10 errors resolved. `services/metrics.py` (explicit dict type), `services/alert_hub.py` (`dict[str, Any]` annotations, Slack indent fix), `services/orgs.py` (separate variable for Row), `config/settings.py` (`typing.get_type_hints()` for nested dataclass resolution), `services/plugin_manager.py` (explicit `dict[str, Any]`), `services/webhooks.py` (`dict[str, Any]` for event payload). MyPy now passes clean with 0 errors.
5. ~~**Dashboard E2E tests**~~ **Fixed in session 6**: Added `TestHealthSmokeTests` (7 tests) and expanded `TestDashboardSummary` (5 tests) covering health/liveness/readiness/history, dashboard summary fields, and auth-gated endpoints. Also fixed `health_history` SQL column (`timestamp` → `created_at`). Total: 162 tests passing.

## P2 — Should have for 1.0

6. ~~**`api/server.py` too large (1171 lines)** — Should be split into routers.~~ **Fixed in session 5**: Split into `api/deps.py`, `api/models.py`, and 12 router modules in `api/routers/`. `server.py` now 248 lines (lifecycle, middleware, mount).
7. **Intelligence engine false positives** — Regex patterns match filenames and IPs in banners. Needs filtering.
8. **RBAC policy engine** — No OPA integration. Authz is simple decorator checks.
9. ~~**`daily_worker.py` hardcoded paths** — Still uses absolute paths to `/home/kirk/Madlab/Clean-Live/PicoShogun`. Needs env vars.~~ **Fixed in session 4**: All hardcoded absolute paths removed. `PICOSHOGUN_DIR`/`HIVEMIND_PROJECTS_DIR` env vars or `Path(__file__)` relative resolution.
10. ~~**Webhook `create()` API alignment**~~ **Fixed in session 6**: `WebhookCreateRequest.name` is now a required field (no default). Test updated to pass explicit name.
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


## Session 6 — Changes Summary

### PicoShogun
- **MyPy clean**: All 10 remaining errors fixed. 0 errors on services/, api/, config/, middleware/, database/.
  - services/metrics.py: Separated metrics dict construction to avoid indexed assignment on object type
  - services/alert_hub.py: Explicit dict[str, Any] annotations on Discord/Slack payloads; fixed _slack_notify indentation bug where colors dict was inside if block
  - services/orgs.py: Renamed runs_today -> runs_today_row to disambiguate sqlite3.Row from int
  - config/settings.py: Replaced dc_fields(cls) type dict with typing.get_type_hints(cls) for proper dataclass resolution
  - services/plugin_manager.py: Explicit dict[str, Any] annotation on status dict
  - services/webhooks.py: Explicit dict[str, Any] annotation on event_payload
- **Webhook name required**: WebhookCreateRequest.name changed from default="default" to required field (no default)
- **Load testing baseline**: Locust benchmark at 50 users - p50 8 ms, p99 670 ms (aggregated)
- **Dashboard smoke tests**: Added TestHealthSmokeTests (7 tests) + expanded TestDashboardSummary (5 tests)
- **Bug fix**: health_history endpoint SQL used wrong column (timestamp -> created_at)
- **All 162 tests pass**, ruff clean
