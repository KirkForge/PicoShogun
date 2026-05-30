# PicoShogun — Known Gaps

Priority-ordered list of what needs work before this can be called 1.0.

## P0 — Must fix before any real deployment

1. **No load testing** — Zero benchmarks for rate limiting, API throughput, or WebSocket connections. No idea what breaks at scale.

## P1 — Important for trust

2. **Discord notifier plugin** — Logs to Python logger, doesn't actually send Discord messages. Misleading.
3. **Org system** — Multi-tenant code exists but is untested at scale. No test asserting tenant A can't read tenant B's data.
4. **MyPy strict** — Currently `--ignore-missing-imports --no-strict-optional`. Real type safety is missing.
5. **Dashboard E2E tests** — No Playwright/Cypress. Frontend could break silently.
6. **Integration tests** — 44 unit tests for ~14k LOC. Need auth→project→alert end-to-end coverage.

## P2 — Should have for 1.0

7. **Intelligence engine false positives** — Regex patterns match filenames and IPs in banners. Needs filtering.
8. **RBAC policy engine** — No OPA integration. Authz is simple decorator checks.
9. **`daily_worker.py` hardcoded paths** — Still uses absolute paths to `/home/kirk/Madlab/Clean-Live/PicoShogun`. Needs env vars.
10. **Webhook `create()` API alignment** — `create(name, url, events, secret)` vs API body `(url, events, secret, name)` — Pydantic model now validates but `name` defaults to `"default"` which may surprise callers.

## P3 — Nice to have

11. **Postgres migration path** — `ConnectionPool` interface exists but SQLite is hardcoded everywhere.
12. **Plugin signed manifests** — Currently loads any Python module from `plugins/`. Trust boundary needs hardening.
13. **Docker CI E2E** — Docker build works locally but CI doesn't test with `PICOSHOGUN_*` env vars end-to-end.

## Completed this session

- **Rate limit persist** — Now defaults to `persist=settings.is_production()` (ON in prod).
- **CORS wildcard blocking** — Now `block_wildcard_in_production=settings.is_production()`.
- **Scheduler RCE** — Added command whitelist (`batch`, `run`, `report`, `backup`, `cleanup`) + param type validation + shell-metacharacter sanitization on `category`.
- **Webhook HMAC** — Added public `sign_payload()` method; documented `verify_signature(bytes)` vs `sign_payload(dict)` contract.
- **Username enumeration** — Auth failure logs no longer include usernames.
- **Version deduplication** — All version strings now read from `config/version.py` (`__version__ = "0.1.0"`). Zero hardcoded copies.
- **API key cleanup cron** — `cleanup_expired_keys()` now runs every 6 hours via scheduler `cleanup` command (also rotates logs, purges audit entries).
- **OTEL metrics** — Wired `PeriodicExportingMetricReader` with 60s export interval instead of TODO stub.
- **Pydantic request models** — `WebhookCreateRequest` and `SchedulerJobCreateRequest` replace raw `dict` params on POST endpoints.
- **`pico_dome/` vendored code removed** — L2/L3/L4 scan+sandbox endpoints now return 501 with install instructions. `pip install picodome` is the proper path.
- **`orchestrator/master.py`** — Already gone from prior session.
- **HealthReadiness model** — Fixed to include `checks` and `timestamp` fields (was missing, causing test failures).
