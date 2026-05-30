# PicoShogun — Known Gaps

Priority-ordered list of what needs work before this can be called 1.0.

## P0 — Must fix before any real deployment

1. **Rate limit persist default is OFF** — `persist=True` should be the default in production. Currently opt-in.
2. **CORS wildcard blocking not enforced** — `block_wildcard_in_production=True` is not yet enabled. Without this, production CORS is wide open.
3. **No load testing** — Zero benchmarks for rate limiting, API throughput, or WebSocket connections. No idea what breaks at scale.

## P1 — Important for trust

4. **Discord notifier plugin** — Logs to Python logger, doesn't actually send Discord messages. Misleading.
5. **Org system** — Multi-tenant code exists but is untested at scale. No test asserting tenant A can't read tenant B's data.
6. **MyPy strict** — Currently `--ignore-missing-imports --no-strict-optional`. Real type safety is missing.
7. **Dashboard E2E tests** — No Playwright/Cypress. Frontend could break silently.

## P2 — Should have for 1.0

8. **API key cleanup as cron job** — `cleanup_expired_keys()` is called at startup but not scheduled periodically.
9. **Intelligence engine false positives** — Regex patterns match filenames and IPs in banners. Needs filtering.
10. **Master CLI deprecated** — `orchestrator/master.py` should be removed, not just marked deprecated.
11. **RBAC policy engine** — No OPA integration. Authz is simple decorator checks.

## P3 — Nice to have

12. **Postgres migration path** — `ConnectionPool` interface exists but SQLite is hardcoded everywhere.
13. **Plugin signed manifests** — Currently loads any Python module from `plugins/`. Trust boundary needs hardening.
14. **Docker CI E2E** — Docker build works locally but CI doesn't test with `PICOSHOGUN_*` env vars end-to-end.
