# Shogun Backlog

## Completed ✅

| ID | Priority | Description | Date |
|----|----------|-------------|------|
| INTEL-03 | P1 | Fix intelligence signal quality — false positive filtering | 2026-05-13 |
| SHIELD-01 | P1 | Integrate DDoS shield as middleware | 2026-05-13 |
| AUDIT-01 | P2 | API audit logging — who did what when | 2026-05-13 |
| EMAIL-01 | P2 | Email alert notifications via SMTP | 2026-05-13 |
| SCHED-01 | P2 | Scheduled jobs UI — CRUD for cron-like tasks | 2026-05-13 |
| RATE-01 | P3 | Rate limiting per org + per IP | 2026-05-13 |
| EXPORT-01 | P3 | Project data export (JSON/CSV) | 2026-05-13 |
| HEALTH-01 | P1 | Health check endpoint with dependency readiness | 2026-05-29 |
| ANOM-01 | P1 | Metrics anomaly detector — auto-detect thresholds | 2026-05-29 |
| ANOM-02 | P2 | Anomaly alert pipeline | 2026-05-29 |
| HEALTH-02 | P2 | Self-monitoring dashboard data | 2026-05-29 |
| DB-02 | P2 | Swap SQLite to SQLite + WAL mode | 2026-05-13 |
| AUTH-01 | P1 | Real user registration endpoint | 2026-05-13 |
| AUTH-02 | P2 | Role-based access control decorator | 2026-05-13 |
| WS-01 | P2 | Real-time event pipeline with auth | 2026-05-29 |
| LIFECYCLE | P1 | FastAPI lifespan context manager | 2026-05-29 |
| SECHEADERS | P1 | Security headers middleware (HSTS, CSP, etc.) | 2026-05-29 |
| REQID | P2 | Request ID middleware for distributed tracing | 2026-05-29 |
| REQSIZELIMIT | P2 | Request size limit middleware (10 MB) | 2026-05-29 |
| STRUCTLOG | P2 | Structured JSON logging | 2026-05-29 |
| RATEPERSIST | P2 | Rate limit persistence (SQLite-backed) | 2026-05-29 |
| CORSHARD | P2 | CORS hardening middleware + SHOGUN_CORS_ORIGINS env var | 2026-05-29 |
| SHUTDOWN | P1 | Graceful SIGTERM/SIGINT shutdown handlers | 2026-05-29 |
| KEYEXPIRY | P2 | API key expiration enforcement at startup | 2026-05-29 |
| CONNPOOL | P3 | ConnectionPool abstraction for Postgres migration | 2026-05-29 |
| AUDITRET | P2 | Per-severity audit log retention + purge API | 2026-05-29 |
| AUDITSTATS | P2 | Audit statistics endpoint (GET /audit/stats) | 2026-05-29 |
| DOCSREST | P2 | Docs restriction middleware (block /docs in prod) | 2026-05-29 |
| HTTPSENFORCE | P2 | HTTPS enforcement middleware (redirect in prod) | 2026-05-29 |
| REQTIMEOUT | P2 | Request timeout middleware (30s, 504) | 2026-05-29 |
| DEPWARNING | P3 | Fix Python 3.12 DeprecationWarning in sqlite3 | 2026-05-29 |
| PYTESTASYNC | P3 | Fix pytest-asyncio deprecation warnings | 2026-05-29 |
| KEYROTATE | P2 | API key rotation endpoint | 2026-05-29 |
| CONFIGVALID | P1 | Startup config validation for insecure production defaults | 2026-05-29 |

## Active Sprint (v2.16 — Next)

| ID | Priority | Status | Description | Acceptance Criteria |
|----|----------|--------|-------------|---------------------|
| POLICY-01 | P3 | TODO | Basic security policy engine | Config: policies/; regex rules for API keys, passwords, tokens |
| RATEPERSIST-FLIP | P2 | TODO | Enable rate limit persistence by default | `persist=True` in production, `persist=False` in development |
| CORSBLOCK-FLIP | P2 | TODO | Enforce CORS wildcard blocking in production | `block_wildcard_in_production=True` when `SHOGUN_CORS_ORIGINS` is set |
| LOADTEST | P3 | TODO | Load testing with k6 or Locust | Baseline benchmarks for rate limiting, API throughput, WebSocket connections |
| MYPYSTRICT | P3 | TODO | MyPy strict type checking | Remove `--ignore-missing-imports --no-strict-optional`, add type stubs |
| E2E-TESTS | P3 | TODO | Dashboard E2E tests | Playwright or Cypress tests for Command Centre SPA |
| SCHEDCLEANUP | P3 | TODO | Schedule API key cleanup as periodic job | Add `cleanup_expired_keys` to scheduler as cron job |
| DOCKERCI | P2 | TODO | Docker CI end-to-end with env vars | Verify Docker build works with SHOGUN_* env vars |

## Discovered Bugs

| ID | Priority | Status | Description | Date |
|----|----------|--------|-------------|------|
| BUG-006 | P1 | FIXED | Backup crash on missing backup_retention_days | 2026-05-12 |
