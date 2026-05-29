# Shogun Command Centre — Changelog

All notable changes to this project will be documented in this file.

## [2.15.0] - 2026-05-29

### Enterprise Hardening — Rate Limit Persistence, Graceful Shutdown, CORS, API Key Lifecycle

- **Rate limit persistence**: `RateLimitMiddleware` supports `persist=True` to store counters in a `rate_limit_counters` SQLite table. Counters are restored on startup so limits survive pod restarts. Flush occurs during eviction cycle (every 60s).
- **Graceful shutdown**: SIGTERM/SIGINT handlers in `api/server.py` `__main__` block. Stops anomaly detector, scheduler, event bus, plugins, and closes DB connections before exit.
- **CORS environment variable**: `SHOGUN_CORS_ORIGINS` env var parsed from comma-separated string (e.g., `https://app.example.com,https://admin.example.com`). Falls back to `["*"]` when unset.
- **API key expiration enforcement**: `AuthService.cleanup_expired_keys()` deactivates keys past their `expires_at` timestamp. Called at startup in lifespan context; logged with id, name, and user_id.
- **Connection pool abstraction**: `ConnectionPool` interface in `database/manager.py` with `acquire()`, `release()`, `close_all()` methods. Current SQLite `DatabaseManager` uses thread-local connections; Postgres migration path swaps in `asyncpg`/`psycopg`.
- **Test config**: Added `asyncio_mode = "strict"` and `asyncio_default_fixture_loop_scope = "function"` to `pyproject.toml` to eliminate pytest-asyncio DeprecationWarning on Python 3.12+.
- **`.env.example`**: Added `SHOGUN_CORS_ORIGINS`, `SHOGUN_DDOS_SHIELD`, `SHOGUN_AUDIT_RETENTION_DAYS`.

### Enterprise Hardening — Audit Log Management, CORS Validation, Config Validation

- **GET /audit/stats**: Audit log statistics and retention policy.
- **POST /audit/purge**: Purge audit logs (admin-only, supports `dry_run` param).
- **Per-severity audit retention**: critical=365d, high=180d, medium=90d, low=30d, default=90d.
- **Configurable retention**: `settings.database.audit_retention_days`.
- **CORS hardening middleware**: `CORSHardeningMiddleware` warns on wildcard CORS in production, optionally blocks cross-origin requests.
- **CORS wildcard validation**: `Settings.validate()` warns on wildcard CORS origin in production.
- **API key rotation**: POST /auth/api-key/{id}/rotate, DELETE /auth/api-key/{id}.

### Enterprise Hardening — Rebrand, Middleware, Deprecation Fixes

- **Complete SecdevKimi → Shogun rebrand** across 40+ files.
- **3 enterprise middleware**: HTTPS enforcement (redirect HTTP→HTTPS in prod), request timeout (30s/504), docs restriction (blocks /docs and /redoc in prod).
- **Python 3.12 datetime DeprecationWarning** fix in `database/manager.py`.
- **PicoSentry fixture fixes**: Added pnpm-lock.yaml and package-lock.json to test fixtures.

### Architecture — Route Versioning & Error Handling

- **API v1 router**: Mounted `api_v1` router with `/api/v1` prefix. Scan, sandbox, and dashboard summary routes use the versioned router.
- **Middleware order**: Fixed execution order (SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield → GZip → CORS → RateLimit → Audit).
- **Global exception handler**: Returns structured JSON for unhandled exceptions instead of HTML tracebacks.
- **Startup config validation**: Lifespan calls `settings.validate()` and logs warnings for insecure production defaults.

### Infrastructure

- **`start_api.sh`**: Project-relative `.venv/`, env-var config, liveness health check.
- **Stale files removed**: Deleted `1` and `secdev_kimi.db.bak-*`.

### Code Quality

- **Module docstring**: Updated from legacy "Secdev_kimi" to "Shogun".
- **Logger name**: `SecdevKimi.API` → `shogun.api`.
- **Test alignment**: `test_api.py` assertions match v2.15.0.

---

## [2.14.0] - 2026-05-29

### Architecture — Enterprise Lifecycle & Middleware

- **FastAPI lifespan**: Replaced deprecated `@app.on_event("startup"/"shutdown")` with proper `lifespan` context manager.
- **Security headers middleware**: HSTS, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, CSP.
- **Request ID middleware**: Generates or propagates `X-Request-ID` for distributed tracing.
- **Request size limit middleware**: Rejects bodies over 10 MB (413).
- **Structured JSON logging**: `config/logging_config.py` with `JSONFormatter`.
- **WebSocket auth**: Token-based auth on `/ws` endpoint.
- **Health probes**: `/health/live` (liveness) and `/health/ready` (readiness).
- **Database v7**: `anomaly_alerts` table.
- **Deprecation**: `orchestrator/master.py` marked deprecated.

---

## [2.13.0] - 2026-05-28

### Bug Fixes

- **Auth token parsing**: Fixed `validate_token()` — simple tokens with colons incorrectly split.
- **Orchestrator `get_status()`**: Fixed `NoneType` crash on null aggregates.
- **Migration idempotency**: Handles `ALTER TABLE ADD COLUMN` duplicate column errors.

### Features

- **Enterprise Command Centre**: SPA dashboard with Canvas charts, theme toggle, keyboard shortcuts.
- **OpenTelemetry integration**: Tracer + meter with graceful no-op fallback.
- **Anomaly detection**: Configurable rules engine with alert pipeline.
- **L2 Supply Chain Scanner**: 13 deterministic rules with API endpoints.
- **L3 Sandbox**: Execution sandbox with seccomp/seatbelt/subprocess backends.
- **L4 Behavioral Analysis**: Timing/exfil/entropy/honeypot detection.

---

## [2.9.0] - 2026-05-13

### Project Data Export (EXPORT-01)
- **GET `/projects/{id}/export`** — Full project dump (JSON/CSV)
- **Query param `?format=json|csv`** — JSON returns all project data. CSV exports runs table only.

## [2.2.0] - 2026-05-11

### Event Bus, Docker, API Expansion, WebSocket Real-Time Events

## [2.1.0] - 2026-05-11

### Plugin System, Metrics, Webhooks, Scheduler, Backup

## [2.0.0] - 2026-05-11

### Enterprise Foundation
- FastAPI REST API with 40+ endpoints
- SQLite WAL mode with migration framework
- JWT + API key auth with RBAC
- Multi-channel alerting (Discord/Slack/Email/Syslog)
- Intelligence engine with 16 patterns
- Orchestrator v2 with async execution

## [1.0.0] - Earlier

### Initial Release
- Basic project runner, console output, SQLite raw queries
