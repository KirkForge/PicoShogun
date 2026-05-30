# PicoShogun — Changelog

All notable changes to this project will be documented in this file.

## [2.16.0] - 2026-05-30

### Rename: Shogun → PicoShogun

- **Product name**: Shogun is now PicoShogun — command centre for the Pico Security Series
- **CLI**: `picoshogun` primary entrypoint, `shogun` backward compat alias
- **Env vars**: `PICOSHOGUN_*` primary, `SHOGUN_*` backward compat
- **Docker**: image name `picoshogun`, containers `picoshogun-*`
- **Logger names**: `shogun.*` → `picoshogun.*`
- **Canary domains**: `canary.shogun.local` → `canary.picoshogun.local`
- **Docs**: Honest pre-1.0 beta status, no inflated enterprise claims
- **Authors**: Removed `55N10E` co-author. Sole author: Henrik Kirk.
- **Architecture**: Iron Dome → PicoDome references in docs
- **Pico Security Series table** added to README

### Documentation Cleanup

- **README.md**: Rewritten with honest product description, Pico Security Series branding
- **STATE.md**: Honest ✅/🔶/❌ assessment, "pre-1.0 beta" maturity
- **AGENTS.md**: "What PicoShogun IS/NOT", no AI co-authors, anti-slop writing rules
- **GAPS.md**: Priority-ordered gap list replaces deleted enterprise docs
- **docs/STATUS.md**: CI billing exhausted, recent changes, known issues
- **PROMPT_PACK.md**: Updated for PicoShogun identity
- **Deleted**: `summary.md` (98/100 enterprise score — replaced by STATE.md + GAPS.md)

## [2.15.0] - 2026-05-29

### Enterprise Hardening — Rate Limit Persistence, Graceful Shutdown, CORS, API Key Lifecycle

- **Rate limit persistence**: `RateLimitMiddleware` supports `persist=True` to store counters in SQLite. Counters restored on startup.
- **Graceful shutdown**: SIGTERM/SIGINT handlers. Stops anomaly detector, scheduler, event bus, plugins, and closes DB connections.
- **CORS environment variable**: `SHOGUN_CORS_ORIGINS` (now `PICOSHOGUN_CORS_ORIGINS`) env var for explicit CORS origins.
- **API key expiration enforcement**: `AuthService.cleanup_expired_keys()` deactivates keys past their `expires_at` timestamp.
- **Connection pool abstraction**: `ConnectionPool` interface for Postgres migration path.
- **Audit log management**: Per-severity retention, purge API with dry_run support.

### Enterprise Hardening — Audit, CORS Validation, Config Validation

- **GET /audit/stats**: Audit log statistics and retention policy.
- **POST /audit/purge**: Purge audit logs (admin-only, supports `dry_run`).
- **CORS hardening middleware**: Warns on wildcard CORS in production.
- **API key rotation**: POST /auth/api-key/{id}/rotate, DELETE /auth/api-key/{id}.

### Enterprise Hardening — Rebrand, Middleware, Deprecation Fixes

- **SecdevKimi → Shogun rebrand** across 40+ files (now PicoShogun).
- **3 enterprise middleware**: HTTPS enforcement, request timeout, docs restriction.
- **Python 3.12 DeprecationWarning** fix in `database/manager.py`.
- **PicoSentry fixture fixes**: pnpm-lock.yaml and package-lock.json added.

### Architecture — Route Versioning & Error Handling

- **API v1 router**: Mounted `api_v1` router with `/api/v1` prefix.
- **Middleware order**: Fixed execution order.
- **Global exception handler**: Structured JSON for unhandled exceptions.
- **Startup config validation**: Warns on insecure production defaults.

## [2.14.0] - 2026-05-29

### Architecture — Enterprise Lifecycle & Middleware

- **FastAPI lifespan**: Replaced deprecated `@app.on_event` with proper `lifespan` context manager.
- **Security headers middleware**: HSTS, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, CSP.
- **Request ID middleware**: X-Request-ID propagation.
- **Request size limit middleware**: 10 MB body limit (413).
- **Structured JSON logging**: `config/logging_config.py` with `JSONFormatter`.
- **WebSocket auth**: Token-based auth on `/ws`.
- **Health probes**: `/health/live` and `/health/ready`.
- **Database v7**: `anomaly_alerts` table.
- **Deprecation**: `orchestrator/master.py` marked deprecated.

## [2.13.0] - 2026-05-28

### Bug Fixes

- **Auth token parsing**: Fixed `validate_token()` — simple tokens with colons incorrectly split.
- **Orchestrator `get_status()`**: Fixed `NoneType` crash on null aggregates.
- **Migration idempotency**: Handles `ALTER TABLE ADD COLUMN` duplicate column errors.

### Features

- **Command Centre SPA**: Canvas charts, theme toggle, keyboard shortcuts.
- **OpenTelemetry integration**: Tracer + meter with graceful no-op fallback.
- **Anomaly detection**: Configurable rules engine with alert pipeline.
- **L2 Supply Chain Scanner**: 13 deterministic rules with API endpoints.
- **L3 Sandbox**: Execution sandbox with seccomp/seatbelt/subprocess backends.
- **L4 Behavioral Analysis**: Timing/exfil/entropy/honeypot detection.

## [2.9.0] - 2026-05-13

- **GET `/projects/{id}/export`** — Full project dump (JSON/CSV)

## [2.2.0] - 2026-05-11

- Event Bus, Docker, API Expansion, WebSocket Real-Time Events

## [2.1.0] - 2026-05-11

- Plugin System, Metrics, Webhooks, Scheduler, Backup

## [2.0.0] - 2026-05-11

- FastAPI REST API, SQLite WAL, JWT auth, Multi-channel alerting, Intelligence engine, Orchestrator v2

## [1.0.0] - Earlier

- Initial Release
