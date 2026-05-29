# Shogun Command Centre — Changelog

All notable changes to this project will be documented in this file.

## [2.15.0] - 2026-05-29

### Architecture — Route Versioning & Error Handling

- **API v1 router**: Mounted `api_v1` router with `/api/v1` prefix. Scanner (`/scans`), sandbox (`/sandboxes`), and dashboard summary (`/dashboard/summary`) routes now use the versioned router instead of being directly on `app`. Unversioned routes (health, auth, orgs, etc.) remain on the root app.
- **Middleware order**: Fixed middleware execution order. FastAPI's `add_middleware` is LIFO — reversed the registration so execution order is now: SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield → GZip → CORS → RateLimit → Audit (outermost → innermost).
- **Global exception handler**: Added `app.exception_handler(Exception)` that returns structured JSON (`{error, detail, request_id, timestamp}`) instead of HTML tracebacks for unhandled exceptions.
- **Startup config validation**: Lifespan now calls `settings.validate()` and logs warnings for insecure production defaults (default secret key, missing SSL, debug mode in prod, wildcard allowed hosts).

### Infrastructure

- **`start_api.sh`**: Replaced hardcoded venv path with project-relative `.venv/`. Added venv existence check, configurable `SECDEV_HOST`/`SECDEV_PORT`/`SECDEV_WORKERS` env vars, and health check against `/health/live`.
- **Stale files removed**: Deleted orphaned `1` (accidental stderr dump) and `secdev_kimi.db.bak-*` backup file.

### Code Quality

- **Module docstring**: Updated `api/server.py` docstring from legacy "Secdev_kimi" to "Shogun".
- **Logger name**: Changed from `SecdevKimi.API` to `shogun.api` for structured log consistency.
- **`if __name__` block**: Moved to end of file (was before sandbox route definitions).
- **Test alignment**: Updated `test_api.py` — `app.title` and `app.version` assertions now match v2.15.0.

## [2.14.0] - 2026-05-29

### Architecture — Enterprise Lifecycle & Middleware

- **FastAPI lifespan**: Replaced deprecated `@app.on_event("startup"/"shutdown")` with proper `lifespan` context manager. Startup now wires alert_hub into anomaly_detector, starts scheduler and anomaly detector. Shutdown stops all background services, shuts down event bus, unloads plugins, and closes DB connections.
- **Security headers middleware**: Added `SecurityHeadersMiddleware` — sets HSTS, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, and Content-Security-Policy on every response.
- **Request ID middleware**: Added `RequestIDMiddleware` — generates or propagates `X-Request-ID` header for distributed tracing and correlation.
- **Request size limit middleware**: Added `RequestSizeLimitMiddleware` — rejects request bodies over 10 MB (configurable), returning 413.
- **Structured JSON logging**: Added `config/logging_config.py` with `JSONFormatter` that emits single-line JSON log entries with timestamp, level, logger, message, and optional fields (request_id, component, etc.). Configurable via `settings.logging.structured`.

### Health Probes

- **GET `/health/live`**: Liveness probe — returns 200 if process is alive and responding.
- **GET `/health/ready`**: Readiness probe — returns 200 only if DB is connected; returns 503 otherwise.

### WebSocket Authentication

- **WS `/ws`**: WebSocket endpoint now supports optional token-based authentication:
  - Query param: `ws://host/ws?token=<jwt>`
  - Auth message: `{"action": "auth", "token": "<jwt>"}` after connecting
  - Invalid tokens close the connection with code 4001.
  - Unauthenticated connections can receive broadcast events but cannot subscribe to specific channels.

### Database

- **Migration v7**: Added `anomaly_alerts` table with `rule_id`, `metric_name`, `value`, `threshold`, `comparison`, `severity`, `description`, and `created_at` columns plus indexes on `(rule_id, created_at)` and `(severity, created_at)`.

### Configuration

- **`pyproject.toml`**: Replaced the scanner-only `pyproject.toml` with a proper Shogun platform configuration including all dependencies, optional dev/observability extras, ruff, mypy, and pytest settings.
- **`.gitignore`**: Expanded with database artifacts, backup files, PicoSentry node_modules, and additional security exclusions.

### Deprecations

- **`orchestrator/master.py`**: Marked as deprecated with `DeprecationWarning`. All orchestration should go through `api/server.py` and `services/orchestrator.py`. Will be removed in v3.0.

---

## [2.13.0] - 2026-05-28

### Bug Fixes

- **Auth token parsing**: Fixed `validate_token()` — simple tokens with colons (timestamps) were incorrectly split, causing 401s
- **Orchestrator `get_status()`**: Fixed `NoneType` crash when `completed` or `failed` counts are null in SQLite aggregates
- **Migration idempotency**: Migration runner now handles `ALTER TABLE ADD COLUMN` duplicate column errors gracefully

### Features

- **Enterprise Command Centre**: Full SPA dashboard with Canvas charts, theme toggle, keyboard shortcuts
- **OpenTelemetry integration**: Tracer + meter with graceful no-op fallback
- **Anomaly detection**: Configurable rules engine with alert pipeline
- **L2 Supply Chain Scanner**: 13 deterministic rules with API endpoints
- **L3 Sandbox**: Execution sandbox with seccomp/seatbelt/subprocess backends
- **L4 Behavioral Analysis**: Timing/exfil/entropy/honeypot detection

---

## [2.9.0] - 2026-05-13

### Project Data Export (EXPORT-01)
- **GET `/projects/{id}/export`** — Full project dump (JSON/CSV)
- **Query param `?format=json|csv`** — JSON returns all project data. CSV exports runs table only.
- **Org gate**: Verifies project belongs to caller's organization before export

## [2.2.0] - 2026-05-11

### Event Bus (Pub/Sub)
- **EventBus**: Centralized publish/subscribe system with priority levels and wildcard subscriptions

### Docker Support
- **Dockerfile**: Production-ready Python 3.12 slim image
- **docker-compose.yml**: Full stack with monitoring and tracing profiles

### API Expansion
- Plugins, Webhooks, Scheduler, Backup, Logs, Metrics, Events endpoints

### WebSocket Real-Time Events
- `/ws` endpoint for live event streaming with channel subscriptions

## [2.1.0] - 2026-05-11

### Plugin System, Metrics, Webhooks, Scheduler, Backup

## [2.0.0] - 2026-05-11

### Enterprise Foundation
- Complete architecture overhaul from v1.0
- FastAPI REST API with 40+ endpoints
- SQLite WAL mode with migration framework
- JWT + API key auth with RBAC
- Multi-channel alerting (Discord/Slack/Email/Syslog)
- Intelligence engine with 16 patterns
- Orchestrator v2 with async execution

## [1.0.0] - Earlier

### Initial Release
- Basic project runner, console output, SQLite raw queries
