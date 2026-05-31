# PicoShogun — Project Scope & Prompt Pack

## Project Identity
**PicoShogun** is the command centre and firewall for the Pico Security Series: a FastAPI API + SQLite backend that orchestrates PicoSentry, PicoDome, and PicoWatch, extracts intelligence from their output, alerts on findings, and exposes it all via REST/WebSocket. Version 0.1.0.

Pre-1.0 beta. Real development started late May 2026.

## What's REAL (functional, tested)

- **API server** (248 lines + 12 router modules): FastAPI with 55+ endpoints, 12-layer middleware stack, JWT auth, CORS, GZip, rate limiting, audit logging, WebSocket `/ws` with auth, org management, API key rotation/expiration.
- **Database** (`database/manager.py`): Thread-safe SQLite with WAL mode, 7 migrations, 15+ tables, `ConnectionPool` abstraction (SQLite/Postgres), backup/restore.
- **Orchestrator** (`services/orchestrator.py`): Loads project registry, runs Pico series tools via subprocess, captures output, extracts intelligence, generates alerts.
- **Intelligence engine** (`services/intelligence.py`): 16 regex patterns with FP filtering (private IP exclusion, banner context, filename keywords), failure classification, cross-project correlation queries.
- **Auth** (`services/auth.py`): JWT + bcrypt with PBKDF2 fallback, API key management with rotation + expiration, RBAC (18 permissions, 3 roles).
- **Alert hub** (`services/alert_hub.py`): Discord webhook delivery, Slack/Email/Syslog channels with cooldown, dedup, retry. Falls back to log-only with warning when webhook URL not configured.
- **Config** (`config/settings.py`): Dataclass-based with `PICOSHOGUN_*` env var support (backward compat: `SHOGUN_*`), JSON persistence, production validation.
- **Middleware** (12 layers): SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield → GZip → CORS → CORSHardening → RateLimit → Audit → Timeout → HTTPS → DocsRestriction.
- **Rate limiting**: Per-IP (100/min) + per-org (1000/min) with SQLite persistence (opt-in).
- **Graceful shutdown**: SIGTERM/SIGINT handlers.
- **Audit log management**: Per-severity retention, purge API with dry_run.
- **Metrics** (`services/metrics.py`): Prometheus-compatible.
- **Webhooks** (`services/webhooks.py`): HMAC-signed with retry.
- **Scheduler**, **Backup**, **Event bus**, **WebSocket manager**: All functional.
- **Plugin system**: Dynamic loading with Ed25519 signed manifest verification.
- **OpenTelemetry**: Tracing + meter with graceful no-op fallback.
- **Frontend** (`front/index.html`): Command Centre SPA with Canvas charts, theme toggle, keyboard shortcuts.
- **DevOps**: Dockerfile (multi-stage, non-root), docker-compose, GitHub Actions CI.
- **Load testing baseline**: p50 8ms, p99 670ms (Locust, 50 users).

## What's COSPLAY (honest limitations)

- 🔶 **Organization system** (`services/orgs.py`): Complete multi-tenant code with tiers, API keys, member management. Not tested at scale.
- 🔶 **Discord notifier**: Real webhook delivery when configured. Log-only fallback when not.
- 🔶 **Intelligence engine output quality**: Regex patterns with FP filtering. `classify_failure()` is the most useful part.
- 🔶 **Load testing**: Baseline only, no sustained load testing.
- 🔶 **Rate limit persist**: `persist=True` is off by default.
- 🔶 **CORS wildcard blocking**: `block_wildcard_in_production=True` not yet enforced.
- 🔶 **PicoDome license gate**: Format-only validation. Full HMAC requires PicoShogun.

## Architecture Constraints
- Python 3.12, FastAPI, SQLite (WAL mode), no ORM
- All Pico series tool execution via subprocess
- Configuration: dataclass + `PICOSHOGUN_*` / `SHOGUN_*` env vars
- Auth: JWT (PyJWT) with bcrypt, API keys in DB with rotation + expiration
- Deployment: Docker Compose or systemd + uvicorn
- Frontend: single `index.html` SPA, no build step
- Database migrations: sequential SQL strings — no Alembic