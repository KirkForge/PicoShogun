# PicoShogun — Project Scope & Prompt Pack

## Project Identity
**PicoShogun** is the command centre and firewall for the Pico Security Series: a FastAPI API + SQLite backend that runs 75+ security projects, extracts intelligence from their output, alerts on findings, and exposes it all via REST/WebSocket/CLI. Version 2.16.0.

Pre-1.0 beta. Real development started late May 2026.

## What's REAL (functional, tested)

- **API server** (`api/server.py`, 1100+ lines): FastAPI with 55+ endpoints, 12-layer middleware stack, JWT auth, CORS, GZip, rate limiting, audit logging, WebSocket `/ws` with auth, org management, API key rotation/expiration.
- **Database** (`database/manager.py`, 410+ lines): Thread-safe SQLite with WAL mode, 7 migrations, 15+ tables, `ConnectionPool` abstraction, backup/restore.
- **Orchestrator** (`services/orchestrator.py`): Loads project registry, runs projects via subprocess, captures output, extracts intelligence, generates alerts.
- **Intelligence engine** (`services/intelligence.py`): 16 regex patterns, failure classification, cross-project correlation queries. Some false positives.
- **Auth** (`services/auth.py`): JWT + bcrypt with PBKDF2 fallback, API key management with rotation + expiration, RBAC (viewer/operator/admin).
- **Alert hub** (`services/alert_hub.py`): Discord/Slack/Email/Syslog channels with cooldown, dedup, retry. Note: Discord plugin logs but doesn't actually send messages.
- **Config** (`config/settings.py`): Dataclass-based with `PICOSHOGUN_*` env var support (backward compat: `SHOGUN_*`), JSON persistence, production validation.
- **Middleware** (12 layers): SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield → GZip → CORS → CORSHardening → RateLimit → Audit → Timeout → HTTPS → DocsRestriction.
- **Rate limiting**: Per-IP (100/min) + per-org (1000/min) with SQLite persistence (opt-in — `persist=True` should be default but isn't yet).
- **Graceful shutdown**: SIGTERM/SIGINT handlers.
- **Audit log management**: Per-severity retention, purge API with dry_run.
- **Metrics** (`services/metrics.py`): Prometheus-compatible.
- **Webhooks** (`services/webhooks.py`): HMAC-signed with retry.
- **Scheduler**, **Backup**, **Event bus**, **WebSocket manager**: All functional.
- **Plugin system**: Dynamic loading. Trust boundary — plugins run in-process.
- **OpenTelemetry**: Tracing + meter with graceful no-op fallback.
- **Frontend** (`front/index.html`): Command Centre SPA with Canvas charts, theme toggle, keyboard shortcuts. No E2E tests.
- **DevOps**: Dockerfile (multi-stage, non-root), docker-compose, GitHub Actions CI.

## What's COSPLAY (aspirational, stub, or misleading)

- **Organization system** (`services/orgs.py`): Complete multi-tenant code with tiers, API keys, member management. DB tables exist but contain minimal data. Not tested at scale.
- **Discord notifier plugin** (`plugins/test_discord_notifier/`): Logs to Python `logger`. Doesn't actually send to Discord.
- **Intelligence engine output quality**: Regex patterns produce false positives. `"suspicious_domain"` matches filenames, `"threat_ip"` matches `0.0.0.0` in banner text. `classify_failure()` is the most useful part.
- **Master CLI** (`orchestrator/master.py`): v1 orchestrator, deprecated. Should be removed.

## Architecture Constraints
- Python 3.12, FastAPI, SQLite (WAL mode), no ORM
- All project execution via subprocess
- Configuration: dataclass + `PICOSHOGUN_*` / `SHOGUN_*` env vars
- Auth: JWT (PyJWT) with bcrypt, API keys in DB with rotation + expiration
- Deployment: Docker Compose or systemd + uvicorn
- Frontend: single `index.html` SPA, no build step
- Database migrations: sequential SQL strings — no Alembic

## Remaining Gaps (for next session)
1. Enable `persist=True` for rate limit in production (currently opt-in)
2. Enable `block_wildcard_in_production=True` for CORS hardening
3. Schedule `cleanup_expired_keys()` as periodic cron job
4. Load testing / benchmarks (k6 or Locust)
5. MyPy strict type checking
6. Dashboard E2E tests (Playwright/Cypress)
7. Docker CI end-to-end with `PICOSHOGUN_*` env vars
