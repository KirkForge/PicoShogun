# Shogun — Project Scope & Prompt Pack

## Project Identity
**Shogun** is an enterprise security orchestration and intelligence platform: FastAPI API + SQLite backend that runs 75+ security projects, extracts intelligence from their output, alerts on findings, and exposes it all via REST/WebSocket/CLI. Version 2.15.0.

## What's REAL (functional, deployed, battle-tested)

- **API server** (`api/server.py`, 1100+ lines): FastAPI with 55+ endpoints, 12-layer middleware stack, JWT auth, CORS (with SHOGUN_CORS_ORIGINS env var), GZip, rate limiting (per-IP + per-org with SQLite persistence), audit logging, WebSocket `/ws` with auth, org management, API key rotation/expiration enforcement. Serves real traffic.
- **Database** (`database/manager.py`, 410+ lines): Thread-safe SQLite with WAL mode, 7 migrations, 15+ tables, `ConnectionPool` abstraction for Postgres migration path, backup/restore. Real data: project runs, intel entries, alerts, users.
- **Orchestrator** (`services/orchestrator.py`): Loads project registry, runs projects via subprocess, captures output, extracts intelligence, generates alerts, tracks run history.
- **Intelligence engine** (`services/intelligence.py`): 16 regex patterns, failure classification, cross-project correlation queries.
- **Auth** (`services/auth.py`): JWT + bcrypt with PBKDF2 fallback, API key management with rotation + expiration enforcement, RBAC (viewer/operator/admin).
- **Alert hub** (`services/alert_hub.py`): Discord/Slack/Email/Syslog channels with cooldown, dedup, retry.
- **Config** (`config/settings.py`): Dataclass-based with `SHOGUN_*` env var support, JSON persistence, production validation (warns on insecure defaults, wildcard CORS, missing SSL).
- **Middleware** (12 layers): SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield → GZip → CORS → CORSHardening → RateLimit → Audit → Timeout → HTTPS → DocsRestriction.
- **Rate limiting** (`middleware/rate_limit.py`): Per-IP (100/min) + per-org (1000/min) with optional SQLite persistence (`persist=True`). Eviction + flush every 60s.
- **CORS** (`middleware/cors_hardening.py`): `SHOGUN_CORS_ORIGINS` env var for explicit origins. `CORSHardeningMiddleware` warns on wildcard in production, optionally blocks.
- **Graceful shutdown**: SIGTERM/SIGINT handlers stop anomaly detector, scheduler, event bus, plugins, and close DB connections.
- **Audit log management**: Per-severity retention (critical=365d, high=180d, medium=90d, low=30d), purge API with dry_run support.
- **Metrics** (`services/metrics.py`): Prometheus-compatible counters/gauges/histograms.
- **Webhooks** (`services/webhooks.py`): HMAC-signed outgoing webhooks with retry.
- **Scheduler** (`services/scheduler.py`): Cron-based job daemon with `croniter`.
- **Backup** (`services/backup.py`): Creates `.tar.gz` archives of DB + logs with metadata.
- **Event bus** (`services/event_bus.py`): Thread-safe pub/sub with priority levels and wildcard subscriptions.
- **WebSocket** (`services/websocket_manager.py`): Connection manager with channel subscriptions and event bus bridge.
- **Plugin system** (`services/plugin_manager.py`): Dynamic loading with `plugin.json` manifests.
- **OpenTelemetry** (`services/observability.py`): Tracing + meter with graceful no-op fallback.
- **Frontend** (`front/index.html`): Enterprise Command Centre SPA with Canvas charts, theme toggle, keyboard shortcuts.
- **DevOps**: Dockerfile (multi-stage, non-root), docker-compose with Prometheus/Grafana/OTel profiles, GitHub Actions CI (lint → test → security → Docker).

## What's COSPLAY (aspirational, stub, or misleading)

- **Organization system** (`services/orgs.py`): Complete multi-tenant code with tiers, API keys, member management. DB tables exist but contain minimal data — the code works but is not heavily used.
- **Discord notifier plugin** (`plugins/test_discord_notifier/`): Named as if it sends Discord messages. Actually just logs to Python `logger`. Misleading.
- **Intelligence engine output quality**: The regex patterns produce some false positives. `"suspicious_domain"` matches filenames, `"threat_ip"` matches `0.0.0.0` in banner text. The `classify_failure()` function is the most useful part.
- **Master CLI** (`orchestrator/master.py`): v1 orchestrator, marked as deprecated. Superseded by `services/orchestrator.py`.

## Architecture Constraints
- Python 3.12, FastAPI, SQLite (WAL mode), no ORM
- All project execution via subprocess (`Hivemind-projects/` directory)
- Configuration: dataclass + `SHOGUN_*` env vars, no YAML/JSON config files
- Auth: JWT (PyJWT) with bcrypt, API keys in DB with rotation + expiration
- Deployment: Docker Compose or systemd + uvicorn
- Frontend: single `index.html` SPA, no build step
- Database migrations: sequential SQL strings — no Alembic

## Remaining Gaps (for next session)
1. Enable `persist=True` for rate limit in production (currently opt-in)
2. Enable `block_wildcard_in_production=True` for CORS hardening
3. Schedule `cleanup_expired_keys()` as periodic cron job
4. Load testing / benchmarks (k6 or Locust)
5. MyPy strict type checking (currently `--ignore-missing-imports --no-strict-optional`)
6. Dashboard E2E tests (Playwright/Cypress)
7. Docker CI end-to-end with `SHOGUN_*` env vars
