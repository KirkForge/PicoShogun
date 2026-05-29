# Shogun — Project Scope & Prompt Pack

## Project Identity
**Shogun** is a security lab orchestrator: FastAPI API + SQLite backend that runs 75 Hivemind-projects, extracts intelligence from their output, alerts on findings, and exposes it all via REST/WebSocket/CLI. Version 2.4.0.

## What's REAL (functional, deployed, battle-tested)

- **API server** (`api/server.py`, 704 lines): Full FastAPI with 40+ endpoints, JWT auth middleware, CORS, GZip, rate limiting, audit logging, WebSocket `/ws`, org management. Serves real traffic (239 audit entries in DB).
- **Database** (`database/manager.py`, 337 lines): Thread-safe SQLite with WAL mode, 4 migrations (v1→v4), 15 tables, connection pooling, backup/restore. Real data: 9 project runs, 14 intel entries, 8 alerts, 5 users.
- **Orchestrator** (`services/orchestrator.py`, 598 lines): Loads project registry, runs projects via subprocess, captures output, extracts intelligence, generates alerts, tracks run history. Has actually run projects and logged results.
- **Intelligence engine** (`services/intelligence.py`, 227 lines): 16 regex patterns, failure classification, cross-project correlation queries. Works but is **noisy** — matches filenames as domains, `0.0.0.0` as threat IPs, banner text as auth failures. `classify_failure()` is the most useful part.
- **Auth** (`services/auth.py`, 213 lines): JWT + bcrypt with PBKDF2 fallback, API key management, RBAC (viewer/operator/admin). 5 real users in DB.
- **Alert hub** (`services/alert_hub.py`, 291 lines): Discord/Slack/Email/Syslog channels with cooldown, dedup, retry. 8 real alerts logged (all via syslog from actual failures).
- **Config** (`config/settings.py`, 124 lines): Dataclass-based with env var support, JSON persistence, production validation. Clean and functional.
- **Metrics** (`services/metrics.py`, 150 lines): Prometheus-compatible counters/gauges/histograms. Exports via `/metrics/prometheus` and `/metrics/json`.
- **Webhooks** (`services/webhooks.py`, 154 lines): HMAC-signed outgoing webhooks with retry logic. Code is complete, 0 rows in DB (unused but real).
- **Scheduler** (`services/scheduler.py`, 271 lines): Cron-based job daemon with `croniter`. 0 jobs in DB (unused but real).
- **Backup** (`services/backup.py`, 185 lines): Creates real `.tar.gz` archives of DB + logs with metadata.
- **Event bus** (`services/event_bus.py`, 125 lines): Thread-safe pub/sub with priority levels and wildcard subscriptions.
- **WebSocket** (`services/websocket_manager.py`, 76 lines): Connection manager with channel subscriptions and event bus bridge.
- **Plugin system** (`services/plugin_manager.py`, 183 lines): Dynamic loading with `plugin.json` manifests, hook registration, event dispatch.
- **Middleware**: Rate limiting (per-IP) and audit logging (every request logged to DB).
- **Frontend** (`front/index.html`): Minimal status dashboard that polls `/health` and `/status`.
- **DevOps**: Dockerfile, docker-compose with Prometheus/Grafana profiles, nginx reverse proxy, systemd unit, `.env.example`, `requirements.txt`.
- **Hivemind-projects**: 75 project directories (51 Python files, 12,727 total lines). The honeypot, sniffer, forensics, etc. are real working scripts. The orchestrator runs them via subprocess.

## What's COSPLAY (aspirational, stub, or misleading)

- **IRON_DOME architecture** (`architecture/IRON_DOME.md`): Describes a 5-layer defense system. Only Layer 1 (`ddos_shield.py`) has code — and it's **not imported anywhere**. Layers 2–5 (Validation Shield, Execution Shield, Behavioral Shield, LLM Guardrails) exist only as documentation. The entire `iron_dome/` directory is an island.
- **DDoS Shield** (`iron_dome/L1_perimeter/ddos_shield.py`, 228 lines): Sophisticated adaptive rate limiter with trust scoring, graduated response, circuit breakers. Real code, but **zero integration** — no middleware imports it, no config references it, no test exercises it. Dead code.
- **Discord notifier plugin** (`plugins/test_discord_notifier/`): Named as if it sends Discord messages. Actually just logs to Python `logger`. Misleading.
- **Intelligence engine output quality**: The regex patterns produce mostly false positives. `"suspicious_domain"` matches Python filenames ending in `.com`/`.io`/`.dev`. `"threat_ip"` matches `0.0.0.0` in banner text. `"auth_failure"` matches the word "crack" in project titles. It works, but the signal-to-noise ratio is terrible.
- **Organization system** (`services/orgs.py`, 165 lines): Complete multi-tenant code with tiers, API keys, member management. DB tables exist but are **empty** — zero orgs, zero members, zero API keys.
- **Master CLI** (`orchestrator/master.py`, 646 lines): v1 orchestrator that duplicates DB init and project loading. Superseded by `services/orchestrator.py` but still importable. Legacy cruft.
- **Orgs/Webhooks/Scheduler DB tables**: Created by migrations but contain 0 rows. The code works; nobody's used them yet.

## Scope to Finished Product

### Must-Have (Production-Ready Security Lab)
1. **Fix intelligence signal quality**: Add context-aware filtering — exclude matches inside quoted strings, file paths, and known-safe patterns (`0.0.0.0`, `127.0.0.1`, `localhost`). Add a `min_confidence` threshold parameter. Deduplicate across runs. This is the #1 value gap.
2. **Integrate DDoS shield**: Wire `AdaptiveRateLimiter` into `api/server.py` as middleware (replacing or augmenting the simple `RateLimitMiddleware`). Add config toggle in `settings.py`.
3. **Real Discord alerts**: Replace the test notifier plugin with an actual Discord webhook sender using `requests.post`. Use the webhook URL already configured in `settings.py:AlertConfig.discord_webhook`.
4. **Seed org + user data**: Create a default `admin` org on first run. Add a `setup_admin` CLI command. Make the org system actually usable.
5. **Integration tests**: Add `tests/` directory with pytest fixtures that hit the API, validate auth flow, test intelligence extraction with real project output, verify alert delivery.

### Should-Have (Hardened Enterprise)
6. **Project output validation**: Before feeding output to intelligence engine, filter known-bad patterns (tracebacks, Python module paths, `0.0.0.0`). Add `classify_failure()` results as first-class intelligence entries.
7. **WebSocket auth**: The `/ws` endpoint has zero authentication. Add token-based auth on connect.
8. **Health check depth**: `/health` only checks DB connectivity. Add orchestrator readiness, project registry load status, and alert channel connectivity checks.
9. **Rate limit per-role**: Current `RateLimitMiddleware` is per-IP flat 100/min. Make it per-role (admin=500, operator=200, viewer=100).
10. **Remove master.py v1**: Delete `orchestrator/master.py` and its duplicate DB init. All orchestration goes through `services/orchestrator.py`.

### Nice-to-Have (Growth)
11. **Grafana dashboard config**: The `docker-compose.yml` references Prometheus/Grafana profiles but `monitoring/grafana/` has no dashboard JSON. Create a Shogun dashboard with project status, alert rates, and threat scores.
12. **Webhook delivery UI**: Admin page to create/manage outgoing webhooks (currently API-only, 0 rows in DB).
13. **Scheduled project runs**: Wire `services/scheduler.py` into the API so users can schedule recurring project runs via the UI.
14. **Alert deduplication in intelligence**: When the same pattern fires across multiple runs of the same project, collapse into a single intelligence entry with a count, not N separate entries.

## Architecture Constraints
- Python 3.12, FastAPI, SQLite (WAL mode), no ORM
- All project execution via subprocess (`Hivemind-projects/` directory)
- Configuration: dataclass + env vars, no YAML/JSON config files
- Auth: JWT (PyJWT) with bcrypt, API keys in DB
- Deployment: Docker Compose or systemd + uvicorn
- Frontend: single `index.html` SPA, no build step
- Database migrations are sequential SQL strings — no Alembic
