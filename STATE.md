# PicoShogun — Project State

**Version:** 2.16.0 | **Last Updated:** 2026-05-30 | **Git:** `master`

---

## Pico Security Series

| Product | Purpose | Maturity |
|---------|---------|----------|
| PicoSentry | Supply chain scanner | 🔶 Beta |
| PicoDome | LLM injection protection | 🔶 Beta |
| **PicoShogun** | **Command centre & firewall** | **🔶 Pre-1.0 beta** |
| PicoWatch | Runtime monitor | ❌ Early dev |

---

## Architecture

```
PicoShogun/
├── api/server.py            # FastAPI REST API (v2.16) + WebSocket + Dashboard
│   ├── lifespan context manager (startup/shutdown)
│   ├── SIGTERM/SIGINT graceful shutdown handlers
│   ├── SecurityHeadersMiddleware (HSTS, CSP, X-Frame-Options, etc.)
│   ├── RequestIDMiddleware (X-Request-ID propagation)
│   ├── RequestSizeLimitMiddleware (10 MB default)
│   ├── DDoSShieldMiddleware (adaptive rate limiting)
│   ├── GZipMiddleware
│   ├── CORSMiddleware (PICOSHOGUN_CORS_ORIGINS env var)
│   ├── CORSHardeningMiddleware (wildcard blocking in prod)
│   ├── RateLimitMiddleware (per-IP + per-org, SQLite persistence)
│   └── AuditMiddleware (request logging)
├── front/index.html          # Command Centre SPA dashboard
├── config/
│   ├── settings.py           # Dataclass config from env (PICOSHOGUN_* env vars)
│   ├── logging_config.py     # Structured JSON logging (JSONFormatter)
│   ├── project_registry.json # 75+ project definitions
│   └── anomaly_rules.json    # Metric anomaly thresholds
├── database/
│   └── manager.py            # Thread-safe SQLite WAL + migration framework (7 migrations)
│                               + ConnectionPool abstract interface (Postgres migration path)
├── services/
│   ├── orchestrator.py       # Async project runner with concurrency control
│   ├── intelligence.py       # 16-pattern threat engine with correlation
│   ├── alert_hub.py          # Multi-channel alerts (Discord/Slack/Email/Syslog)
│   ├── auth.py               # JWT + API keys + RBAC + expiration enforcement
│   ├── orgs.py               # Multi-tenant org model with tier limits
│   ├── event_bus.py          # Pub/sub event bus (1000-event history)
│   ├── websocket_manager.py # Real-time WS broadcast with channels
│   ├── metrics.py            # Prometheus-compatible metrics collector
│   ├── scheduler.py          # Cron-based job scheduler (croniter)
│   ├── backup.py             # Compressed DB + log backups with retention
│   ├── log_manager.py        # Auto-rotation + compression + cleanup
│   ├── plugin_manager.py    # Dynamic plugin loading from plugins/
│   ├── webhooks.py           # HMAC-signed outgoing webhooks with retry
│   ├── anomaly_detector.py  # Configurable metric anomaly rules engine
│   ├── audit_cleanup.py     # Per-severity audit log retention + purge API
│   └── observability.py      # OpenTelemetry tracing + FastAPI instrumentation
├── middleware/
│   ├── security_headers.py   # Security headers (HSTS, CSP, etc.)
│   ├── request_id.py         # Request ID / correlation ID
│   ├── request_size_limit.py # Body size limit (10 MB default)
│   ├── rate_limit.py         # Per-IP + per-org rate limiting (SQLite-persisted)
│   ├── cors_hardening.py     # Production CORS wildcard detection + blocking
│   ├── https_enforcement.py # HTTP→HTTPS redirect in production
│   ├── request_timeout.py   # 30s request timeout (504 on overrun)
│   ├── docs_restriction.py   # Block /docs and /redoc in production
│   ├── audit.py              # Request audit logging
│   └── ddos_shield.py        # Adaptive DDoS protection
├── pico_dome/
│   ├── L1_perimeter/         # DDoS shield (middleware)
│   ├── L2_validation/        # Supply chain scanner (13 rules, deterministic)
│   ├── L3_execution/         # Sandbox (seccomp/seatbelt/subprocess)
│   └── L4_behavioral/        # Behavioral analysis (timing/exfil/entropy/honeypot)
├── tests/
│   └── test_api.py           # API endpoint tests (health, auth, observability)
├── deploy/
│   ├── prometheus.yml        # Prometheus scrape config
│   └── otel-collector.yml   # OpenTelemetry collector config
├── docker-compose.yml        # Docker Compose (picoshogun + prometheus + grafana + otel)
├── Dockerfile                # Multi-stage production build
├── pyproject.toml            # Project config (dependencies, lint, test, asyncio)
├── .github/workflows/ci.yml # CI pipeline (lint + test + security + docker)
└── orchestrator/
    └── master.py             # DEPRECATED — use services/orchestrator.py
```

## API Endpoints (v2.16)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | — | Command Centre dashboard |
| GET | `/dashboard` | — | Command Centre dashboard (alias) |
| GET | `/health` | — | Full health check (readiness) |
| GET | `/health/live` | — | Liveness probe (process alive) |
| GET | `/health/ready` | — | Readiness probe (DB connected) |
| GET | `/status` | Bearer | System status |
| GET | `/projects` | Bearer+Org | List projects |
| POST | `/projects/{id}/run` | Bearer+Org | Trigger project run |
| POST | `/batch/run` | Bearer+Org | Batch project execution |
| GET | `/projects/{id}/export` | Bearer+Org | Export project data (JSON/CSV) |
| GET | `/intelligence` | Bearer | Intelligence signals |
| GET | `/audit/stats` | Bearer | Audit log statistics + retention policy |
| POST | `/audit/purge` | Bearer+Admin | Purge audit logs (supports dry_run) |
| POST | `/auth/api-key/{id}/rotate` | Bearer | Rotate API key |
| DELETE | `/auth/api-key/{id}` | Bearer | Revoke API key |
| GET | `/api/v1/scans` | Bearer | Supply chain scans |
| POST | `/api/v1/sandboxes` | Bearer+Operator | Sandbox command execution |
| GET | `/api/v1/dashboard/summary` | Bearer | Aggregated dashboard data |
| WS | `/ws` | Optional | Real-time event stream (supports token auth) |

## What's REAL (functional, tested)

- ✅ API server: FastAPI with 55+ endpoints, 12-layer middleware, JWT auth, rate limiting
- ✅ Database: Thread-safe SQLite WAL, 7 migrations, 15+ tables, backup/restore
- ✅ Auth: JWT + API keys + RBAC, key rotation, expiration enforcement
- ✅ Middleware: SecurityHeaders, RequestID, SizeLimit, DDoSShield, GZip, CORS, RateLimit, Audit, Timeout, HTTPS, DocsRestriction
- ✅ Orchestrator: Async project runner with concurrency control
- ✅ Intelligence engine: 16 regex patterns with correlation
- ✅ Alert hub: Discord/Slack/Email/Syslog channels with cooldown/dedup
- ✅ Scheduler, backup, event bus, WebSocket, metrics, webhooks
- ✅ Frontend dashboard: Single-page app with Canvas charts
- ✅ Docker: Multi-stage build, docker-compose with Prometheus/Grafana/OTel profiles
- ✅ CI: GitHub Actions (lint → test → security → Docker)
- ✅ PicoSentry: 246 tests passing, deterministic supply chain scanner

## What's COSPLAY (aspirational or misleading)

- 🔶 **Organization system** (`services/orgs.py`): Code exists, DB tables exist, not heavily used. Multi-tenant is there but untested at scale.
- 🔶 **Discord notifier plugin**: Logs to Python logger, doesn't actually send to Discord.
- 🔶 **Intelligence engine quality**: Regex patterns produce false positives. `classify_failure()` is the most useful part.
- ❌ **Master CLI** (`orchestrator/master.py`): Deprecated, superseded by `services/orchestrator.py`.
- 🔶 **Load testing**: No benchmarks yet.
- 🔶 **Dashboard E2E tests**: No Playwright/Cypress tests.
- 🔶 **MyPy strict**: Currently `--ignore-missing-imports --no-strict-optional`.
- 🔶 **Rate limit persist**: `persist=True` is off by default.
- 🔶 **CORS wildcard blocking**: `block_wildcard_in_production=True` not yet enforced.

## Deployment

### Docker
```bash
docker build -t picoshogun:latest .
docker run -d -p 8765:8765 \
  -e PICOSHOGUN_SECRET_KEY=your-production-secret \
  -e PICOSHOGUN_ENV=production \
  -e PICOSHOGUN_CORS_ORIGINS=https://app.example.com \
  picoshogun:latest
```

### Docker Compose
```bash
docker compose up -d picoshogun                          # Platform only
docker compose --profile monitoring up -d             # With Prometheus + Grafana
docker compose --profile tracing up -d               # With OTel Collector
```

### CI/CD
- GitHub Actions pipeline at `.github/workflows/ci.yml`
- Stages: lint (ruff) → test (3.10/3.11/3.12) → security (pip-audit + bandit) → Docker build + smoke test
