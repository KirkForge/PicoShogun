# Shogun — Enterprise Security Platform

**Version:** 2.15.0 | **Last Updated:** 2026-05-29 | **Git:** `master`

---

## Architecture

```
Shogun/
├── api/server.py            # FastAPI REST API (v2.15) + WebSocket + Dashboard
│   ├── lifespan context manager (startup/shutdown)
│   ├── SIGTERM/SIGINT graceful shutdown handlers
│   ├── SecurityHeadersMiddleware (HSTS, CSP, X-Frame-Options, etc.)
│   ├── RequestIDMiddleware (X-Request-ID propagation)
│   ├── RequestSizeLimitMiddleware (10 MB default)
│   ├── DDoSShieldMiddleware (adaptive rate limiting)
│   ├── GZipMiddleware
│   ├── CORSMiddleware (SHOGUN_CORS_ORIGINS env var)
│   ├── CORSHardeningMiddleware (wildcard blocking in prod)
│   ├── RateLimitMiddleware (per-IP + per-org, SQLite persistence)
│   └── AuditMiddleware (request logging)
├── front/index.html          # Enterprise Command Centre (SPA dashboard)
├── config/
│   ├── settings.py           # Dataclass config from env (SHOGUN_* env vars)
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
│   ├── websocket_manager.py  # Real-time WS broadcast with channels
│   ├── metrics.py            # Prometheus-compatible metrics collector
│   ├── scheduler.py          # Cron-based job scheduler (croniter)
│   ├── backup.py             # Compressed DB + log backups with retention
│   ├── log_manager.py        # Auto-rotation + compression + cleanup
│   ├── plugin_manager.py     # Dynamic plugin loading from plugins/
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
│   ├── https_enforcement.py  # HTTP→HTTPS redirect in production
│   ├── request_timeout.py    # 30s request timeout (504 on overrun)
│   ├── docs_restriction.py   # Block /docs and /redoc in production
│   ├── audit.py              # Request audit logging
│   └── ddos_shield.py        # Adaptive DDoS protection
├── iron_dome/
│   ├── L1_perimeter/         # DDoS shield (middleware)
│   ├── L2_validation/        # Supply chain scanner (13 rules, deterministic)
│   ├── L3_execution/         # Sandbox (seccomp/seatbelt/subprocess)
│   └── L4_behavioral/        # Behavioral analysis (timing/exfil/entropy/honeypot)
├── tests/
│   └── test_api.py           # API endpoint tests (health, auth, observability)
├── deploy/
│   ├── prometheus.yml        # Prometheus scrape config
│   └── otel-collector.yml   # OpenTelemetry collector config
├── docker-compose.yml        # Docker Compose (shogun + prometheus + grafana + otel)
├── Dockerfile                # Multi-stage production build
├── pyproject.toml            # Project config (dependencies, lint, test, asyncio)
├── .github/workflows/ci.yml # CI pipeline (lint + test + security + docker)
└── orchestrator/
    └── master.py             # DEPRECATED — use services/orchestrator.py
```

## API Endpoints (v2.15)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | — | Command Centre dashboard |
| GET | `/dashboard` | — | Command Centre dashboard (alias) |
| GET | `/health` | — | Full health check (readiness) |
| GET | `/health/live` | — | Liveness probe (process alive) |
| GET | `/health/ready` | — | Readiness probe (DB connected) |
| GET | `/health/history` | Bearer | Health check history |
| GET | `/status` | Bearer | System status overview |
| GET | `/projects` | Bearer+Org | List projects (filterable) |
| GET | `/projects/{id}` | Bearer+Org | Project details |
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

## Enterprise Hardening (v2.15.0)

### Middleware Stack (execution order, outermost → innermost)
1. **SecurityHeadersMiddleware** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
2. **RequestIDMiddleware** — X-Request-ID propagation for distributed tracing
3. **RequestSizeLimitMiddleware** — 10 MB body size limit
4. **DDoSShieldMiddleware** — Adaptive rate limiting with trust scoring
5. **GZipMiddleware** — Response compression
6. **CORSMiddleware** — Cross-origin resource sharing (SHOGUN_CORS_ORIGINS env var)
7. **CORSHardeningMiddleware** — Production CORS wildcard detection + blocking
8. **RateLimitMiddleware** — Per-IP (100/min) + per-org (1000/min) rate limiting (SQLite-persisted)
9. **AuditMiddleware** — Request audit logging to DB
10. **RequestTimeoutMiddleware** — 30s timeout (504 on overrun)
11. **HTTPSEnforcementMiddleware** — HTTP→HTTPS redirect in production
12. **DocsRestrictionMiddleware** — Block /docs and /redoc in production

### Rate Limit Persistence
- `RateLimitMiddleware` now supports `persist=True` to flush counters to SQLite
- On startup, persisted counters are restored so limits survive pod restarts
- Flushing occurs during the eviction cycle (every 60s) to minimize overhead
- Table: `rate_limit_counters` (bucket_type, bucket_key, timestamps, updated_at)

### CORS Environment Variable
- `SHOGUN_CORS_ORIGINS` env var sets explicit CORS origins (comma-separated)
- Example: `SHOGUN_CORS_ORIGINS=https://app.example.com,https://admin.example.com`
- When unset, defaults to `["*"]` (development-friendly)
- `CORSHardeningMiddleware` blocks wildcard origins in production when explicit origins are set
- Config validation warns on wildcard CORS in production

### Graceful Shutdown
- `SIGTERM` and `SIGINT` handlers in `api/server.py` `__main__` block
- Stops anomaly detector, scheduler, event bus, plugins, and DB connections before exit
- Ensures in-flight work is not lost on Kubernetes pod termination

### API Key Expiration Enforcement
- `AuthService.cleanup_expired_keys()` deactivates keys past their `expires_at` timestamp
- Called at startup in the lifespan context; can be scheduled periodically via `scheduler`
- Expired keys are logged with id, name, and user_id for audit trail

### Audit Log Management
- **GET /audit/stats** — Audit log statistics + retention policy
- **POST /audit/purge** — Purge audit logs (admin-only, supports dry_run)
- Per-severity retention: critical=365d, high=180d, medium=90d, low=30d, default=90d
- Configurable via `settings.database.audit_retention_days`

### Configuration Validation
- Production mode warns on: default secret key, no SSL cert, debug enabled, wildcard hosts, wildcard CORS
- CORS wildcard with credentials is explicitly flagged as a security misconfiguration

### Connection Pool Abstraction
- `ConnectionPool` abstract interface in `database/manager.py`
- Methods: `acquire()`, `release()`, `close_all()`
- Current SQLite `DatabaseManager` uses thread-local connections; Postgres migration can swap in `asyncpg`/`psycopg` pool

### PicoSentry Scanner (246 tests, 0 failures)
- All fixture data complete: pnpm-lock.yaml and package-lock.json added
- L2-PNPM-001 rule correctly detects dangerous pnpm configurations

### Test Configuration
- `asyncio_mode = "strict"` and `asyncio_default_fixture_loop_scope = "function"` in `pyproject.toml`
- Eliminates pytest-asyncio DeprecationWarning on Python 3.12+

## Deployment

### Docker
```bash
docker build -t shogun:latest .
docker run -d -p 8765:8765 \
  -e SHOGUN_SECRET_KEY=your-production-secret \
  -e SHOGUN_ENV=production \
  -e SHOGUN_CORS_ORIGINS=https://app.example.com \
  shogun:latest
```

### Docker Compose
```bash
docker compose up -d shogun                          # Platform only
docker compose --profile monitoring up -d             # With Prometheus + Grafana
docker compose --profile tracing up -d               # With OTel Collector
```

### CI/CD
- GitHub Actions pipeline at `.github/workflows/ci.yml`
- Stages: lint (ruff + mypy) → test (3.10/3.11/3.12) → security (pip-audit + bandit) → Docker build + smoke test
