# Shogun — Enterprise Security Platform

**Version:** 2.15.0 | **Last Updated:** 2026-05-29 | **Git:** `main`

---

## Architecture

```
Shogun/
├── api/server.py            # FastAPI REST API (v2.15) + WebSocket + Dashboard
│   ├── lifespan context manager (startup/shutdown)
│   ├── SecurityHeadersMiddleware (HSTS, CSP, X-Frame-Options, etc.)
│   ├── RequestIDMiddleware (X-Request-ID propagation)
│   ├── RequestSizeLimitMiddleware (10 MB default)
│   ├── DDoSShieldMiddleware (adaptive rate limiting)
│   ├── GZipMiddleware
│   ├── CORSMiddleware
│   ├── RateLimitMiddleware (per-IP + per-org)
│   └── AuditMiddleware (request logging)
│   Note: FastAPI add_middleware is LIFO; registered in reverse order
├── front/index.html          # Enterprise Command Centre (SPA dashboard)
├── config/
│   ├── settings.py           # Pydantic-style dataclass config from env
│   ├── logging_config.py     # Structured JSON logging (JSONFormatter)
│   ├── project_registry.json # 75+ project definitions
│   └── anomaly_rules.json    # Metric anomaly thresholds
├── database/
│   └── manager.py            # Thread-safe SQLite WAL with migration framework (7 migrations)
├── services/
│   ├── orchestrator.py       # Async project runner with concurrency control
│   ├── intelligence.py       # 16-pattern threat engine with correlation
│   ├── alert_hub.py          # Multi-channel alerts (Discord/Slack/Email/Syslog)
│   ├── auth.py               # JWT + API keys + RBAC (fixed token parsing)
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
│   └── observability.py      # OpenTelemetry tracing + FastAPI instrumentation
├── middleware/
│   ├── security_headers.py   # Security headers (HSTS, CSP, etc.)
│   ├── request_id.py         # Request ID / correlation ID
│   ├── request_size_limit.py # Body size limit (10 MB default)
│   ├── rate_limit.py         # Per-IP + per-org rate limiting
│   ├── audit.py              # Request audit logging
│   └── ddos_shield.py        # Adaptive DDoS protection
├── iron_dome/
│   ├── L1_perimeter/         # DDoS shield (middleware)
│   ├── L2_validation/        # Supply chain scanner (13 rules, deterministic)
│   ├── L3_execution/         # Sandbox (seccomp/seatbelt/subprocess)
│   └── L4_behavioral/        # Behavioral analysis (timing/exfil/entropy/honeypot)
├── tests/
│   ├── test_api.py           # API endpoint tests (observability, health, auth)
│   ├── test_scanner.py       # L2 scanner tests (390 lines)
├── deploy/
│   ├── prometheus.yml        # Prometheus scrape config
│   └── otel-collector.yml   # OpenTelemetry collector config
├── docker-compose.yml        # Docker Compose (shogun + prometheus + grafana + otel)
├── Dockerfile                # Multi-stage production build
├── pyproject.toml            # Project configuration (dependencies, linting, testing)
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
| GET | `/intelligence/correlations/{id}` | Bearer | Correlation analysis |
| GET | `/intelligence/threat-score` | Bearer | Aggregate threat score |
| GET | `/alerts` | Bearer | Alert listing |
| POST | `/alerts/{id}/acknowledge` | Bearer | Acknowledge alert |
| POST | `/alerts/retry` | Bearer | Retry failed alerts |
| GET | `/reports/summary` | Bearer | Summary report |
| GET | `/reports/project/{id}` | Bearer | Project report |
| GET | `/metrics` | Bearer | JSON metrics |
| GET | `/metrics/prometheus` | — | Prometheus metrics |
| GET | `/metrics/json` | Bearer | Detailed JSON metrics |
| POST | `/auth/register` | — | User registration |
| POST | `/auth/login` | — | JWT login |
| POST | `/auth/api-key` | Bearer | Create API key |
| POST | `/auth/api-key/{id}/rotate` | Bearer | Rotate API key |
| DELETE | `/auth/api-key/{id}` | Bearer | Revoke API key |
| GET | `/plugins` | Bearer | Loaded plugins |
| GET | `/webhooks` | Bearer | Webhook listing |
| POST | `/webhooks` | Bearer+Operator | Create webhook |
| GET | `/scheduler/jobs` | Bearer | Scheduled jobs |
| POST | `/scheduler/jobs` | Bearer+Operator | Create scheduled job |
| PATCH | `/scheduler/jobs/{id}/enable` | Bearer+Operator | Enable job |
| PATCH | `/scheduler/jobs/{id}/disable` | Bearer+Operator | Disable job |
| DELETE | `/scheduler/jobs/{id}` | Bearer+Admin | Delete job |
| POST | `/backup` | Bearer+Admin | Create backup |
| GET | `/backups` | Bearer | List backups |
| GET | `/logs/stats` | Bearer | Log stats |
| POST | `/logs/rotate` | Bearer | Trigger log rotation |
| GET | `/logs` | Bearer | Log entries (filterable) |
| GET | `/events/history` | Bearer | Event bus history |
| GET | `/orgs` | Bearer | List organizations |
| POST | `/orgs` | Bearer | Create organization |
| GET | `/orgs/{id}` | Bearer | Organization details |
| GET | `/orgs/{id}/members` | Bearer | Org members |
| GET | `/orgs/{id}/usage` | Bearer | Org usage vs limits |
| POST | `/orgs/{id}/upgrade` | Bearer+Admin | Upgrade org tier |
| GET | `/anomaly/rules` | Bearer | Anomaly detection rules |
| GET | `/anomaly/alerts` | Bearer | Anomaly alerts |
| POST | `/anomaly/check` | Bearer | Trigger anomaly check |
| PATCH | `/anomaly/rules/{id}` | Bearer | Update anomaly rule |
| POST | `/api/v1/scans` | Bearer+Viewer | Run L2 supply chain scan |
| GET | `/api/v1/scans/rules` | Bearer+Viewer | List scanner rules |
| POST | `/api/v1/sandboxes` | Bearer+Operator | Run L3 sandbox |
| GET | `/api/v1/sandboxes/policies/default` | Bearer | Default sandbox policy |
| GET | `/api/v1/dashboard/summary` | Bearer | Aggregated dashboard data |
| WS | `/ws` | Optional | Real-time event stream (supports token auth) |

## v2.15 Changes

### Architecture — Route Versioning & Error Handling

- **API v1 router**: Mounted `api_v1` router. Scan, sandbox, and dashboard summary routes now use the versioned router (`/api/v1/scans`, `/api/v1/sandboxes`, `/api/v1/dashboard/summary`). Unversioned routes remain on root app.
- **Middleware order**: Fixed middleware execution order. `add_middleware` is LIFO in FastAPI — reversed registration so execution order is now correct: SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield → GZip → CORS → RateLimit → Audit.
- **Global exception handler**: Returns structured JSON for unhandled exceptions instead of HTML tracebacks. Includes `request_id` for correlation.
- **Startup config validation**: Lifespan calls `settings.validate()` and logs warnings for insecure production defaults.

### Infrastructure

- **`start_api.sh`**: Project-relative `.venv/`, env-var config (`SECDEV_HOST`, `SECDEV_PORT`, `SECDEV_WORKERS`), liveness health check.
- **Stale files removed**: Deleted `1` and `secdev_kimi.db.bak-*`.
- **Logger renamed**: `SecdevKimi.API` → `shogun.api` for structured log consistency.

## v2.15 Changes

### Enterprise Hardening

- **App lifecycle**: FastAPI `lifespan` context manager replaces deprecated `on_event` handlers. Proper startup/shutdown of scheduler, anomaly detector, event bus, plugins, and DB connections.
- **Security headers**: `SecurityHeadersMiddleware` adds HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, and Permissions-Policy.
- **Request tracing**: `RequestIDMiddleware` generates/propagates `X-Request-ID` for distributed tracing.
- **Request size limit**: `RequestSizeLimitMiddleware` rejects bodies over 10 MB (413).
- **Structured logging**: `config/logging_config.py` with JSON formatter for production log aggregation.
- **WebSocket auth**: `/ws` endpoint supports optional JWT authentication via query param or auth message.
- **Health probes**: `/health/live` (liveness) and `/health/ready` (readiness) for Kubernetes/Docker deployments.
- **Database v7**: `anomaly_alerts` table with indexed columns for rule_id and severity.
- **Project config**: Comprehensive `pyproject.toml` with all dependencies, linting, and test config.
- **Deprecation**: `orchestrator/master.py` marked deprecated — will be removed in v3.0.

## Deployment

### Docker
```bash
docker build -t shogun:latest .
docker run -d -p 8765:8765 \
  -e SHOGUN_SECRET_KEY=your-production-secret \
  -e SHOGUN_ENV=production \
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
