# Shogun — Enterprise Security Platform

**Version:** 2.13.0 | **Last Updated:** 2026-05-28 | **Git:** `main`

---

## Architecture

```
Shogun/
├── api/server.py            # FastAPI REST API (v2.13) + WebSocket + Dashboard
├── front/index.html          # Enterprise Command Centre (SPA dashboard)
├── config/
│   ├── settings.py           # Pydantic-style dataclass config from env
│   ├── project_registry.json # 75+ project definitions
│   └── anomaly_rules.json    # Metric anomaly thresholds
├── database/
│   └── manager.py            # Thread-safe SQLite WAL with migration framework (6 migrations)
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
│   ├── rate_limit.py         # Per-IP + per-org rate limiting
│   ├── audit.py              # Request audit logging middleware
│   └── ddos_shield.py        # Adaptive DDoS protection
├── iron_dome/
│   ├── L1_perimeter/         # DDoS shield (middleware)
│   ├── L2_validation/        # Supply chain scanner (13 rules, deterministic)
│   ├── L3_execution/         # Sandbox (seccomp/seatbelt/subprocess)
│   └── L4_behavioral/        # Behavioral analysis (timing/exfil/entropy/honeypot)
├── tests/
│   ├── test_api.py           # API endpoint tests (20 tests)
│   ├── test_scanner.py       # L2 scanner tests (390 lines)
│   └── fixtures/             # Test fixture projects
├── deploy/
│   ├── prometheus.yml        # Prometheus scrape config
│   └── otel-collector.yml    # OpenTelemetry collector config
├── docker-compose.yml        # Docker Compose (shogun + prometheus + grafana + otel)
├── Dockerfile                # Multi-stage production build
├── .github/workflows/ci.yml  # CI pipeline (lint + test + security + docker)
├── orchestrator/master.py    # Legacy CLI orchestrator
├── picosentry/               # Standalone npm/pnpm scanner (src layout)
└── nginx/secdev-default.conf # Reverse proxy config
```

## API Endpoints (v2.13)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | — | Command Centre dashboard |
| GET | `/dashboard` | — | Command Centre dashboard (alias) |
| GET | `/health` | — | Health readiness check |
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
| GET | `/webhooks` | Bearer | Webhook endpoints |
| POST | `/webhooks` | Bearer | Create webhook |
| POST | `/webhooks/{id}/test` | Bearer | Test webhook |
| DELETE | `/webhooks/{id}` | Bearer | Delete webhook |
| GET | `/scheduler/jobs` | Bearer | Scheduled jobs |
| POST | `/scheduler/jobs` | Bearer | Add scheduled job |
| PATCH | `/scheduler/jobs/{id}/enable` | Bearer | Enable job |
| PATCH | `/scheduler/jobs/{id}/disable` | Bearer | Disable job |
| DELETE | `/scheduler/jobs/{id}` | Bearer | Remove job |
| POST | `/backup` | Bearer | Create backup |
| GET | `/backups` | Bearer | List backups |
| GET | `/logs/stats` | Bearer | Log statistics |
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
| WS | `/ws` | — | Real-time event stream |

## Command Centre Features (v2.13)

The enterprise dashboard at `/` or `/dashboard` provides:

- **Overview Panel**: System health, threat score, active threats, pending alerts with live status pills and animated metric transitions
- **Threat Score Trend Chart**: Canvas-rendered time-series chart with danger threshold line and gradient fill (light/dark theme aware)
- **Run Success Rate Sparkline**: Per-project success rate visualization with colour-coded bars
- **Live Event Feed**: WebSocket-powered real-time event stream with severity colour coding
- **Health Checks**: Per-component status with latency metrics
- **Projects**: Full project listing with category filters, run triggers, success rates
- **Intelligence**: Signal feed with severity badges, confidence scores, threat score
- **Alerts**: Alert table with channel, status, acknowledge/retry flow
- **Supply Chain Scanner (L2)**: Run scans against project directories, view findings, browse rules
- **L3 Sandbox**: Execute commands under sandbox policy, view verdicts and events
- **Organizations**: Multi-tenant org management with tier badges
- **Scheduler**: Cron job management with enable/disable
- **Logs**: Filterable system log viewer
- **Auth Modal**: JWT/API key authentication with local token persistence
- **WebSocket**: Auto-reconnecting live event stream (exponential backoff, 10 retries)
- **Theme Toggle**: Light/dark theme with localStorage persistence
- **Keyboard Shortcuts**: 1-9 for panels, T for theme, R for refresh, ? for help
- **Responsive Design**: Collapsible sidebar on mobile

## OpenTelemetry Integration

- `services/observability.py` provides tracer + meter with graceful no-op fallback
- Auto-instrumentation via `FastAPIInstrumentor` when OTEL endpoint is configured
- Decorators: `@trace_span()` and `@trace_async_span()` for manual span creation
- Env vars: `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`
- Docker Compose profile `tracing` starts OTel Collector

## Bug Fixes (v2.13)

- **Auth token parsing**: Fixed `validate_token()` — simple tokens with colons (timestamps) were incorrectly split, causing 401s
- **Orchestrator `get_status()`**: Fixed `NoneType` crash when `completed` or `failed` counts are null in SQLite aggregates
- **Migration idempotency**: Migration runner now handles `ALTER TABLE ADD COLUMN` duplicate column errors gracefully

## Security Layers (Iron Dome)

| Layer | Module | Status |
|-------|--------|--------|
| L1 | Perimeter (DDoS, rate limiting) | ✅ Middleware integrated |
| L2 | Supply Chain Validation (13 rules) | ✅ Deterministic, 133 tests |
| L3 | Execution Sandbox | ✅ seccomp/seatbelt/subprocess |
| L4 | Behavioral Analysis | ✅ Timing/exfil/entropy/honeypot |

## Database Schema (Migrations)

- v1: Initial (project_runs, intelligence, alerts, metrics, projects, health_checks)
- v2: Users + API keys
- v3: Audit log + org improvements
- v4: Scheduled jobs, webhooks, org tables
- v5: Orgs (multi-tenant)
- v6: org_id on project_runs + revoked_at on api_keys (idempotent)

## Deployment

### Docker
```bash
docker build -t shogun:latest .
docker run -d -p 8765:8765 \
  -e SECDEV_SECRET_KEY=your-production-secret \
  -e SECDEV_ENV=production \
  shogun:latest
```

### Docker Compose
```bash
# Start platform only
docker compose up -d shogun

# Start with monitoring stack
docker compose --profile monitoring up -d

# Start with OpenTelemetry tracing
docker compose --profile tracing up -d
```

### CI/CD
- GitHub Actions pipeline at `.github/workflows/ci.yml`
- Stages: lint (ruff + mypy) → test (3.10/3.11/3.12) → security (pip-audit + bandit) → Docker build + smoke test
- PicoSentry tests run separately

## What's Archived (decoupled, not deleted)

- Cron generator, frontend HTML (replaced by Command Centre)
- Legacy orchestrator CLI (replaced by API + dashboard)
