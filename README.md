# Shogun — Enterprise Security Platform

Enterprise-grade security orchestration and intelligence platform. FastAPI + SQLite + Python 3.12.

## Quick Start

```bash
# Setup
bash scripts/setup.sh
source .venv/bin/activate

# Start API
python -m uvicorn api.server:app --reload

# Or use the entrypoint
shogun

# Run batch
bash scripts/run_category.sh monitoring --parallel 4 --verbose
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHOGUN_ENV` | `development` | Environment (`development`/`production`) |
| `SHOGUN_SECRET_KEY` | `change-me-in-production` | JWT signing key |
| `SHOGUN_CORS_ORIGINS` | `*` | Comma-separated CORS origins |
| `SHOGUN_DDOS_SHIELD` | `false` | Enable DDoS shield |
| `SHOGUN_DB_PATH` | `shogun.db` | SQLite database path |
| `SHOGUN_API_PORT` | `8765` | API listen port |
| `SHOGUN_AUDIT_RETENTION_DAYS` | `90` | Audit log retention period |

See `.env.example` for the full list.

## Features

- **12-layer middleware stack**: SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield → GZip → CORS → CORSHardening → RateLimit → Audit → Timeout → HTTPS → DocsRestriction
- **Rate limiting**: Per-IP (100/min) + per-org (1000/min) with SQLite persistence
- **JWT + API keys + RBAC**: Token auth, API key rotation, expired key cleanup
- **Audit log management**: Per-severity retention, purge API, dry-run support
- **Graceful shutdown**: SIGTERM/SIGINT handlers for Kubernetes pod termination
- **Project Orchestration**: Run 100+ security projects with async execution
- **Intelligence Engine**: 16-pattern threat extraction with correlation
- **Alert Hub**: Multi-channel alerts (Discord/Slack/Email/Syslog)
- **Plugin System**: Dynamic extensibility with lifecycle hooks
- **Metrics**: Prometheus-compatible with built-in collection
- **Webhooks**: HMAC-signed outgoing integrations
- **Scheduler**: Cron-based job scheduling
- **Backup/Restore**: Compressed archives with retention
- **Event Bus**: Pub/sub with WebSocket real-time streaming
- **Log Management**: Auto-rotation with compression
- **OpenTelemetry**: Distributed tracing with graceful no-op fallback
- **Docker**: Production-ready containers with monitoring profiles

## Architecture

```
api/server.py              # FastAPI REST API + WebSocket + Dashboard
config/settings.py         # Dataclass config from env vars (SHOGUN_*)
database/manager.py        # Thread-safe SQLite WAL + migrations + ConnectionPool interface
services/auth.py           # JWT + API keys + RBAC + expiration enforcement
services/audit_cleanup.py # Per-severity audit log retention + purge API
middleware/                # 12-layer enterprise middleware stack
iron_dome/                 # L1-L4 defense layers (perimeter, validation, sandbox, behavioral)
picosentry/                # Supply chain scanner (246 tests, deterministic)
```

See `STATE.md` for the full architecture diagram.

## API Endpoints

Base URL: `http://localhost:8765`

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Full health check (readiness) |
| GET | `/health/live` | — | Liveness probe |
| GET | `/health/ready` | — | Readiness probe (DB connected) |
| GET | `/status` | Bearer | System status |
| GET | `/projects` | Bearer+Org | List projects |
| POST | `/projects/{id}/run` | Bearer+Org | Trigger project run |
| GET | `/intelligence` | Bearer | Intelligence signals |
| GET | `/audit/stats` | Bearer | Audit statistics + retention |
| POST | `/audit/purge` | Admin | Purge audit logs |
| POST | `/auth/api-key/{id}/rotate` | Bearer | Rotate API key |
| DELETE | `/auth/api-key/{id}` | Bearer | Revoke API key |
| GET | `/api/v1/scans` | Bearer | Supply chain scans |
| POST | `/api/v1/sandboxes` | Bearer+Operator | Sandbox execution |
| WS | `/ws` | Optional | Real-time event stream |

Full endpoint list in `STATE.md`.

## Testing

```bash
python -m pytest tests/ -v                    # Main tests (20)
python -m pytest picosentry/tests/ -v          # PicoSentry tests (246)
python -W error::DeprecationWarning -m pytest   # Strict deprecation check
ruff check .                                    # Lint
```

## Docker

```bash
docker build -t shogun:latest .
docker run -d -p 8765:8765 \
  -e SHOGUN_SECRET_KEY=your-production-secret \
  -e SHOGUN_ENV=production \
  -e SHOGUN_CORS_ORIGINS=https://app.example.com \
  shogun:latest
```

## License

Enterprise internal use.
