# Shogun — Enterprise Security Platform

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support%20my%20hardware-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/KirkForge)


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
| `SHOGUN_SECRET_KEY` | **required in production** | JWT signing key — `assert_secure()` refuses boot with default |
| `SHOGUN_CORS_ORIGINS` | `http://localhost:8765` | Comma-separated CORS origins |
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

## Security

### Startup Validation
Shogun refuses to boot in production with insecure defaults. The `assert_secure()` check runs on startup and enforces:
- **No default secret key** — `SHOGUN_SECRET_KEY` must be set; the `change-me-in-production` default is rejected in production
- **No wildcard CORS** — `SHOGUN_CORS_ORIGINS` must list explicit origins in production
- **No wildcard allowed hosts** — `SHOGUN_ALLOWED_HOSTS` must be explicit in production
- **No debug mode** — `SHOGUN_DEBUG=false` in production

Override with `SHOGUN_SKIP_SECURE_ASSERT=1` (not recommended; only for CI/testing).

### TLS Termination
Shogun does not terminate TLS itself. It expects to run behind a reverse proxy (nginx, Caddy, cloud load balancer) that handles TLS. The `ssl_cert_path` and `ssl_key_path` settings in `SecurityConfig` are for documentation — actual TLS is configured in `nginx/shogun-default.conf` or your upstream proxy.

### Plugin Trust Boundary
The plugin system (`services/plugin_manager.py`) loads Python modules from the `plugins/` directory at runtime. **This directory is a trust boundary equivalent to giving someone a shell on the server.** Plugin code runs in-process with full access to the Shogun runtime, database, and network. Before any multi-tenant or external deployment:
- Restrict plugin directory permissions to the Shogun process owner only
- Consider signed plugin manifests with verification
- Consider sandboxed plugin execution (separate process, reduced privileges)

### Token Auth
Shogun uses JWT (PyJWT) for authentication. The legacy simple-token format has been removed — it used non-timing-safe comparison and lacked expiration claims. Existing simple tokens will be rejected.

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
