![PicoShogun Banner](docs/banner.png)

# PicoShogun — Command Centre for the Pico Security Series

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support%20my%20hardware-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/KirkForge)

Command centre, firewall, and monitoring for the Pico Security Series. FastAPI + SQLite + Python 3.12.

| Product | Purpose | Repo |
|---------|---------|------|
| PicoSentry | Supply chain scanner | KirkForge/PicoSentry |
| PicoDome | LLM injection protection | KirkForge/PicoDome |
| **PicoShogun** | **Command centre & firewall** | **KirkForge/PicoShogun** |
| PicoWatch | Runtime monitor | KirkForge/PicoWatch |

## Status

**Pre-1.0 beta.** Active development started late May 2026. The core API, auth, middleware stack, and orchestration work. The frontend dashboard is functional but rough. Several features are scaffolding — see STATE.md and GAPS.md for what's real vs. aspirational.

## Quick Start

```bash
# Setup
bash scripts/setup.sh
source .venv/bin/activate

# Start API
python -m uvicorn api.server:app --reload

# Or use the entrypoint
picoshogun
# (shogun also works as backward compat alias)

# Run batch
bash scripts/run_category.sh monitoring --parallel 4 --verbose
```

## Environment Variables

Primary prefix is `PICOSHOGUN_*`. `SHOGUN_*` works as backward compat.

| Variable | Default | Description |
|----------|---------|-------------|
| `PICOSHOGUN_ENV` | `development` | Environment (`development`/`production`) |
| `PICOSHOGUN_SECRET_KEY` | **required in production** | JWT signing key — `assert_secure()` refuses boot with default |
| `PICOSHOGUN_CORS_ORIGINS` | `http://localhost:8765` | Comma-separated CORS origins |
| `PICOSHOGUN_DDOS_SHIELD` | `false` | Enable DDoS shield |
| `PICOSHOGUN_DB_PATH` | `picoshogun.db` | SQLite database path |
| `PICOSHOGUN_API_PORT` | `8765` | API listen port |
| `PICOSHOGUN_AUDIT_RETENTION_DAYS` | `90` | Audit log retention period |

See `.env.example` for the full list.

## Features

- **12-layer middleware stack**: SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield → GZip → CORS → CORSHardening → RateLimit → Audit → Timeout → HTTPS → DocsRestriction
- **Rate limiting**: Per-IP (100/min) + per-org (1000/min) with SQLite persistence
- **JWT + API keys + RBAC**: Token auth, API key rotation, expired key cleanup
- **Audit log management**: Per-severity retention, purge API, dry-run support
- **Graceful shutdown**: SIGTERM/SIGINT handlers for Kubernetes pod termination
- **PicoDome integration**: L1-L4 defense layers (perimeter, validation, sandbox, behavioral)
- **PicoSentry integration**: Supply chain scanner (246 tests, deterministic)
- **Project Orchestration**: Run 75+ security projects with async execution
- **Intelligence Engine**: 16-pattern threat extraction with correlation
- **Alert Hub**: Multi-channel alerts (Discord/Slack/Email/Syslog)
- **Metrics**: Prometheus-compatible with built-in collection
- **Scheduler**: Cron-based job scheduling
- **Backup/Restore**: Compressed archives with retention
- **Event Bus**: Pub/sub with WebSocket real-time streaming

## Security

### Startup Validation
PicoShogun refuses to boot in production with insecure defaults. The `assert_secure()` check runs on startup and enforces:
- **No default secret key** — `PICOSHOGUN_SECRET_KEY` must be set; the default is rejected in production
- **No wildcard CORS** — `PICOSHOGUN_CORS_ORIGINS` must list explicit origins in production
- **No wildcard allowed hosts** — `PICOSHOGUN_ALLOWED_HOSTS` must be explicit in production
- **No debug mode** — `PICOSHOGUN_DEBUG=false` in production

Override with `PICOSHOGUN_SKIP_SECURE_ASSERT=1` (not recommended; only for CI/testing).

### TLS Termination
PicoShogun does not terminate TLS itself. It expects to run behind a reverse proxy (nginx, Caddy, cloud load balancer) that handles TLS.

### Plugin Trust Boundary
The plugin system loads Python modules from the `plugins/` directory at runtime. **This directory is a trust boundary equivalent to giving someone a shell on the server.** Plugin code runs in-process with full access to the runtime, database, and network.

### Token Auth
JWT (PyJWT) for authentication. The legacy simple-token format has been removed — it used non-timing-safe comparison and lacked expiration claims.

## Architecture

```
api/server.py              # FastAPI REST API + WebSocket + Dashboard
config/settings.py         # Dataclass config from env vars (PICOSHOGUN_*)
database/manager.py        # Thread-safe SQLite WAL + migrations + ConnectionPool interface
services/auth.py           # JWT + API keys + RBAC + expiration enforcement
services/audit_cleanup.py # Per-severity audit log retention + purge API
middleware/                # 12-layer middleware stack
pico_dome/                 # L1-L4 defense layers (PicoDome integration)
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
docker build -t picoshogun:latest .
docker run -d -p 8765:8765 \
  -e PICOSHOGUN_SECRET_KEY=your-production-secret \
  -e PICOSHOGUN_ENV=production \
  -e PICOSHOGUN_CORS_ORIGINS=https://app.example.com \
  picoshogun:latest
```

## License

BUSL-1.1
