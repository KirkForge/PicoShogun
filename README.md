# Shogun — Enterprise Security Platform

Enterprise-grade security lab orchestration and intelligence platform.

## Quick Start

```bash
# Setup
bash scripts/setup.sh
source venv/bin/activate

# Start API
python -m uvicorn api.server:app --reload

# Or start daemon
python orchestrator/master.py serve

# Or run batch
bash scripts/run_category.sh monitoring --parallel 4 --verbose
```

## Features

- **Project Orchestration**: Run 100+ security projects with async execution
- **Intelligence Engine**: Extract threats, correlate signals, score risks
- **Alert Hub**: Multi-channel alerts (Discord/Slack/Email/Syslog)
- **Authentication**: JWT + API keys with role-based access
- **Plugin System**: Dynamic extensibility with lifecycle hooks
- **Metrics**: Prometheus-compatible with built-in collection
- **Webhooks**: HMAC-signed outgoing integrations
- **Scheduler**: Cron-based job scheduling
- **Backup/Restore**: Compressed archives with retention
- **Event Bus**: Pub/sub with WebSocket real-time streaming
- **Log Management**: Auto-rotation with compression
- **Docker**: Production-ready containers with monitoring

## Architecture

See `STATE.md` for full architecture and development state.

## Changelog

See `CHANGELOG.md` for version history.

## API

Base URL: `http://localhost:8765`

WebSocket: `ws://localhost:8765/ws`

Health: `GET /health` (no auth)

Full endpoints in `STATE.md`.

## License

Enterprise internal use.
