# Secdev_kimi Enterprise Changelog

All notable changes to this project will be documented in this file.

## [2.9.0] - 2026-05-13

### Project Data Export (EXPORT-01)
- **GET `/projects/{id}/export`** — Full project dump (JSON/CSV)
- **Query param `?format=json|csv`** — JSON returns all project data (config, runs, alerts, intelligence, metrics). CSV exports runs table only.
- **Response structure**: `export_version`, `exported_at`, `project_config`, `project_runs`, `alerts`, `intelligence`, `metrics`
- **Org gate**: Verifies project belongs to caller's organization before export

## [2.2.0] - 2026-05-11

### Event Bus (Pub/Sub)
- **EventBus**: Centralized publish/subscribe system
- **Event Types**: Priority levels (low, normal, high, critical)
- **History**: Last 1000 events with filtering by type
- **Wildcard Subscribers**: Subscribe to all events with `*`
- **Thread-safe**: Lock-protected for concurrent access

### Log Management
- **Log Rotation**: Automatic rotation when logs exceed max size
- **Compression**: Gzip compression for old logs
- **Retention**: Configurable day-based cleanup
- **Multi-file**: Rotate all logs in directory
- **Stats**: Log directory size and file count tracking

### Docker Support
- **Dockerfile**: Production-ready Python 3.11 slim image
- **docker-compose.yml**: Full stack with monitoring profile
- **Health Checks**: Built-in container health checks
- **Volumes**: Persistent data, logs, plugins
- **Prometheus + Grafana**: Optional monitoring stack (profiles)

### API Expansion
- **Plugins**: `/plugins` - List loaded plugins and health
- **Webhooks**: `/webhooks` GET/POST - Manage webhook endpoints
- **Scheduler**: `/scheduler/jobs` GET/POST - Job management
- **Backup**: `/backup` POST + `/backups` GET - Full backup system
- **Logs**: `/logs/stats` + `/logs/rotate` - Log management
- **Metrics**: `/metrics/prometheus` + `/metrics/json` - Prometheus/JSON export
- **Events**: `/events/history` - Event bus history

### WebSocket Real-Time Events
- **WebSocket endpoint**: `/ws` for live event streaming
- **Channel subscriptions**: Client can subscribe to specific event types
- **Event bus bridge**: Automatic forwarding of all events to WS clients
- **Priority-aware**: Critical events pushed immediately
- **JSON protocol**: Simple JSON message format

### Integration Points
- All new services integrated into API
- Metrics auto-collect from orchestrator
- Webhooks dispatch on intelligence/alert events
- Scheduler daemon ready for background jobs
- WebSocket bridge from event bus

## [2.1.0] - 2026-05-11

### Plugin System
- **Plugin Manager**: Dynamic loading from `plugins/` directory
- **Plugin Interface**: Base class with lifecycle hooks
- **Event Hooks**: `project_start`, `project_complete`, `intelligence`, `alert`
- **Metadata**: JSON manifest system for plugin discovery
- **Hot-loading**: Runtime plugin management

### Metrics & Monitoring
- **Metrics Collector**: Prometheus-compatible metrics
- **Metric Types**: Gauge, Counter, Histogram support
- **Pre-built Metrics**: Project runs, API requests, threat scores, uptime
- **Prometheus Export**: `/metrics` endpoint ready
- **JSON Export**: Programmatic access to metrics data

### Webhooks
- **Webhook Manager**: Outgoing webhook system
- **HMAC Signatures**: SHA-256 signed payloads
- **Retry Logic**: Automatic retry on failure
- **Event Filtering**: Subscribe to specific event types
- **Signature Verification**: For incoming webhooks

### Job Scheduler
- **Cron Expressions**: Full cron syntax support (with croniter)
- **Commands**: `batch`, `run`, `report`, `backup`
- **Daemon Mode**: Background scheduler thread
- **Job Management**: Add, remove, enable, disable jobs
- **Status Tracking**: Last run, next run, status history

### Backup & Restore
- **Full Backups**: Database + logs in compressed archives
- **Metadata**: Version tracking in backups
- **Restore**: Point-in-time recovery with safety checks
- **Retention**: Automatic cleanup of old backups
- **Auto-backup**: Daily automated backups

### Infrastructure
- **STATE.md**: Development state tracking
- **CHANGELOG.md**: Version history

## [2.0.0] - 2026-05-11

### Enterprise Foundation
- **BREAKING**: Complete architecture overhaul from v1.0
- Full modular design with services layer
- Environment-based configuration system
- SQLite database with migration framework

### Core Services
- **Orchestrator v2**: Async execution, health checks, retry logic, parallel batches
- **Intelligence Engine**: 15 threat patterns, correlation analysis, composite scoring
- **Alert Hub**: Multi-channel delivery (Discord/Slack/Email/Syslog) with deduplication
- **Auth Service**: JWT tokens, API keys, role-based access control

### API & Middleware
- **REST API** (FastAPI): Full CRUD for projects, runs, intelligence, alerts
- **Rate Limiting**: Per-IP request throttling
- **Audit Logging**: All API requests tracked to database
- **Authentication**: Bearer token + API key validation

### Infrastructure
- **Batch Runner**: Bash script with parallel execution support
- **Master CLI**: 8 commands (status, run, batch, report, health, init, api, serve)
- **Setup Script**: One-command environment initialization
- **systemd Service**: Production deployment ready
- **.env Template**: Configuration reference

### Security
- PBKDF2 + bcrypt password hashing
- JWT with configurable expiration
- API key rotation with expiration
- Request audit trail

---

## [1.0.0] - Earlier

### Initial Release
- Basic project runner
- Simple console output
- Manual bash execution
- SQLite raw queries
