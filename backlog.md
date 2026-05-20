# SecDev_kimi Backlog v2.8.0
# Each item: 1 day of work max
# Format: ID | Priority | Status | Description | Acceptance Criteria | Date

## Active Sprint
INTEL-03|P1|DONE|Fix intelligence signal quality — false positive filtering|Context-aware filtering: exclude file paths, quoted strings, safe IPs/domains; base confidence 0.5; min_confidence param|2026-05-13
SHIELD-01|P1|DONE|Integrate DDoS shield as middleware|AdaptiveRateLimiter wired into api/server.py; config toggle; error reporting back to shield; disabled by default|2026-05-13
AUDIT-01|P2|DONE|API audit logging — who did what when|middleware logs every request: method, path, user_id, ip, duration, response_code|2026-05-13
EMAIL-01|P2|DONE|Email alert notifications via SMTP|SMTP host, port, user, password from env; TLS, STARTTLS, SSL modes; tested config loading|2026-05-13
SCHED-01|P2|DONE|Scheduled jobs UI — CRUD for cron-like tasks|POST /scheduled-jobs creates job with cron expr; GET lists; PATCH enables/disables; worker picks up due jobs|2026-05-13
RATE-01|P3|DONE|Rate limiting per org + per IP|middleware: 100 req/min per IP, 1000 req/min per org token; 429 response with Retry-After|2026-05-13
EXPORT-01|P3|DONE|Project data export (JSON/CSV)|GET /projects/{id}/export returns full project dump: config, runs, alerts, intelligence, metrics; JSON/CSV format via ?format= param|2026-05-13

## Active Sprint (v2.11 — Next)
HEALTH-01|P1|TODO|Health check endpoint with dependency readiness
ANOM-01|P1|TODO|Metrics anomaly detector — auto-detect thresholds
ANOM-02|P2|TODO|Anomaly alert pipeline
HEALTH-02|P2|TODO|Self-monitoring dashboard data
POLICY-01|P3|TODO|Basic security policy engine

## Completed ✅
DB-02|P2|DONE|Swap SQLite to SQLite + WAL mode|concurrent writes without locking; orchestrator + db/manager both use WAL|2026-05-13
AUTH-01|P1|DONE|Real user registration endpoint|POST /auth/register creates user in DB with bcrypt hash|2026-05-13
AUTH-02|P2|DONE|Role-based access control decorator|@require_role("admin") blocks non-admins|2026-05-13
API-01|P1|DONE|/metrics returns real DB counts (total/completed/failed/alerts_fired)|2026-05-12
API-02|P2|DONE|GET /logs reads orchestrator.log, filter by level/date/lines|2026-05-12
API-03|P2|DONE|GET /events/history returns latest N events from event_bus|2026-05-12
WS-01|P2|DONE|Real-time event pipeline|event bus → WebSocket broadcast verified alive|2026-05-12
BUG-006|P1|FIXED|Backup crash on missing backup_retention_days|2026-05-12
FRONT-01|P3|DONE|Minimal HTML status page|2026-05-12
FRONT-03|P3|DONE|Serve static frontend files|2026-05-12
INTEL-01|P2|DONE|Make intelligence engine actually parse script output|2026-05-13
INTEL-02|P2|DONE|Alert on real conditions|2026-05-13
PLUGIN-01|P3|DONE|Fix dynamic plugin loading|2026-05-13
PWA-01|P4|DONE|nginx reverse proxy:80→:8765, WebSocket upgrade headers|2026-05-13
MON-01|P3|DONE|Export real Prometheus metrics|/metrics/prometheus returns real counters|2026-05-12

## Discovered Bugs
BUG-006|P1|FIXED|Backup crash on missing backup_retention_days|2026-05-12


## Sprint 2.11 — Anomaly Detection & Health Alerting (2026-05-13)
HEALTH-01|P1|TODO|Health check endpoint with dependency readiness|GET /health returns DB, smtp, redis status; all services green/yellow/red|2026-05-13
ANOM-01|P1|TODO|Metrics anomaly detector — auto-detect thresholds|Config: anomaly_rules.json; rules: metric_name, threshold, comparison, duration, alert_channel; detect in background task|2026-05-13
ANOM-02|P2|TODO|Anomaly alert pipeline — Email/Discord/webhook on breach|Hook into existing alert_hub; reuse email/discord credentials; anomaly-specific message templating|2026-05-13
HEALTH-02|P2|TODO|Self-monitoring dashboard data|GET /health/history returns last N checks with trend; store in DB table health_checks|2026-05-13
POLICY-01|P3|TODO|Basic security policy engine (secret scanning rules)|Config: policies/; simple regex rules for API keys, passwords, tokens; POST /policies/scan to test a string|2026-05-13
