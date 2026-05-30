"""REST API for PicoShogun — security orchestration & intelligence platform."""
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from config.logging_config import configure_logging
from config.settings import settings
from database.manager import db
from middleware.audit import AuditMiddleware
from middleware.cors_hardening import CORSHardeningMiddleware
from middleware.ddos_shield import DDoSShieldMiddleware
from middleware.docs_restriction import DocsRestrictionMiddleware
from middleware.https_enforcement import HTTPSEnforcementMiddleware
from middleware.rate_limit import RateLimitMiddleware
from middleware.request_id import RequestIDMiddleware
from middleware.request_size_limit import RequestSizeLimitMiddleware
from middleware.request_timeout import RequestTimeoutMiddleware
from middleware.security_headers import SecurityHeadersMiddleware
from services.anomaly_detector import AnomalyDetector
from services.audit_cleanup import get_audit_stats, purge_audit_logs
from services.auth import AuthService
from services.backup import BackupManager
from services.event_bus import event_bus
from services.log_manager import log_manager
from services.metrics import metrics
from services.observability import init_telemetry, setup_fastapi_instrumentation
from services.orchestrator import EnhancedOrchestrator
from services.orgs import Organization
from services.plugin_manager import plugin_manager
from services.scheduler import scheduler
from services.webhooks import webhook_manager
from services.websocket_manager import ws_manager

# ─── Configure structured logging ──────────────────────────────────────
configure_logging(
    level=settings.logging.level,
    log_dir=settings.logging.log_dir if settings.logging.structured else None,
    structured=settings.logging.structured,
    max_bytes=settings.logging.max_bytes,
    backup_count=settings.logging.backup_count,
)

logger = logging.getLogger("picoshogun.api")

# ─── Service instances (created before app for lifespan access) ─────
auth_service = AuthService()
orchestrator = EnhancedOrchestrator()
anomaly_detector = AnomalyDetector(db, alert_hub=None)  # alert_hub wired at startup

security = HTTPBearer()


# ─── Application lifecycle ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle.

    Starts: structured logging, OpenTelemetry, scheduler, anomaly detector.
    Stops: scheduler, anomaly detector, event bus, plugin manager, DB connections.
    """
    logger.info("PicoShogun starting up — version 0.1.0")

    # Enforce secure configuration — refuse to start with insecure defaults in production
    settings.assert_secure()

    # Log any non-critical config warnings
    config_issues = settings.validate()
    for issue in config_issues:
        if issue.startswith("CONFIG:"):
            logger.warning("CONFIG: %s", issue)

    # OpenTelemetry (graceful no-op if not configured)
    init_telemetry(service_name="picoshogun")
    setup_fastapi_instrumentation(app)
    logger.info("OpenTelemetry initialized (if endpoint configured)")

    # Wire alert_hub into anomaly detector now that all services are ready
    from services.alert_hub import AlertHub
    anomaly_detector.alert_hub = AlertHub()
    logger.info("Alert hub wired to anomaly detector")

    # Start background services
    anomaly_detector.start()
    scheduler.start()
    logger.info("Anomaly detector and scheduler started")

    # Cleanup expired API keys on startup
    expired_count = auth_service.cleanup_expired_keys()
    if expired_count:
        logger.info("Startup: deactivated %d expired API key(s)", expired_count)

    yield  # Application is running

    # ── Graceful shutdown ──
    logger.info("PicoShogun shutting down — stopping background services")
    anomaly_detector.stop()
    scheduler.stop()
    event_bus.shutdown()
    plugin_manager.unload_all()
    db.close()
    logger.info("All background services stopped")


app = FastAPI(
    title="PicoShogun Command Centre API",
    description="Command centre for the Pico Security Series",
    version="0.1.0",
    docs_url=settings.api.docs_url,
    redoc_url=settings.api.redoc_url,
    lifespan=lifespan,
)

# ─── Global exception handler ────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Return structured JSON for unhandled exceptions instead of HTML tracebacks."""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(
        "Unhandled exception on %s %s [request_id=%s]: %s",
        request.method, request.url.path, request_id, exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "detail": "An unexpected error occurred. Please try again later.",
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )

# ─── API v1 router ──────────────────────────────────────────────────────

api_v1 = APIRouter(prefix=settings.api.api_prefix)

# ─── Middleware (order matters — last added = outermost) ─────────────────
# Execution order (outermost → innermost):
#   SecurityHeaders → RequestID → RequestSizeLimit → DDoSShield
#   → GZip → CORS → RateLimit → Audit
app.add_middleware(AuditMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    max_requests_per_ip=100,
    max_requests_per_org=1000,
    window=60,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(DDoSShieldMiddleware, enabled=settings.security.ddos_shield_enabled)
app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=10 * 1024 * 1024)  # 10 MB
app.add_middleware(RequestIDMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# ── Security middleware ──────────────────────────────────────
app.add_middleware(RequestTimeoutMiddleware, timeout_seconds=30)
app.add_middleware(HTTPSEnforcementMiddleware, enabled=settings.is_production())
app.add_middleware(DocsRestrictionMiddleware, enabled=settings.is_production())
app.add_middleware(CORSHardeningMiddleware, block_wildcard_in_production=False)

# ─── Pydantic Models ──────────────────────────────────────────────────────

class ProjectRunRequest(BaseModel):
    project_id: str = Field(..., description="Project ID to run")
    timeout: int | None = Field(300, ge=10, le=3600)
    parameters: dict[str, Any] | None = Field(None)

class BatchRunRequest(BaseModel):
    project_ids: list[str] = Field(..., min_length=1, max_length=20)
    timeout: int | None = Field(300, ge=10, le=3600)

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: str | None = Field(None)
    role: str = Field("viewer", pattern="^(viewer|operator|admin)$")

class AlertResponse(BaseModel):
    id: int
    project_id: str | None
    alert_type: str
    severity: str
    message: str
    channel: str
    sent: bool
    created_at: datetime

class IntelligenceItem(BaseModel):
    id: int
    source_project: str
    intel_type: str
    severity: str
    data: dict
    confidence: float
    created_at: datetime

class ProjectStatus(BaseModel):
    id: str
    name: str
    category: str
    priority: int
    status: str
    version: str
    last_run: datetime | None
    run_count: int
    success_rate: float
    avg_duration: float

class SystemStatus(BaseModel):
    projects_total: int
    projects_active: int
    projects_failed: int
    active_threats: int
    pending_alerts: int
    threat_score: float
    system_health: str
    uptime_seconds: float
    timestamp: datetime

class HealthCheck(BaseModel):
    component: str
    status: str
    message: str
    latency_ms: float
    timestamp: datetime

class HealthReadiness(BaseModel):
    overall: str  # healthy | degraded | critical
    checks: list[HealthCheck]
    timestamp: datetime

# ─── Authentication ───────────────────────────────────────────────────────

class OrgTierUpgradeRequest(BaseModel):
    tier: str = Field(..., pattern="^(free|starter|pro|enterprise)$")

class OrgCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=50, pattern="^[a-z0-9-]+$")
    tier: str = Field("free", pattern="^(free|starter|pro|enterprise)$")

class OrgMemberInviteRequest(BaseModel):
    user_id: int = Field(..., gt=0)
    role: str = Field("member", pattern="^(admin|member|viewer)$")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    user = auth_service.validate_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    return user

# ─── Role-based access control ──────────────────────────────────────────────

def require_role(required: str):
    """FastAPI dependency that enforces minimum role level.

    Hierarchy: viewer < operator < admin
    Usage: user: dict = Depends(require_role("operator"))
    """
    role_levels = {"viewer": 0, "operator": 1, "admin": 2}
    min_level = role_levels.get(required, 0)

    async def _check_role(user: dict = Depends(get_current_user)):
        user_role = user.get("role", "viewer")
        if role_levels.get(user_role, 0) < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {required} (have: {user_role})"
            )
        return user
    return _check_role

async def get_current_org(
    api_key: str | None = Header(None, alias="X-Org-API-Key"),
    user: dict = Depends(get_current_user)
):
    """Resolve org context from API key header or user's default org.

    Security: If an API key is provided, it must belong to an org that the
    authenticated user is a member of. Cross-tenant API keys are rejected.
    """
    user_orgs = Organization.list_orgs_for_user(user["id"])

    if api_key and api_key.startswith("sk_"):
        org = Organization.get_by_api_key(api_key)
        if org:
            # Verify the user is a member of this org (tenant isolation)
            user_org_ids = {o["id"] for o in user_orgs} if user_orgs else set()
            if org["id"] not in user_org_ids:
                logger.warning(
                    "Cross-tenant org access rejected: user %s attempted org %s",
                    user.get("username"), org.get("slug"),
                )
                raise HTTPException(
                    status_code=403,
                    detail="API key does not belong to an organization you are a member of",
                )
            return org
        # API key not found — reject rather than falling back
        raise HTTPException(status_code=403, detail="Invalid organization API key")

    # No API key provided — fall back to user's first org
    if not user_orgs:
        raise HTTPException(status_code=403, detail="User not associated with any organization")
    return user_orgs[0]

# ─── Unversioned API Routes ───────────────────────────────────────────────

@app.get("/", tags=["Health"], response_class=HTMLResponse)
async def root():
    import pathlib
    html_path = pathlib.Path(__file__).parent.parent / "front" / "index.html"
    try:
        return html_path.read_text(encoding="utf-8")
    except Exception:
        return {"service": "PicoShogun API", "version": "0.1.0", "status": "operational", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/dashboard", tags=["Dashboard"], response_class=HTMLResponse)
async def dashboard():
    import pathlib
    html_path = pathlib.Path(__file__).parent.parent / "front" / "index.html"
    try:
        return html_path.read_text(encoding="utf-8")
    except Exception:
        raise HTTPException(status_code=404, detail="Dashboard not found") from None

# ─── Health Probes ────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthReadiness, tags=["Health"])
async def health_check():
    checks = orchestrator.get_health_checks()
    # Derive overall status from component statuses
    statuses = [c["status"] for c in checks]
    if any(s == "critical" for s in statuses):
        overall = "critical"
    elif any(s in ("warning", "degraded") for s in statuses):
        overall = "degraded"
    else:
        overall = "healthy"
    return HealthReadiness(
        overall=overall,
        checks=[HealthCheck(**c) for c in checks],
        timestamp=datetime.now(timezone.utc),
    )

@app.get("/health/live", tags=["Health"])
async def liveness_probe():
    """Kubernetes liveness probe — process is alive."""
    return {"status": "alive", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/health/ready", tags=["Health"])
async def readiness_probe():
    """Kubernetes readiness probe — can accept traffic."""
    try:
        db.execute_one("SELECT 1")
        return {"status": "ready", "timestamp": datetime.now(timezone.utc).isoformat()}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not_ready", "timestamp": datetime.now(timezone.utc).isoformat()})

@app.get("/health/history", tags=["Health"])
async def health_history(limit: int = 50, user: dict = Depends(get_current_user)):
    # Check if health_history table exists
    try:
        rows = db.execute("SELECT * FROM health_history ORDER BY checked_at DESC LIMIT ?", (limit,))
        return {"history": [dict(r) for r in rows] if rows else []}
    except Exception:
        return {"history": [], "note": "Health history not available"}

@app.get("/status", response_model=SystemStatus, tags=["Status"])
async def get_status(user: dict = Depends(get_current_user)):
    status = orchestrator.get_status()
    health = orchestrator.get_health_checks()
    active_threats = db.execute_one("SELECT COUNT(*) as c FROM intelligence WHERE severity IN ('critical', 'high')")
    pending_alerts = db.execute_one("SELECT COUNT(*) as c FROM alerts WHERE sent = 0")
    threat_data = db.execute_one("SELECT AVG(confidence) as avg_conf FROM intelligence WHERE severity IN ('critical', 'high')")
    uptime = status.get("uptime_seconds", 0)
    overall = "healthy"
    if any(c["status"] == "critical" for c in health):
        overall = "critical"
    elif any(c["status"] in ("warning", "degraded") for c in health):
        overall = "degraded"
    return SystemStatus(
        projects_total=status.get("projects_total", 0),
        projects_active=status.get("projects_active", 0),
        projects_failed=status.get("projects_failed", 0),
        active_threats=active_threats["c"] if active_threats else 0,
        pending_alerts=pending_alerts["c"] if pending_alerts else 0,
        threat_score=threat_data["avg_conf"] if threat_data and threat_data["avg_conf"] else 0.0,
        system_health=overall,
        uptime_seconds=uptime,
        timestamp=datetime.now(timezone.utc),
    )

# ─── Projects ─────────────────────────────────────────────────────────────

@app.get("/projects", response_model=list[ProjectStatus], tags=["Projects"])
async def list_projects(
    category: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org),
):
    projects = orchestrator.list_projects(category=category, status_filter=status_filter)
    return [ProjectStatus(**p) if isinstance(p, dict) else p for p in projects]

@app.get("/projects/{project_id}", response_model=ProjectStatus, tags=["Projects"])
async def get_project(
    project_id: str,
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org),
):
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@app.post("/projects/{project_id}/run", tags=["Projects"])
async def run_project(
    project_id: str,
    request: ProjectRunRequest | None = None,
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org),
):
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    timeout = request.timeout if request else 300
    result = orchestrator.run_project(project_id, timeout=timeout)
    return result

@app.post("/batch/run", tags=["Projects"])
async def run_batch(
    request: BatchRunRequest,
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org),
):
    results = []
    for pid in request.project_ids:
        try:
            result = orchestrator.run_project(pid, timeout=request.timeout)
            results.append({"project_id": pid, "status": "completed", "result": result})
        except Exception as e:
            results.append({"project_id": pid, "status": "failed", "error": str(e)})
    return {"results": results, "total": len(results)}

@app.get("/projects/{project_id}/export", tags=["Projects"])
async def export_project(
    project_id: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org),
):
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if format == "csv":
        import csv as csv_module
        import io
        output = io.StringIO()
        writer = csv_module.DictWriter(output, fieldnames=project.keys())
        writer.writeheader()
        writer.writerow(project)
        return PlainTextResponse(content=output.getvalue(), media_type="text/csv")
    return project

# ─── Intelligence ─────────────────────────────────────────────────────────

@app.get("/intelligence", response_model=list[IntelligenceItem], tags=["Intelligence"])
async def list_intelligence(
    source: str | None = None,
    severity: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    user: dict = Depends(get_current_user),
):
    query = "SELECT * FROM intelligence WHERE 1=1"
    params = []
    if source:
        query += " AND source_project = ?"
        params.append(source)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, tuple(params))
    return [IntelligenceItem(**dict(r)) for r in rows] if rows else []

@app.get("/intelligence/correlations/{project_id}", tags=["Intelligence"])
async def get_correlations(project_id: str, user: dict = Depends(get_current_user)):
    correlations = db.execute(
        "SELECT * FROM intelligence WHERE source_project = ? AND confidence > 0.7 ORDER BY confidence DESC",
        (project_id,)
    )
    return {"project_id": project_id, "correlations": [dict(c) for c in correlations] if correlations else []}

@app.get("/intelligence/threat-score", tags=["Intelligence"])
async def get_threat_score(user: dict = Depends(get_current_user)):
    # Aggregate threat score from intelligence
    result = db.execute_one("SELECT AVG(confidence) as avg_score, COUNT(*) as total FROM intelligence WHERE severity IN ('critical', 'high')")
    return {
        "threat_score": round(result["avg_score"], 3) if result and result["avg_score"] else 0.0,
        "total_threats": result["total"] if result else 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ─── Alerts ───────────────────────────────────────────────────────────────

@app.get("/alerts", response_model=list[AlertResponse], tags=["Alerts"])
async def list_alerts(
    severity: str | None = None,
    channel: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    user: dict = Depends(get_current_user),
):
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if channel:
        query += " AND channel = ?"
        params.append(channel)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = db.execute(query, tuple(params))
    return [AlertResponse(**dict(r)) for r in rows] if rows else []

@app.post("/alerts/{alert_id}/acknowledge", tags=["Alerts"])
async def acknowledge_alert(alert_id: int, user: dict = Depends(get_current_user)):
    result = db.execute_one("UPDATE alerts SET sent = 1 WHERE id = ? RETURNING id", (alert_id,))
    if not result:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged", "alert_id": alert_id, "note": "Marked as sent (acknowledged)"}

# ─── Reports ──────────────────────────────────────────────────────────────

@app.get("/reports/summary", tags=["Reports"])
async def get_summary_report(user: dict = Depends(get_current_user)):
    project_stats = orchestrator.get_status()
    health = orchestrator.get_health_checks()
    return {
        "projects": project_stats,
        "health": health,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/reports/project/{project_id}", tags=["Reports"])
async def get_project_report(project_id: str, user: dict = Depends(get_current_user)):
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"project": project, "timestamp": datetime.now(timezone.utc).isoformat()}

# ─── Metrics ──────────────────────────────────────────────────────────────

@app.get("/metrics", tags=["Metrics"])
async def get_metrics(
    detailed: bool = False,
    user: dict = Depends(get_current_user),
):
    metrics_data = metrics.to_dict()
    if not detailed:
        return metrics_data
    # Add additional details for detailed view
    metrics_data["projects"] = orchestrator.get_status()
    metrics_data["health"] = orchestrator.get_health_checks()
    return metrics_data

@app.get("/metrics/prometheus", tags=["Metrics"])
async def get_prometheus_metrics():
    """Prometheus scraper endpoint — unauthenticated by design."""
    return Response(content=metrics.to_prometheus(), media_type="text/plain")

@app.get("/metrics/json", tags=["Metrics"])
async def get_json_metrics(user: dict = Depends(get_current_user)):
    return metrics.to_dict()

# ─── Authentication ───────────────────────────────────────────────────────

@app.post("/auth/register", tags=["Authentication"])
async def register(request: RegisterRequest):
    try:
        user_id = auth_service.create_user(username=request.username, password=request.password, email=request.email, role=request.role)
        if not user_id:
            raise HTTPException(status_code=409, detail="Username already exists")
        return {"user_id": user_id, "username": request.username, "role": request.role}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

@app.post("/auth/login", tags=["Authentication"])
async def login(username: str, password: str):
    token = auth_service.authenticate(username, password)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Decode token to get user info for the response
    user_info = auth_service.validate_token(token)
    return {"access_token": token, "token_type": "bearer", "user_id": user_info.get("id"), "role": user_info.get("role")}

@app.post("/auth/api-key", tags=["Authentication"])
async def create_api_key(
    request: dict,
    user: dict = Depends(get_current_user),
):
    key_name = request.get("name", "default")
    api_key = auth_service.create_api_key(user["id"], name=key_name)
    return {"api_key": api_key, "name": key_name}

@app.post("/auth/api-key/{key_id}/rotate", tags=["Authentication"])
async def rotate_api_key(
    key_id: int,
    user: dict = Depends(get_current_user),
):
    new_key = auth_service.rotate_api_key(key_id, user["id"])
    if not new_key:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"api_key": new_key, "message": "API key rotated successfully"}

@app.delete("/auth/api-key/{key_id}", tags=["Authentication"], status_code=204)
async def revoke_api_key(
    key_id: int,
    user: dict = Depends(get_current_user),
):
    success = auth_service.revoke_api_key(key_id, user["id"])
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")

# ─── Plugins ─────────────────────────────────────────────────────────────

@app.get("/plugins", tags=["Plugins"])
async def list_plugins(user: dict = Depends(get_current_user)):
    return {"plugins": plugin_manager.get_status()}

# ─── Webhooks ─────────────────────────────────────────────────────────────

@app.get("/webhooks", tags=["Webhooks"])
async def list_webhooks(user: dict = Depends(get_current_user)):
    return {"webhooks": {name: {"url": w.url, "events": w.events, "active": w.active} for name, w in webhook_manager.webhooks.items()}}

@app.post("/webhooks", tags=["Webhooks"])
async def create_webhook(
    request: dict,
    user: dict = Depends(require_role("operator")),
):
    url = request.get("url")
    events = request.get("events", ["*"])
    secret = request.get("secret")
    name = request.get("name", "default")
    try:
        webhook_id = webhook_manager.create(name=name, url=url, events=events, secret=secret)
        return {"id": webhook_id, "url": url, "events": events}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

# ─── Scheduler ────────────────────────────────────────────────────────────

@app.get("/scheduler/jobs", tags=["Scheduler"])
async def list_scheduler_jobs(user: dict = Depends(get_current_user)):
    return {"jobs": scheduler.get_status()}

@app.post("/scheduler/jobs", tags=["Scheduler"])
async def create_scheduler_job(
    request: dict,
    user: dict = Depends(require_role("operator")),
):
    try:
        job_id = scheduler.add_job(
            name=request.get("name", "unnamed"),
            cron=request.get("cron", "*/5 * * * *"),
            command=request.get("command", "batch"),
            params=request.get("params", {}),
            enabled=request.get("enabled", True)
        )
        return {"job_id": job_id, "status": "scheduled"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from None

@app.patch("/scheduler/jobs/{job_id}/enable", tags=["Scheduler"])
async def enable_scheduler_job(job_id: str, user: dict = Depends(require_role("operator"))):
    scheduler.enable_job(int(job_id))
    return {"job_id": job_id, "status": "enabled"}

@app.patch("/scheduler/jobs/{job_id}/disable", tags=["Scheduler"])
async def disable_scheduler_job(job_id: str, user: dict = Depends(require_role("operator"))):
    scheduler.disable_job(int(job_id))
    return {"job_id": job_id, "status": "disabled"}

@app.delete("/scheduler/jobs/{job_id}", tags=["Scheduler"], status_code=204)
async def delete_scheduler_job(job_id: str, user: dict = Depends(require_role("admin"))):
    scheduler.remove_job(int(job_id))

# ─── Backup ───────────────────────────────────────────────────────────────

@app.post("/backup", tags=["Backup"])
async def create_backup(user: dict = Depends(require_role("admin"))):
    backup_mgr = BackupManager()
    result = backup_mgr.create_backup()
    return {"status": "backup_created", "path": result}

@app.get("/backups", tags=["Backup"])
async def list_backups(user: dict = Depends(get_current_user)):
    backup_mgr = BackupManager()
    backups = backup_mgr.list_backups()
    return {"backups": backups}

# ─── Log Management ───────────────────────────────────────────────────────

@app.get("/logs/stats", tags=["Logs"])
async def get_log_stats(user: dict = Depends(get_current_user)):
    return log_manager.get_stats()

@app.post("/logs/rotate", tags=["Logs"])
async def rotate_logs(user: dict = Depends(get_current_user)):
    log_manager.rotate()
    return {"status": "rotated"}

@app.get("/logs", tags=["Logs"])
async def get_logs(
    level: str | None = None,
    source: str | None = None,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(get_current_user),
):
    return {"logs": log_manager.get_stats()}

# ─── Audit Log Management ────────────────────────────────────────────────

@app.get("/audit/stats", tags=["Audit"])
async def audit_stats(user: dict = Depends(get_current_user)):
    """Get audit log statistics and retention policy."""
    return get_audit_stats()

@app.post("/audit/purge", tags=["Audit"])
async def purge_audit(
    retention_days: int | None = None,
    dry_run: bool = False,
    user: dict = Depends(require_role("admin")),
):
    """Purge audit logs older than retention period.

    Admin-only. Default uses per-severity retention policy.
    Set dry_run=true to preview what would be deleted.
    """
    return purge_audit_logs(retention_days=retention_days, dry_run=dry_run)


# ─── Event Bus ────────────────────────────────────────────────────────────

@app.get("/events/history", tags=["Events"])
async def get_event_history(
    event_type: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(get_current_user)
):
    events = event_bus.get_history(event_type, limit)
    return [
        {
            "id": e.id,
            "type": e.type,
            "source": e.source,
            "payload": e.payload,
            "timestamp": e.timestamp.isoformat(),
            "priority": e.priority
        }
        for e in events
    ]

# ─── Organizations ────────────────────────────────────────────────────────

@app.get("/orgs", tags=["Organizations"])
async def list_orgs(user: dict = Depends(get_current_user)):
    """List organizations the user belongs to."""
    orgs = Organization.list_orgs_for_user(user["id"])
    return {
        "orgs": orgs,
        "count": len(orgs)
    }

@app.get("/orgs/{org_id}", tags=["Organizations"])
async def get_org(org_id: int, user: dict = Depends(get_current_user)):
    """Get organization details + usage."""
    orgs = Organization.list_orgs_for_user(user["id"])
    org = next((o for o in orgs if o["id"] == org_id), None)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    usage = Organization.get_usage(org_id)
    return {
        "id": org["id"],
        "name": org["name"],
        "slug": org["slug"],
        "tier": org["tier"],
        "api_key": org["api_key"][:12] + "..." if len(org.get("api_key", "")) > 20 else "hidden",
        "is_active": org["is_active"],
        "created_at": org["created_at"],
        "usage": usage
    }

@app.post("/orgs", tags=["Organizations"])
async def create_org(
    request: OrgCreateRequest,
    user: dict = Depends(get_current_user)
):
    """Create a new organization."""
    org_id = Organization.create(
        name=request.name,
        slug=request.slug,
        owner_user_id=user["id"],
        tier=request.tier
    )
    if not org_id:
        raise HTTPException(status_code=409, detail="Organization slug already exists")
    return {
        "id": org_id,
        "name": request.name,
        "slug": request.slug,
        "tier": request.tier
    }

@app.get("/orgs/{org_id}/members", tags=["Organizations"])
async def list_org_members(
    org_id: int,
    user: dict = Depends(get_current_user)
):
    """List members of an organization."""
    orgs = Organization.list_orgs_for_user(user["id"])
    if not any(o["id"] == org_id for o in orgs):
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    members = Organization.get_members(org_id)
    return {"members": members, "count": len(members)}

@app.get("/orgs/{org_id}/usage", tags=["Organizations"])
async def get_org_usage(
    org_id: int,
    user: dict = Depends(get_current_user)
):
    """Get current usage vs limits for an organization."""
    orgs = Organization.list_orgs_for_user(user["id"])
    if not any(o["id"] == org_id for o in orgs):
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    return Organization.get_usage(org_id)

@app.post("/orgs/{org_id}/upgrade", tags=["Organizations"])
async def upgrade_org_tier(
    org_id: int,
    request: OrgTierUpgradeRequest,
    user: dict = Depends(require_role("admin"))
):
    """Upgrade organization subscription tier."""
    orgs = Organization.list_orgs_for_user(user["id"])
    org = next((o for o in orgs if o["id"] == org_id), None)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if org.get("user_role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can upgrade tier")
    success = Organization.update_tier(org_id, request.tier)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid tier")
    return {"message": f"Organization upgraded to {request.tier}", "tier": request.tier}

# ─── FRONT-03: Serve static files ───────────────────────────────────────────
front_dir = Path(__file__).parent.parent / "front"
if front_dir.exists():
    app.mount("/front", StaticFiles(directory=str(front_dir)), name="front")

# ─── Anomaly Detection ────────────────────────────────────────────────────

@app.get("/anomaly/rules", tags=["Anomaly"])
async def list_anomaly_rules(user: dict = Depends(get_current_user)):
    """List all configured anomaly detection rules."""
    return anomaly_detector.get_rules()

@app.get("/anomaly/alerts", tags=["Anomaly"])
async def list_anomaly_alerts(limit: int = Query(50, ge=1, le=200), user: dict = Depends(get_current_user)):
    """List recent anomaly alerts."""
    return anomaly_detector.get_alerts(limit=limit)

@app.post("/anomaly/check", tags=["Anomaly"])
async def trigger_anomaly_check(user: dict = Depends(get_current_user)):
    """Manually trigger an anomaly detection cycle."""
    alerts = anomaly_detector.check_rules()
    return {"triggered": len(alerts), "alerts": [{"rule_id": a.rule_id, "metric": a.metric_name, "value": a.value, "threshold": a.threshold, "severity": a.severity} for a in alerts]}

@app.patch("/anomaly/rules/{rule_id}", tags=["Anomaly"])
async def update_anomaly_rule(rule_id: str, enabled: bool | None = None, threshold: float | None = None, user: dict = Depends(get_current_user)):
    """Update an anomaly detection rule (enable/disable, change threshold)."""
    updates = {}
    if enabled is not None:
        updates["enabled"] = enabled
    if threshold is not None:
        updates["threshold"] = threshold
    if not updates:
        raise HTTPException(400, "No updates provided")
    if not anomaly_detector.update_rule(rule_id, **updates):
        raise HTTPException(404, f"Rule '{rule_id}' not found")
    return {"status": "updated", "rule_id": rule_id}

# ─── Startup/shutdown handled by lifespan context manager (see above) ────

# ─── API v1 Routes ────────────────────────────────────────────────────────

@api_v1.get("/dashboard/summary", tags=["Dashboard"])
async def dashboard_summary(user: dict = Depends(get_current_user)):
    """Aggregated dashboard data — single-call overview for the command centre."""
    status = orchestrator.get_status()
    health = orchestrator.get_health_checks()
    recent_projects = orchestrator.list_projects(limit=10)
    recent_intel = db.execute(
        "SELECT id, source_project, intel_type, severity, confidence, created_at FROM intelligence ORDER BY created_at DESC LIMIT 10",
        ()
    )
    recent_alerts = db.execute(
        "SELECT id, project_id, alert_type, severity, message, channel, sent, created_at FROM alerts ORDER BY created_at DESC LIMIT 10",
        ()
    )
    pending_alerts = db.execute_one("SELECT COUNT(*) as c FROM alerts WHERE sent = 0")
    health_overall = "healthy"
    if any(c["status"] == "critical" for c in health):
        health_overall = "critical"
    elif any(c["status"] in ("warning", "degraded") for c in health):
        health_overall = "degraded"
    return {
        "status": status,
        "health": {"overall": health_overall, "checks": health},
        "recent_projects": [dict(p) for p in recent_projects],
        "recent_intelligence": [dict(i) for i in recent_intel] if recent_intel else [],
        "recent_alerts": [dict(a) for a in recent_alerts] if recent_alerts else [],
        "pending_alerts_count": pending_alerts["c"] if pending_alerts else 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ─── L2 Supply Chain Scanner Endpoints ──────────────────────────────────

class ScanRequest(BaseModel):
    target: str = Field(..., description="Path to project directory to scan")
    rules: list[str] | None = Field(None, description="Subset of rule IDs to run")
    format: str = Field("json", pattern="^(json|sarif)$")

class ScanResponse(BaseModel):
    scan_id: str
    timestamp: str
    target: str
    engine_version: str
    findings_count: int
    findings: list[dict[str, Any]]
    stats: dict[str, Any]

@api_v1.post("/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    request: ScanRequest,
    user: dict = Depends(require_role("viewer"))
):
    """Run an L2 supply chain scan on a project directory."""
    from pathlib import Path as _Path

    from pico_dome.L2_validation.engine import create_default_engine as _create_engine

    target = _Path(request.target).resolve()
    if not target.exists():
        raise HTTPException(status_code=400, detail=f"Target path does not exist: {request.target}")

    engine = _create_engine()
    result = engine.scan(target, rules=request.rules)

    return ScanResponse(
        scan_id=result.scan_id,
        timestamp=result.timestamp,
        target=result.target,
        engine_version=result.engine_version,
        findings_count=len(result.findings),
        findings=[f.to_dict() for f in result.findings],
        stats=result.stats.to_dict(),
    )

@api_v1.get("/scans/rules", tags=["Scans"])
async def list_scan_rules(user: dict = Depends(get_current_user)):
    """List available L2 supply chain scanner rules."""
    from pico_dome.L2_validation.engine import create_default_engine as _create_engine
    engine = _create_engine()
    return {"rules": engine.list_rules()}

# ─── L3 Sandbox Endpoints ─────────────────────────────────────────────────

class SandboxRunRequest(BaseModel):
    command: list[str] = Field(..., description="Command and arguments to execute under sandbox")
    policy_file: str | None = Field(None, description="Path to policy YAML file (default: built-in)")
    timeout: float | None = Field(None, ge=1, le=3600, description="Override wall-time limit (seconds)")
    format: str = Field("json", pattern="^(json|sarif)$")

class SandboxRunResponse(BaseModel):
    run_id: str
    timestamp: str
    command: list[str]
    overall_verdict: str
    exit_code: int | None
    duration_ms: int
    events: list[dict[str, Any]]
    policy_name: str

@api_v1.post("/sandboxes", response_model=SandboxRunResponse, tags=["Sandbox"])
async def run_sandbox(
    request: SandboxRunRequest,
    user: dict = Depends(require_role("operator"))
):
    """Run a command under L3 sandbox policy."""
    from pathlib import Path as _Path

    from pico_dome.L3_execution.engine import sandbox_run
    from pico_dome.L3_execution.policy_loader import load_policy as _load_policy

    policy = _load_policy(
        _Path(request.policy_file) if request.policy_file else None
    )

    result = sandbox_run(
        command=request.command,
        policy=policy,
        timeout=request.timeout,
    )

    return SandboxRunResponse(
        run_id=result.run_id,
        timestamp=result.timestamp,
        command=result.command,
        overall_verdict=result.overall_verdict.value,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        events=[
            {
                "rule_id": e.rule_id.value if hasattr(e.rule_id, "value") else str(e.rule_id),
                "verdict": e.verdict.value,
                "operation": e.operation,
                "detail": e.detail,
                "path": e.path,
                "address": e.address,
            }
            for e in result.events
        ],
        policy_name=policy.name,
    )

@api_v1.get("/sandboxes/policies/default", tags=["Sandbox"])
async def get_default_policy(user: dict = Depends(get_current_user)):
    """Get the default L3 sandbox policy."""
    from pico_dome.L3_execution.policy_loader import load_policy as _load_policy
    policy = _load_policy()
    return policy.to_dict()

# ─── Mount v1 router ─────────────────────────────────────────────────────
app.include_router(api_v1)

# ─── WebSocket with Authentication ─────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str | None = None):
    """Real-time WebSocket for live events with optional token auth.

    Clients can authenticate by:
    1. Passing ?token=<jwt> in the WebSocket URL
    2. Sending {"action": "auth", "token": "<jwt>"} after connecting
    """
    # Validate token if provided via query param
    user = None
    if token:
        user = auth_service.validate_token(token)
        if not user:
            await websocket.close(code=4001, reason="Invalid authentication token")
            return

    await ws_manager.connect(websocket, channels=["*"] if not token else ["*"])

    # If not authenticated via query param, require auth message
    authenticated = user is not None

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "auth" and not authenticated:
                    auth_token = msg.get("token", "")
                    user = auth_service.validate_token(auth_token)
                    if user:
                        authenticated = True
                        await websocket.send_text(json.dumps({"type": "auth", "status": "ok", "user_id": user.get("user_id")}))
                    else:
                        await websocket.send_text(json.dumps({"type": "auth", "status": "denied"}))
                        await websocket.close(code=4001, reason="Invalid authentication token")
                        return
                elif msg.get("action") == "subscribe" and authenticated:
                    channels = msg.get("channels", ["*"])
                    ws_manager.subscribe(websocket, channels)
                elif msg.get("action") == "subscribe" and not authenticated:
                    await websocket.send_text(json.dumps({"type": "error", "message": "Authentication required"}))
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

if __name__ == "__main__":
    import signal

    import uvicorn

    def _graceful_shutdown(signum, frame):
        """Handle SIGTERM/SIGINT by stopping background services before exit."""
        sig_name = signal.strsignal(signum) or str(signum)
        logger.info("Received %s — initiating graceful shutdown", sig_name)
        anomaly_detector.stop()
        scheduler.stop()
        event_bus.shutdown()
        plugin_manager.unload_all()
        db.close()
        logger.info("Graceful shutdown complete — exiting")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT, _graceful_shutdown)

    uvicorn.run(
        app,
        host=settings.api.host,
        port=settings.api.port,
        workers=settings.api.workers,
        reload=settings.api.reload
    )
