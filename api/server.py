"""Enterprise REST API for Secdev_kimi with FastAPI."""
from fastapi import Response, FastAPI, APIRouter, HTTPException, Depends, Query, Header, BackgroundTasks, status, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
import json
import logging
from pathlib import Path

from config.settings import settings
from database.manager import db
from services.orchestrator import EnhancedOrchestrator
from services.auth import AuthService
from services.orgs import Organization
from services.plugin_manager import plugin_manager
from services.webhooks import webhook_manager
from services.metrics import metrics
from services.scheduler import scheduler
from services.backup import BackupManager
from services.log_manager import log_manager
from services.event_bus import event_bus
from services.websocket_manager import ws_manager
from services.anomaly_detector import AnomalyDetector
from middleware.rate_limit import RateLimitMiddleware
from middleware.audit import AuditMiddleware
from middleware.ddos_shield import DDoSShieldMiddleware
from services.observability import init_telemetry, setup_fastapi_instrumentation

logger = logging.getLogger("SecdevKimi.API")

app = FastAPI(
    title="Secdev_kimi Enterprise API",
    description="Enterprise-grade security lab orchestration and intelligence platform",
    version="2.13.0",
    docs_url=settings.api.docs_url,
    redoc_url=settings.api.redoc_url,
)

# Create router with prefix
api_v1 = APIRouter(prefix=settings.api.api_prefix)

# Note: routes defined below with @app.get will need @api_v1.get for prefix to apply
# For now, legacy routes stay on app directly; migrate in future refactor.

# Middleware
app.add_middleware(DDoSShieldMiddleware, enabled=settings.security.ddos_shield_enabled)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    RateLimitMiddleware,
    max_requests_per_ip=100,
    max_requests_per_org=1000,
    window=60,
)
app.add_middleware(AuditMiddleware)

security = HTTPBearer()
auth_service = AuthService()
orchestrator = EnhancedOrchestrator()
anomaly_detector = AnomalyDetector(db, alert_hub=None)  # alert_hub wired after startup

# ─── Pydantic Models ──────────────────────────────────────────────────────

class ProjectRunRequest(BaseModel):
    project_id: str = Field(..., description="Project ID to run")
    timeout: Optional[int] = Field(300, ge=10, le=3600)
    parameters: Optional[Dict[str, Any]] = Field(None)

class BatchRunRequest(BaseModel):
    project_ids: List[str] = Field(..., min_length=1, max_length=20)
    timeout: Optional[int] = Field(300, ge=10, le=3600)

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: Optional[str] = Field(None)
    role: str = Field("viewer", pattern="^(viewer|operator|admin)$")

class AlertResponse(BaseModel):
    id: int
    project_id: Optional[str]
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
    data: Dict
    confidence: float
    created_at: datetime

class ProjectStatus(BaseModel):
    id: str
    name: str
    category: str
    priority: int
    status: str
    version: str
    last_run: Optional[datetime]
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
    checks: List[HealthCheck]
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
    api_key: Optional[str] = Header(None, alias="X-Org-API-Key"),
    user: dict = Depends(get_current_user)
):
    """Resolve org context from API key header or user's default org."""
    if api_key and api_key.startswith("sk_"):
        org = Organization.get_by_api_key(api_key)
        if org:
            return org
    # Fall back to user's first org
    orgs = Organization.list_orgs_for_user(user["id"])
    if not orgs:
        raise HTTPException(status_code=403, detail="User not associated with any organization")
    return orgs[0]

# ─── API Routes ─────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"], response_class=HTMLResponse)
async def root():
    import pathlib
    html_path = pathlib.Path(__file__).parent.parent / "front" / "index.html"
    try:
        return html_path.read_text(encoding="utf-8")
    except Exception:
        return {"service": "Shogun Enterprise API", "version": "2.13.0", "status": "operational", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/dashboard", tags=["Dashboard"], response_class=HTMLResponse)
async def dashboard():
    """Serve the enterprise command centre dashboard."""
    import pathlib
    html_path = pathlib.Path(__file__).parent.parent / "front" / "index.html"
    try:
        return html_path.read_text(encoding="utf-8")
    except Exception:
        raise HTTPException(status_code=404, detail="Dashboard not found")

@app.get("/api/v1/dashboard/summary", tags=["Dashboard"])
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
    return {
        "overall": overall,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/health/history", tags=["Health"])
async def health_history(limit: int = 50, user: dict = Depends(get_current_user)):
    """Return last N health check snapshots for trend analysis."""
    rows = db.execute("""
        SELECT component, status, message, latency_ms, created_at
        FROM health_checks
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))
    return [{"component": r[0], "status": r[1], "message": r[2], "latency_ms": r[3], "timestamp": r[4]} for r in rows]

@app.get("/status", response_model=SystemStatus, tags=["Status"])
async def get_status(user: dict = Depends(get_current_user)):
    return orchestrator.get_status()

# ─── Projects ───────────────────────────────────────────────────────────────

@app.get("/projects", response_model=List[ProjectStatus], tags=["Projects"])
async def list_projects(
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org)
):
    if org:
        projects = orchestrator.list_projects(category, status, limit, offset)
        # Filter to org's projects
        org_project_ids = {p["project_id"] for p in Organization.get_usage(org["id"]).get("projects", [])}
        if org_project_ids:
            projects = [p for p in projects if p.get("id") in org_project_ids]
        return projects
    return orchestrator.list_projects(category, status, limit, offset)

@app.get("/projects/{project_id}", response_model=ProjectStatus, tags=["Projects"])
async def get_project(
    project_id: str, 
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org)
):
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
    # Verify project belongs to org
    if org:
        org_projects = Organization.get_usage(org["id"]).get("projects", [])
        if not any(p.get("project_id") == project_id for p in org_projects):
            raise HTTPException(status_code=403, detail="Project not in this organization")
    return project

@app.post("/projects/{project_id}/run", tags=["Projects"])
async def run_project(
    project_id: str,
    request: ProjectRunRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_role("operator")),
    org: dict = Depends(get_current_org)
):
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
    # Check org quota
    if org and not Organization.can_run(org["id"]):
        raise HTTPException(status_code=429, detail="Organization run quota exceeded")
    background_tasks.add_task(orchestrator.run_project, project_id, request.timeout)
    return {"message": f"Project {project_id} queued for execution", "project_id": project_id}

@app.post("/batch/run", tags=["Projects"])
async def run_batch(
    request: BatchRunRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org)
):
    # Check org quota for batch
    if org:
        remaining = Organization.TIERS.get(org.get("tier", "free"), Organization.TIERS["free"])["runs_per_day"]
        usage = Organization.get_usage(org["id"])
        runs_today = usage.get("runs_today", {}).get("used", 0)
        if runs_today + len(request.project_ids) > remaining:
            raise HTTPException(status_code=429, detail="Batch run would exceed organization quota")
    background_tasks.add_task(orchestrator.run_batch, request.project_ids, request.timeout)
    return {"message": f"Batch run queued for {len(request.project_ids)} projects"}

@app.get("/projects/{project_id}/export", tags=["Projects"])
async def export_project(
    project_id: str,
    format: str = Query("json", pattern="^(json|csv)$"),
    user: dict = Depends(get_current_user),
    org: dict = Depends(get_current_org)
):
    """Export all data for a project: config, runs, alerts, intelligence.
    
    Returns a comprehensive JSON dump of everything related to the project.
    CSV format exports runs table only.
    """
    project = orchestrator.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
    
    # Verify project belongs to org
    if org:
        org_projects = Organization.get_usage(org["id"]).get("projects", [])
        if not any(p.get("project_id") == project_id for p in org_projects):
            raise HTTPException(status_code=403, detail="Project not in this organization")
    
    # Fetch related data from DB
    runs = db.execute(
        "SELECT * FROM project_runs WHERE project_id = ? ORDER BY run_start DESC",
        (project_id,)
    )
    alerts = db.execute(
        "SELECT * FROM alerts WHERE project_id = ? ORDER BY created_at DESC",
        (project_id,)
    )
    intelligence = db.execute(
        "SELECT * FROM intelligence WHERE source_project = ? ORDER BY created_at DESC",
        (project_id,)
    )
    metrics_data = db.execute(
        "SELECT * FROM metrics WHERE project_id = ? ORDER BY created_at DESC",
        (project_id,)
    )
    
    export_data = {
        "export_version": "2.9.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "project_id": project_id,
        "project_config": project,
        "project_runs": [dict(r) for r in runs],
        "alerts": [dict(r) for r in alerts],
        "intelligence": [dict(r) for r in intelligence],
        "metrics": [dict(r) for r in metrics_data],
    }
    
    if format == "csv":
        import csv
        import io
        from fastapi.responses import PlainTextResponse
        
        output = io.StringIO()
        if runs:
            writer = csv.DictWriter(output, fieldnames=dict(runs[0]).keys())
            writer.writeheader()
            writer.writerows([dict(r) for r in runs])
        else:
            output.write("No runs found for this project.\n")
        
        output.seek(0)
        filename = f"{project_id}_runs.csv"
        return PlainTextResponse(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    
    return export_data

# ─── Intelligence ───────────────────────────────────────────────────────────

@app.get("/intelligence", response_model=List[IntelligenceItem], tags=["Intelligence"])
async def list_intelligence(
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    user: dict = Depends(get_current_user)
):
    return orchestrator.list_intelligence(severity, source, limit)

@app.get("/intelligence/correlations/{project_id}", tags=["Intelligence"])
async def get_correlations(project_id: str, user: dict = Depends(get_current_user)):
    return orchestrator.get_correlations(project_id)

@app.get("/intelligence/threat-score", tags=["Intelligence"])
async def get_threat_score(user: dict = Depends(get_current_user)):
    return orchestrator.get_threat_score()

# ─── Alerts ─────────────────────────────────────────────────────────────────

@app.get("/alerts", response_model=List[AlertResponse], tags=["Alerts"])
async def list_alerts(
    sent: Optional[bool] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    user: dict = Depends(get_current_user)
):
    return orchestrator.list_alerts(sent, severity, limit)

@app.post("/alerts/{alert_id}/acknowledge", tags=["Alerts"])
async def acknowledge_alert(alert_id: int, user: dict = Depends(get_current_user)):
    success = orchestrator.acknowledge_alert(alert_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    
    event_bus.publish(
        "alert.acknowledged",
        {"alert_id": alert_id},
        source="api",
        priority="normal"
    )
    
    return {"message": f"Alert {alert_id} acknowledged"}

# ─── Reports ────────────────────────────────────────────────────────────────

@app.get("/reports/summary", tags=["Reports"])
async def get_summary_report(user: dict = Depends(get_current_user)):
    return orchestrator.generate_summary_report()

@app.get("/reports/project/{project_id}", tags=["Reports"])
async def get_project_report(project_id: str, user: dict = Depends(get_current_user)):
    report = orchestrator.generate_project_report(project_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Project {project_id} not found")
    return report

# ─── Metrics ─────────────────────────────────────────────────────────────────

@app.get("/metrics", tags=["Metrics"])
async def get_metrics(
    project_id: Optional[str] = Query(None),
    metric_name: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(get_current_user)
):
    real_counts = db.execute_one("""
        SELECT 
            COUNT(*) as total_runs,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
            SUM(alerts_generated) as alerts_fired
        FROM project_runs
    """)
    return {
        "project_runs_total": real_counts["total_runs"] if real_counts else 0,
        "project_runs_completed": real_counts["completed"] if real_counts else 0,
        "project_runs_failed": real_counts["failed"] if real_counts else 0,
        "alerts_fired": real_counts["alerts_fired"] if real_counts else 0,
        "metrics_db": orchestrator.get_metrics(project_id, metric_name, limit)
    }

# ─── Authentication ─────────────────────────────────────────────────────────

@app.post("/auth/register", tags=["Authentication"])
async def register(request: RegisterRequest):
    user_id = auth_service.create_user(
        username=request.username,
        password=request.password,
        email=request.email,
        role=request.role
    )
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists"
        )
    return {"user_id": user_id, "username": request.username, "role": request.role}

@app.post("/auth/login", tags=["Authentication"])
async def login(username: str, password: str):
    token = auth_service.authenticate(username, password)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/api-key", tags=["Authentication"])
async def create_api_key(
    name: str,
    permissions: str = "read",
    user: dict = Depends(get_current_user)
):
    api_key = auth_service.create_api_key(user["id"], name, permissions)
    return {"api_key": api_key, "name": name, "permissions": permissions}

@app.post("/auth/api-key/{key_id}/rotate", tags=["Authentication"])
async def rotate_api_key(
    key_id: int,
    user: dict = Depends(get_current_user)
):
    new_key = auth_service.rotate_api_key(key_id, user["id"])
    if not new_key:
        raise HTTPException(status_code=404, detail="API key not found or not owned by this user")
    return {"new_api_key": new_key, "message": "API key rotated successfully"}

@app.delete("/auth/api-key/{key_id}", tags=["Authentication"], status_code=204)
async def revoke_api_key(
    key_id: int,
    user: dict = Depends(get_current_user)
):
    success = auth_service.revoke_api_key(key_id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    return None

# ─── Plugins ──────────────────────────────────────────────────────────────

@app.get("/plugins", tags=["Plugins"])
async def list_plugins(user: dict = Depends(get_current_user)):
    return plugin_manager.get_status()

# ─── Webhooks ─────────────────────────────────────────────────────────────

@app.get("/webhooks", tags=["Webhooks"])
async def list_webhooks(user: dict = Depends(get_current_user)):
    rows = db.execute("SELECT id, name, url, events, active, created_at FROM webhooks")
    return [dict(r) for r in rows]

@app.post("/webhooks", tags=["Webhooks"])
async def create_webhook(
    name: str,
    url: str,
    events: List[str],
    user: dict = Depends(require_role("operator"))
):
    webhook_id = webhook_manager.create(name, url, events)
    
    event_bus.publish(
        "webhook.created",
        {"id": webhook_id, "name": name, "url": url, "events": events},
        source="api",
        priority="normal"
    )
    
    return {"id": webhook_id, "name": name, "url": url, "events": events}

# ─── Scheduler ────────────────────────────────────────────────────────────

@app.get("/scheduler/jobs", tags=["Scheduler"])
async def list_jobs(user: dict = Depends(get_current_user)):
    return scheduler.get_status()

@app.post("/scheduler/jobs", tags=["Scheduler"])
async def add_job(
    name: str,
    cron: str,
    command: str,
    params: Optional[Dict] = None,
    user: dict = Depends(require_role("operator"))
):
    job_id = scheduler.add_job(name, cron, command, params)
    return {"id": job_id, "name": name, "cron": cron, "command": command}

@app.patch("/scheduler/jobs/{job_id}/enable", tags=["Scheduler"])
async def enable_job(
    job_id: int,
    user: dict = Depends(require_role("operator"))
):
    if scheduler.enable_job(job_id):
        return {"id": job_id, "enabled": True, "message": "Job enabled"}
    raise HTTPException(status_code=404, detail="Job not found")

@app.patch("/scheduler/jobs/{job_id}/disable", tags=["Scheduler"])
async def disable_job(
    job_id: int,
    user: dict = Depends(require_role("operator"))
):
    if scheduler.disable_job(job_id):
        return {"id": job_id, "enabled": False, "message": "Job disabled"}
    raise HTTPException(status_code=404, detail="Job not found")

@app.delete("/scheduler/jobs/{job_id}", tags=["Scheduler"], status_code=204)
async def delete_job(
    job_id: int,
    user: dict = Depends(require_role("admin"))
):
    if scheduler.remove_job(job_id):
        return None
    raise HTTPException(status_code=404, detail="Job not found")

# ─── Backup ───────────────────────────────────────────────────────────────

@app.post("/backup", tags=["Backup"])
async def create_backup(
    include_logs: bool = True,
    user: dict = Depends(require_role("admin"))
):
    bm = BackupManager()
    result = bm.create_backup(include_logs=include_logs)
    
    event_bus.publish(
        "backup.created",
        {"include_logs": include_logs, "success": bool(result)},
        source="api",
        priority="normal"
    )
    
    if result:
        return result
    raise HTTPException(status_code=500, detail="Backup failed")

@app.get("/backups", tags=["Backup"])
async def list_backups(user: dict = Depends(get_current_user)):
    bm = BackupManager()
    return bm.list_backups()

# ─── Logs ─────────────────────────────────────────────────────────────────

@app.get("/logs/stats", tags=["Logs"])
async def get_log_stats(user: dict = Depends(get_current_user)):
    return log_manager.get_stats()

@app.post("/logs/rotate", tags=["Logs"])
async def rotate_logs(user: dict = Depends(get_current_user)):
    log_manager.auto_rotate()
    return {"message": "Log rotation completed"}

@app.get("/logs", tags=["Logs"])
async def get_logs(
    file: Optional[str] = Query(None, description="Log filename (e.g. orchestrator.log)"),
    lines: int = Query(100, ge=1, le=1000, description="Number of recent lines"),
    level: Optional[str] = Query(None, description="Filter by log level: INFO, WARNING, ERROR, DEBUG"),
    since: Optional[str] = Query(None, description="ISO datetime to filter from (e.g. 2026-05-12)"),
    user: dict = Depends(get_current_user)
):
    """Read log file contents with filtering and pagination."""
    import re

    log_file = log_manager.log_dir / (file or "orchestrator.log")
    if not log_file.exists() or not str(log_file).startswith(str(log_manager.log_dir)):
        raise HTTPException(status_code=404, detail=f"Log file not found: {file}")

    entries = []
    cutoff = datetime.fromisoformat(since) if since else None
    line_pattern = re.compile(r"^(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}).*?(INFO|WARNING|ERROR|DEBUG|CRITICAL)", re.I)

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        all_lines = f.readlines()

    # Read last N lines with filters
    for raw_line in reversed(all_lines):
        line = raw_line.rstrip("\n")
        if not line:
            continue

        m = line_pattern.match(line)
        if m:
            log_dt_str, log_level = m.group(1), m.group(2).upper()
        else:
            log_level = "UNKNOWN"
            log_dt_str = None

        if level and log_level != level.upper():
            continue
        if cutoff and log_dt_str:
            try:
                log_dt = datetime.fromisoformat(log_dt_str.replace(" ", "T"))
                if log_dt < cutoff:
                    break
            except Exception:
                pass

        entries.append({
            "timestamp": log_dt_str,
            "level": log_level,
            "message": line
        })

        if len(entries) >= lines:
            break

    return {
        "file": str(log_file.name),
        "directory": str(log_manager.log_dir),
        "total_lines_read": len(all_lines),
        "returned": len(entries),
        "entries": list(reversed(entries))
    }

# ─── Metrics ──────────────────────────────────────────────────────────────

@app.get("/metrics/prometheus", tags=["Metrics"])
async def get_prometheus_metrics():
    """Prometheus scraper endpoint — unauthenticated by design."""
    return Response(content=metrics.to_prometheus(), media_type="text/plain")

@app.get("/metrics/json", tags=["Metrics"])
async def get_json_metrics(user: dict = Depends(get_current_user)):
    return metrics.to_dict()

# ─── Event Bus ────────────────────────────────────────────────────────────

@app.get("/events/history", tags=["Events"])
async def get_event_history(
    event_type: Optional[str] = None,
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

# ─── Organizations ────────────────────────────────────────────────────────────

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
async def update_anomaly_rule(rule_id: str, enabled: Optional[bool] = None, threshold: Optional[float] = None, user: dict = Depends(get_current_user)):
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

# ─── Startup ──────────────────────────────────────────────────────────────

# TODO: Migrate startup/shutdown to FastAPI lifespan (on_event is deprecated in FastAPI 0.100+)
@app.on_event("startup")
async def startup_event():
    """Start background services on API startup."""
    # Initialize OpenTelemetry (gracefully no-ops if not configured)
    init_telemetry(service_name="shogun")
    setup_fastapi_instrumentation(app)
    logger.info("OpenTelemetry initialized (if endpoint configured)")
    
    anomaly_detector.start()
    logger.info("Anomaly detector started (60s check interval)")

@app.on_event("shutdown")
async def shutdown_event():
    """Stop background services on shutdown."""
    anomaly_detector.stop()
    logger.info("Anomaly detector stopped")

# ─── WebSocket ────────────────────────────────────────────────────────────


# ─── Supply Chain Scanner (L2 Validation) ──────────────────────────────

class ScanRequest(BaseModel):
    target: str = Field(..., description="Path to project directory to scan")
    rules: Optional[List[str]] = Field(None, description="Subset of rule IDs to run")
    format: str = Field("json", pattern="^(json|sarif)$")

class ScanResponse(BaseModel):
    scan_id: str
    timestamp: str
    target: str
    engine_version: str
    findings_count: int
    findings: List[Dict[str, Any]]
    stats: Dict[str, Any]

@app.post("/api/v1/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    request: ScanRequest,
    user: dict = Depends(require_role("viewer"))
):
    """Run an L2 supply chain scan on a project directory."""
    from pathlib import Path as _Path
    from iron_dome.L2_validation.engine import create_default_engine as _create_engine

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

@app.get("/api/v1/scans/rules", tags=["Scans"])
async def list_scan_rules(user: dict = Depends(get_current_user)):
    """List available L2 supply chain scanner rules."""
    from iron_dome.L2_validation.engine import create_default_engine as _create_engine
    engine = _create_engine()
    return {"rules": engine.list_rules()}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time WebSocket for live events."""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "subscribe":
                    channels = msg.get("channels", ["*"])
                    ws_manager.subscribe(websocket, channels)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.api.host,
        port=settings.api.port,
        workers=settings.api.workers,
        reload=settings.api.reload
    )

# ─── L3 Sandbox Endpoints ─────────────────────────────────────────────────

class SandboxRunRequest(BaseModel):
    command: List[str] = Field(..., description="Command and arguments to execute under sandbox")
    policy_file: Optional[str] = Field(None, description="Path to policy YAML file (default: built-in)")
    timeout: Optional[float] = Field(None, ge=1, le=3600, description="Override wall-time limit (seconds)")
    format: str = Field("json", pattern="^(json|sarif)$")

class SandboxRunResponse(BaseModel):
    run_id: str
    timestamp: str
    command: List[str]
    overall_verdict: str
    exit_code: Optional[int]
    duration_ms: int
    events: List[Dict[str, Any]]
    policy_name: str

@app.post("/api/v1/sandboxes", response_model=SandboxRunResponse, tags=["Sandbox"])
async def run_sandbox(
    request: SandboxRunRequest,
    user: dict = Depends(require_role("operator"))
):
    """Run a command under L3 sandbox policy."""
    from pathlib import Path as _Path
    from iron_dome.L3_execution.engine import sandbox_run
    from iron_dome.L3_execution.policy_loader import load_policy as _load_policy

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

@app.get("/api/v1/sandboxes/policies/default", tags=["Sandbox"])
async def get_default_policy(user: dict = Depends(get_current_user)):
    """Get the default L3 sandbox policy."""
    from iron_dome.L3_execution.policy_loader import load_policy as _load_policy
    policy = _load_policy()
    return policy.to_dict()
