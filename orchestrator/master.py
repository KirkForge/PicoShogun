#!/usr/bin/env python3
"""
Secdev_kimi Master Orchestrator
Central brain for the 75-project smart security lab.
Coordinates, learns, adapts, and evolves.

Architecture:
- Plugin-based project loader
- SQLite state tracking
- Cross-project intelligence feed
- Discord/Slack alerting
- REST API gateway
- Adaptive scheduling
"""

import os
import sys
import json
import sqlite3
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Any
from collections import defaultdict

# ─── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent
PROJECTS_DIR = Path("/home/kirk/.picoclaw/workspace/Hivemind-projects")
UPGRADE_DIR = BASE_DIR / "projects"
LOGS_DIR = BASE_DIR / "logs"
CONFIG_DIR = BASE_DIR / "config"
DB_PATH = BASE_DIR / "secdev_kimi.db"
REGISTRY_PATH = CONFIG_DIR / "project_registry.json"

LOGS_DIR.mkdir(exist_ok=True)
CONFIG_DIR.mkdir(exist_ok=True)

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler(LOGS_DIR / "orchestrator.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("SecdevKimi")

# ─── Database ───────────────────────────────────────────────────────────────

def _get_sqlite_conn():
    """Return a WAL-enabled SQLite connection (consistent with database/manager.py)."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    """Initialize SQLite database for state tracking."""
    conn = _get_sqlite_conn()
    c = conn.cursor()
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS project_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL,
            run_start TIMESTAMP,
            run_end TIMESTAMP,
            status TEXT,  -- running, completed, failed, timeout
            exit_code INTEGER,
            output TEXT,
            alerts_generated INTEGER DEFAULT 0,
            intelligence_extracted TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS intelligence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_project TEXT,
            intel_type TEXT,  -- threat, anomaly, pattern, correlation
            severity TEXT,    -- critical, high, medium, low, info
            data TEXT,
            related_projects TEXT,
            action_taken TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT,
            alert_type TEXT,
            severity TEXT,
            message TEXT,
            channel TEXT,  -- discord, syslog, webhook
            sent BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT,
            metric_name TEXT,
            metric_value REAL,
            unit TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info("Database initialized")

# ─── Project Registry ───────────────────────────────────────────────────────
@dataclass
class ProjectMeta:
    id: str
    name: str
    category: str  # defense, offense, analysis, monitoring, crypto
    priority: int    # 1-10, 10 = most critical
    dependencies: List[str]
    cron_schedule: str
    estimated_duration: int  # minutes
    status: str = "pending"  # pending, active, upgrading, complete
    version: str = "1.0.0"
    intelligence_outputs: List[str] = None
    intelligence_inputs: List[str] = None

class ProjectRegistry:
    """Manages the 75 projects and their metadata."""
    
    def __init__(self):
        self.projects: Dict[str, ProjectMeta] = {}
        self.load()
    
    def load(self):
        if REGISTRY_PATH.exists():
            with open(REGISTRY_PATH) as f:
                data = json.load(f)
                for pid, pdict in data.items():
                    self.projects[pid] = ProjectMeta(**pdict)
        else:
            self._build_default_registry()
    
    def save(self):
        data = {pid: asdict(p) for pid, p in self.projects.items()}
        with open(REGISTRY_PATH, "w") as f:
            json.dump(data, f, indent=2)
    
    def _build_default_registry(self):
        """Auto-generate registry from existing Hivemind projects."""
        projects = sorted([p for p in PROJECTS_DIR.glob("*") if p.is_dir() and not p.name.startswith(".")])
        categories = {
            "honeypot": "defense", "password": "analysis", "sniffer": "monitoring",
            "keylogger": "analysis", "forensics": "analysis", "lab": "infrastructure",
            "encryption": "crypto", "phishing": "offense", "wifi": "monitoring",
            "vuln": "offense", "firewall": "defense", "factor": "defense",
            "secure-web": "defense", "snort": "monitoring", "scanner": "offense",
            "dns": "monitoring", "antivirus": "defense", "anomaly": "monitoring",
            "malware": "analysis", "tls": "defense", "zero-day": "analysis",
            "tor": "privacy", "honeypot-advanced": "defense", "gpu": "analysis",
            "browser": "defense", "sandbox": "analysis", "disk": "defense",
            "ml-ids": "monitoring", "routing": "defense", "wallet": "crypto",
            "rootkit": "analysis", "darkweb": "monitoring", "ddos": "offense",
            "messaging": "crypto", "pki": "crypto", "ctf": "training",
            "container": "defense", "vuln_analysis": "analysis", "threat": "monitoring",
            "header": "defense", "red-team": "offense", "iot": "analysis",
            "binary": "analysis", "exploit": "offense", "api": "offense",
            "devops": "defense", "attack-detection": "monitoring", "cloud": "defense",
            "social": "offense", "mobile": "offense", "shellcode": "offense",
            "privesc": "offense", "active-directory": "defense", "segmentation": "defense",
            "waf": "defense", "secure-boot": "defense", "embedded": "analysis",
            "evasion": "offense", "memory": "analysis", "cryptography": "crypto",
            "threat-intel": "monitoring", "camera": "monitoring", "wireless": "offense",
            "insider": "monitoring", "email": "defense", "supply-chain": "defense",
            "datacenter": "defense", "bug-bounty": "offense", "vehicle": "analysis",
            "ics-scada": "analysis", "steganography": "analysis", "biometric": "defense",
            "architecture": "defense"
        }
        
        for i, pdir in enumerate(projects, 1):
            pid = f"{i:02d}_{pdir.name}"
            cat = "unknown"
            for key, val in categories.items():
                if key in pdir.name.lower():
                    cat = val
                    break
            
            self.projects[pid] = ProjectMeta(
                id=pid,
                name=pdir.name,
                category=cat,
                priority=5,
                dependencies=[],
                cron_schedule="*/10 * * * *",  # Every 10 min (placeholder)
                estimated_duration=10,
                status="pending"
            )
        
        self.save()
        logger.info(f"Built registry with {len(self.projects)} projects")

# ─── Intelligence Engine ──────────────────────────────────────────────────────
class IntelligenceEngine:
    """Cross-project learning and correlation engine."""
    
    def __init__(self):
        self.patterns = defaultdict(list)
        self.threat_scores = defaultdict(float)
    
    def ingest(self, project_id: str, data: Dict[str, Any]):
        """Ingest intelligence from a project run."""
        conn = _get_sqlite_conn()
        c = conn.cursor()
        
        intel_type = data.get("type", "unknown")
        severity = data.get("severity", "info")
        intel_data = json.dumps(data.get("data", {}))
        related = json.dumps(data.get("related", []))
        
        c.execute("""
            INSERT INTO intelligence (source_project, intel_type, severity, data, related_projects)
            VALUES (?, ?, ?, ?, ?)
        """, (project_id, intel_type, severity, intel_data, related))
        
        conn.commit()
        conn.close()
        
        # Update threat scoring
        self._update_threat_score(project_id, severity, data)
        
        logger.info(f"Intelligence ingested from {project_id}: {intel_type} [{severity}]")
    
    def _update_threat_score(self, project_id: str, severity: str, data: Dict):
        """Update composite threat score for the environment."""
        weights = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.1}
        score = weights.get(severity, 0)
        
        # Decay old scores
        for pid in self.threat_scores:
            self.threat_scores[pid] *= 0.95
        
        self.threat_scores[project_id] += score
        
        # Log aggregate
        total = sum(self.threat_scores.values())
        logger.info(f"Aggregate threat score: {total:.1f} (from {len(self.threat_scores)} sources)")
    
    def get_correlations(self, project_id: str) -> List[Dict]:
        """Find intelligence correlated with a specific project."""
        conn = _get_sqlite_conn()
        c = conn.cursor()
        
        c.execute("""
            SELECT source_project, intel_type, severity, data, created_at
            FROM intelligence
            WHERE related_projects LIKE ?
            ORDER BY created_at DESC
            LIMIT 20
        """, (f"%{project_id}%",))
        
        results = []
        for row in c.fetchall():
            results.append({
                "source": row[0],
                "type": row[1],
                "severity": row[2],
                "data": json.loads(row[3]),
                "time": row[4]
            })
        
        conn.close()
        return results

# ─── Alert Hub ──────────────────────────────────────────────────────────────
class AlertHub:
    """Smart alerting with deduplication and severity escalation."""
    
    def __init__(self):
        self.recent_alerts = defaultdict(list)  # project -> recent messages
        self.cooldown_seconds = 300  # 5 min cooldown per alert type
    
    def send(self, project_id: str, alert_type: str, severity: str, 
             message: str, channels: List[str] = None):
        """Send alert through configured channels with dedup."""
        if channels is None:
            channels = ["discord", "syslog"]
        
        # Deduplication check
        now = datetime.now()
        key = f"{project_id}:{alert_type}"
        
        for prev in self.recent_alerts.get(key, []):
            if (now - prev).total_seconds() < self.cooldown_seconds:
                logger.debug(f"Alert suppressed (cooldown): {key}")
                return False
        
        self.recent_alerts[key].append(now)
        
        # Store in DB
        conn = _get_sqlite_conn()
        c = conn.cursor()
        
        for ch in channels:
            c.execute("""
                INSERT INTO alerts (project_id, alert_type, severity, message, channel)
                VALUES (?, ?, ?, ?, ?)
            """, (project_id, alert_type, severity, message, ch))
        
        conn.commit()
        conn.close()
        
        # Send to Discord if configured
        if "discord" in channels:
            self._discord_notify(project_id, severity, message)
        
        logger.info(f"ALERT [{severity}] {project_id}: {message[:80]}")
        return True
    
    def _discord_notify(self, project_id: str, severity: str, message: str):
        """Send to Discord webhook (if configured)."""
        webhook_url = os.environ.get("DISCORD_WEBHOOK_URL")
        if not webhook_url:
            return
        
        colors = {"critical": 15158332, "high": 16711680, "medium": 16776960, 
                  "low": 65280, "info": 3447003}
        
        payload = {
            "embeds": [{
                "title": f"🛡️ Secdev_kimi Alert: {project_id}",
                "description": message,
                "color": colors.get(severity, 3447003),
                "fields": [
                    {"name": "Severity", "value": severity.upper(), "inline": True},
                    {"name": "Time", "value": datetime.now().isoformat(), "inline": True}
                ]
            }]
        }
        
        try:
            import requests
            requests.post(webhook_url, json=payload, timeout=5)
        except Exception as e:
            logger.error(f"Discord notify failed: {e}")

# ─── Project Runner ─────────────────────────────────────────────────────────
class ProjectRunner:
    """Executes individual projects with monitoring and error handling."""
    
    def __init__(self, registry: ProjectRegistry, intel: IntelligenceEngine, 
                 alerts: AlertHub):
        self.registry = registry
        self.intel = intel
        self.alerts = alerts
    
    def run(self, project_id: str) -> Dict:
        """Execute a project and capture all outputs."""
        meta = self.registry.projects.get(project_id)
        if not meta:
            return {"error": f"Unknown project: {project_id}"}
        
        # Map registry ID to actual directory name (replace _ with - for lookup)
        dir_name = project_id.split("_", 1)[1]
        project_dir = PROJECTS_DIR / dir_name
        if not project_dir.exists():
            return {"error": f"Project directory not found: {project_dir}"}
        
        # Find main script
        main_script = None
        for ext in [".py", ".sh"]:
            candidates = list(project_dir.glob(f"*{ext}"))
            if candidates:
                main_script = candidates[0]
                break
        
        if not main_script:
            return {"error": "No executable script found"}
        
        logger.info(f"Running {project_id} from {main_script}")
        
        # Record start
        conn = _get_sqlite_conn()
        c = conn.cursor()
        c.execute("""
            INSERT INTO project_runs (project_id, run_start, status)
            VALUES (?, ?, ?)
        """, (project_id, datetime.now(), "running"))
        run_id = c.lastrowid
        conn.commit()
        conn.close()
        
        # Execute
        start_time = datetime.now()
        try:
            if main_script.suffix == ".py":
                cmd = [sys.executable, str(main_script)]
            else:
                cmd = ["bash", str(main_script)]
            
            result = subprocess.run(
                cmd,
                cwd=str(project_dir),
                capture_output=True,
                text=True,
                timeout=meta.estimated_duration * 60
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Parse output for intelligence
            intel_extracted = self._extract_intelligence(project_id, result.stdout + result.stderr)
            
            # Update DB
            conn = _get_sqlite_conn()
            c = conn.cursor()
            c.execute("""
                UPDATE project_runs
                SET run_end = ?, status = ?, exit_code = ?, output = ?, 
                    intelligence_extracted = ?, alerts_generated = ?
                WHERE id = ?
            """, (datetime.now(), 
                  "completed" if result.returncode == 0 else "failed",
                  result.returncode,
                  result.stdout + result.stderr,
                  json.dumps(intel_extracted),
                  len(intel_extracted)))
            conn.commit()
            conn.close()
            
            # Feed intelligence to engine
            for intel in intel_extracted:
                self.intel.ingest(project_id, intel)
            
            logger.info(f"{project_id} completed in {duration:.1f}s (exit={result.returncode})")
            
            return {
                "success": result.returncode == 0,
                "duration": duration,
                "output": result.stdout,
                "stderr": result.stderr,
                "intelligence": intel_extracted
            }
            
        except subprocess.TimeoutExpired:
            conn = _get_sqlite_conn()
            c = conn.cursor()
            c.execute("UPDATE project_runs SET run_end = ?, status = ? WHERE id = ?",
                       (datetime.now(), "timeout", run_id))
            conn.commit()
            conn.close()
            
            self.alerts.send(project_id, "timeout", "high", 
                           f"Project timed out after {meta.estimated_duration} minutes")
            return {"error": "timeout"}
            
        except Exception as e:
            conn = _get_sqlite_conn()
            c = conn.cursor()
            c.execute("UPDATE project_runs SET run_end = ?, status = ? WHERE id = ?",
                       (datetime.now(), "failed", run_id))
            conn.commit()
            conn.close()
            
            self.alerts.send(project_id, "execution_error", "high", str(e))
            return {"error": str(e)}
    
    def _extract_intelligence(self, project_id: str, output: str) -> List[Dict]:
        """Parse project output for intelligence signals."""
        intel = []
        
        # Pattern matching for common security signals
        patterns = {
            "threat_ip": (r"(\d+\.\d+\.\d+\.\d+)", "low"),
            "critical_vuln": (r"CRITICAL|RCE|exploit|shell", "critical"),
            "high_vuln": (r"HIGH|vulnerability|CVE-\d+", "high"),
            "auth_failure": (r"failed.*auth|brute|password", "medium"),
            "anomaly": (r"anomaly|unusual|outlier|z-score", "medium"),
            "connection": (r"connection.*from|new.*session", "info"),
        }
        
        for intel_type, (pattern, severity) in patterns.items():
            import re
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                intel.append({
                    "type": intel_type,
                    "severity": severity,
                    "data": {"matches": list(set(matches))[:10]},  # dedup, limit
                    "related": []
                })
        
        return intel

# ─── API Gateway ──────────────────────────────────────────────────────────────
class APIGateway:
    """REST API for external integration and dashboard."""
    
    def __init__(self, registry: ProjectRegistry, intel: IntelligenceEngine,
                 alerts: AlertHub, runner: ProjectRunner):
        self.registry = registry
        self.intel = intel
        self.alerts = alerts
        self.runner = runner
    
    def start(self, port: int = 8765):
        """Start Flask/FastAPI server (placeholder - implement with preferred framework)."""
        logger.info(f"API Gateway would start on port {port}")
        # Implementation: FastAPI/Flask routes for:
        # GET /projects - list all
        # GET /projects/{id} - project details
        # POST /projects/{id}/run - trigger run
        # GET /intelligence - recent intel
        # GET /alerts - active alerts
        # GET /metrics - aggregate metrics
        # GET /threat-score - current threat level

# ─── Master Orchestrator ────────────────────────────────────────────────────
class SecdevKimiOrchestrator:
    """Main orchestrator that ties everything together."""
    
    def __init__(self):
        init_db()
        self.registry = ProjectRegistry()
        self.intel = IntelligenceEngine()
        self.alerts = AlertHub()
        self.runner = ProjectRunner(self.registry, self.intel, self.alerts)
        self.api = APIGateway(self.registry, self.intel, self.alerts, self.runner)
        self.running = False
    
    def run_project(self, project_id: str) -> Dict:
        """Execute a single project."""
        return self.runner.run(project_id)
    
    def run_batch(self, project_ids: List[str]) -> Dict[str, Dict]:
        """Run multiple projects sequentially."""
        results = {}
        for pid in project_ids:
            results[pid] = self.run_project(pid)
        return results
    
    def get_status(self) -> Dict:
        """Get overall system status."""
        conn = _get_sqlite_conn()
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) FROM project_runs WHERE status = 'completed'")
        completed = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM project_runs WHERE status = 'failed'")
        failed = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM intelligence WHERE severity IN ('critical', 'high')")
        active_threats = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM alerts WHERE sent = 0")
        pending_alerts = c.fetchone()[0]
        
        conn.close()
        
        return {
            "projects_total": len(self.registry.projects),
            "projects_completed": completed,
            "projects_failed": failed,
            "active_threats": active_threats,
            "pending_alerts": pending_alerts,
            "threat_score": sum(self.intel.threat_scores.values()),
            "timestamp": datetime.now().isoformat()
        }
    
    def generate_report(self) -> str:
        """Generate comprehensive status report."""
        status = self.get_status()
        
        report = f"""
╔════════════════════════════════════════════════════════════════╗
║     Secdev_kimi Enterprise Security Lab Report                ║
╚════════════════════════════════════════════════════════════════╝

Generated: {status['timestamp']}

OVERALL STATUS
──────────────
Projects:      {status['projects_total']} total
              {status['projects_completed']} completed
              {status['projects_failed']} failed
Threat Level:  {status['threat_score']:.1f}/100
Active Intel:  {status['active_threats']} critical/high items
Pending Alerts: {status['pending_alerts']}

THREAT SCORE BREAKDOWN
──────────────────────
"""
        for pid, score in sorted(self.intel.threat_scores.items(), key=lambda x: -x[1])[:10]:
            report += f"  {pid}: {score:.1f}\n"
        
        return report

# ─── CLI ──────────────────────────────────────────────────────────────────────
def main():
    orch = SecdevKimiOrchestrator()
    
    if len(sys.argv) < 2:
        print(orch.generate_report())
        return
    
    cmd = sys.argv[1]
    
    if cmd == "status":
        print(json.dumps(orch.get_status(), indent=2))
    
    elif cmd == "run" and len(sys.argv) > 2:
        project_id = sys.argv[2]
        result = orch.run_project(project_id)
        print(json.dumps(result, indent=2, default=str))
    
    elif cmd == "batch" and len(sys.argv) > 2:
        # Run multiple: python master.py batch 01 02 03
        pids = [f"{int(x):02d}_{list(orch.registry.projects.values())[int(x)-1].name}" 
                for x in sys.argv[2:] if x.isdigit()]
        results = orch.run_batch(pids)
        print(json.dumps(results, indent=2, default=str))
    
    elif cmd == "report":
        print(orch.generate_report())
    
    elif cmd == "init":
        print("Secdev_kimi initialized. Registry built.")
        print(f"Projects registered: {len(orch.registry.projects)}")
    
    else:
        print(f"Unknown command: {cmd}")
        print("Usage: master.py [status|run <id>|batch <ids...>|report|init]")

if __name__ == "__main__":
    main()
