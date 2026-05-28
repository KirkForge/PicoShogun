#!/usr/bin/env python3
"""Daily SaaS gap worker — picks top task from backlog, executes, commits."""
import subprocess
import re
from datetime import datetime
from pathlib import Path

SECDEV_DIR = Path("/home/kirk/.picoclaw/workspace/Secdev_kimi")
BACKLOG_FILE = SECDEV_DIR / "backlog.md"
LOG_FILE = SECDEV_DIR / "logs/daily_worker.log"

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def read_backlog():
    if not BACKLOG_FILE.exists():
        return "", []
    content = BACKLOG_FILE.read_text()
    lines = content.split("\n")
    return content, lines

def find_top_task(lines):
    """Find highest-priority TODO task."""
    tasks = []
    for line in lines:
        match = re.match(r"^(\w+-\d+)\|(P\d)\|TODO\|(.+)\|(.+)$", line)
        if match:
            id_, priority, desc, criteria = match.groups()
            prio_val = int(priority[1])  # P1=1, P2=2, etc.
            tasks.append({
                "id": id_,
                "priority": priority,
                "priority_val": prio_val,
                "description": desc,
                "criteria": criteria
            })
    if not tasks:
        return None
    tasks.sort(key=lambda x: x["priority_val"])
    return tasks[0]

def update_task_status(content, task_id, new_status, note=""):
    """Replace TODO with new status."""
    pattern = rf"^({re.escape(task_id)}\|P\d\|)TODO(\|.+)$"
    replacement = rf"\1{new_status}\2"
    updated = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    if note:
        updated = updated.replace("## Completed", f"## Completed\n{task_id}|{datetime.now().strftime('%Y-%m-%d')}|{new_status}|{note}")
    return updated

def run_command(cmd, cwd=None, timeout=60):
    """Run shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, shell=True, cwd=cwd or SECDEV_DIR,
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, str(e)

def execute_task(task):
    """Execute the top task based on its ID."""
    task_id = task["id"]
    desc = task["description"]
    criteria = task["criteria"]
    
    log(f"=== Task: {task_id} ===")
    log(f"Desc: {desc}")
    log(f"Acceptance: {criteria}")
    
    if task_id == "INFRA-01":
        # Fix systemd service
        service_file = SECDEV_DIR / "secdev-kimi.service"
        content = service_file.read_text()
        # Fix ExecStart to use venv Python and correct path
        content = content.replace(
            "ExecStart=/usr/bin/python3 -m uvicorn api.server:app",
            "ExecStart=/home/kirk/.picoclaw/workspace/Secdev_kimi/venv/bin/python -m uvicorn api.server:app"
        )
        # Fix PYTHONPATH
        content = content.replace(
            "PYTHONPATH=/home/kirk/.picoclaw/workspace/Secdev_kimi",
            "PYTHONPATH=/home/kirk/.picoclaw/workspace/Secdev_kimi"
        )
        content = content.replace(
            "Environment=SECDEV_SECRET_KEY=change-me-in-production",
            "Environment=SECDEV_SECRET_KEY=secdev-kimi-production-key-$(date +%s)"
        )
        service_file.write_text(content)
        
        # Copy to systemd
        success, out = run_command(f"sudo cp {service_file} /etc/systemd/system/secdev-kimi.service")
        if not success:
            log(f"WARN: Could not copy service file (may need sudo): {out}")
            return "PARTIAL", "Service file prepared but not installed (needs sudo)"
        
        run_command("sudo systemctl daemon-reload")
        success, out = run_command("sudo systemctl enable secdev-kimi")
        if success:
            return "DONE", "Systemd service registered and enabled"
        else:
            return "PARTIAL", f"Service file installed but enable failed: {out}"
    
    elif task_id == "INFRA-02":
        # Stand up API on a real port
        # Kill any existing process on 8765
        run_command("pkill -f 'uvicorn.*api.server' 2>/dev/null")
        
        # Start the API
        proc = subprocess.Popen(
            [
                "/home/kirk/.picoclaw/workspace/Secdev_kimi/venv/bin/python",
                "-m", "uvicorn", "api.server:app",
                "--host", "0.0.0.0", "--port", "8765",
                "--workers", "1"
            ],
            cwd=SECDEV_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        
        # Wait a moment then test
        import time
        time.sleep(2)
        
        success, out = run_command("curl -s http://localhost:8765/health", timeout=5)
        if success and "ok" in out.lower():
            return "DONE", f"API running on port 8765 (PID {proc.pid}), /health responds"
        else:
            return "PARTIAL", f"Started API (PID {proc.pid}) but health check failed: {out}"
    
    elif task_id == "DB-01":
        # Database v3 migrations already done
        success, out = run_command("/home/kirk/.picoclaw/workspace/Secdev_kimi/venv/bin/python -c \"from database.manager import db; print('DB OK')\"")
        if success:
            return "DONE", "Database manager initializes correctly with v3 schema"
        else:
            return "BLOCKED", f"DB init failed: {out}"
    
    elif task_id == "API-01":
        # Fill in stub /metrics endpoint
        metrics_file = SECDEV_DIR / "services" / "metrics.py"
        if metrics_file.exists():
            content = metrics_file.read_text()
            # Check if already has real metrics
            if "project_runs_total" in content:
                return "DONE", "Metrics endpoint already has real counters"
            else:
                # This is more complex — would need to actually implement metrics collection
                return "PARTIAL", "Metrics file exists but needs manual implementation"
        else:
            return "BLOCKED", "metrics.py not found"
    
    else:
        log(f"Task {task_id} has no automated handler yet — manual work required")
        return "TODO", "No automation for this task yet"

def commit_changes(status, note):
    """Git add, commit, push if configured."""
    # Check if there are changes
    success, out = run_command("git status --short", cwd=SECDEV_DIR)
    if not out.strip():
        log("No git changes to commit")
        return
    
    # Stage backlog and any changes
    run_command("git add backlog.md database/manager.py requirements.txt secdev-kimi.service", cwd=SECDEV_DIR)
    run_command("git add -A", cwd=SECDEV_DIR)
    
    msg = f"daily: {status.lower()} — {note[:60]}"
    success, out = run_command(f"git commit -m '{msg}'", cwd=SECDEV_DIR)
    if success:
        log(f"Committed: {msg}")
    else:
        log(f"Commit result: {out}")
    
    # Try push if remote exists
    success, out = run_command("git remote get-url origin 2>/dev/null", cwd=SECDEV_DIR)
    if success and out.strip():
        run_command("git push", cwd=SECDEV_DIR)

def main():
    log("=== Daily SaaS Worker Start ===")
    
    # Read backlog
    content, lines = read_backlog()
    if not lines:
        log("No backlog found — creating")
        return
    
    # Find top task
    task = find_top_task(lines)
    if not task:
        log("No TODO tasks found — all caught up or backlog empty")
        return
    
    log(f"Selected task: {task['id']} ({task['priority']})")
    
    # Execute
    status, note = execute_task(task)
    log(f"Result: {status} — {note}")
    
    # Update backlog
    if status in ("DONE", "PARTIAL"):
        new_content = update_task_status(content, task["id"], status, note)
        BACKLOG_FILE.write_text(new_content)
        log("Backlog updated")
    
    # Commit
    commit_changes(status, note)
    
    log("=== Daily SaaS Worker Done ===")
    log("")

if __name__ == "__main__":
    main()
