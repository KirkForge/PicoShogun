#!/usr/bin/env python3
"""
Generate staggered cron schedules for SecDev projects.
Smart filtering: only creates entries for projects with executable scripts.

All paths are resolved relative to PICOSHOGUN_DIR and HIVEMIND_PROJECTS_DIR
env vars, or fall back to the project root's parent/Hivemind-projects.
"""

import json
import os
from pathlib import Path

# Resolve project root — env var override or relative to this script's parent
BASE = Path(os.environ.get("PICOSHOGUN_DIR", str(Path(__file__).resolve().parent.parent)))
HIVE = Path(os.environ.get("HIVEMIND_PROJECTS_DIR", str(BASE.parent / "Hivemind-projects")))
SEC = BASE
CONFIG = SEC / "config"
REGISTRY = CONFIG / "project_registry.json"

# Load registry
with open(REGISTRY) as f:
    registry = json.load(f)

# Category scheduling rules
CAT_RULES = {
    "monitoring":   {"interval": 30,  "priority": 1},   # Every 30 min
    "analysis":     {"interval": 60,  "priority": 2},   # Every hour
    "defense":      {"interval": 120, "priority": 3},   # Every 2 hours
    "offense":      {"interval": 180, "priority": 4},   # Every 3 hours
    "crypto":       {"interval": 240, "priority": 5},   # Every 4 hours
    "training":     {"interval": 360, "priority": 6},   # Every 6 hours
    "unknown":      {"interval": 480, "priority": 7},   # Every 8 hours
}

# Heavy projects: once daily off-peak
DAILY = {
    "24-gpu-password-cracking": "04:00",
    "27-full-disk-encryption":  "03:00",
    "28-ml-intrusion-detection": "05:00",
}

def find_main_script(project_dir):
    """Find the main executable in a project directory."""
    if not project_dir.exists():
        return None
    for ext in [".py", ".sh"]:
        candidates = list(project_dir.glob(f"*{ext}"))
        if candidates:
            # Prefer files that don't contain README or SETUP
            for c in candidates:
                lower = c.name.lower()
                if "setup" in lower or "guide" in lower:
                    continue
                return c
            return candidates[0]
    return None

entries = []
comment_lines = []

for pid, meta in registry.items():
    short_name = pid.split("_", 1)[1]
    cat = meta.get("category", "unknown")

    project_dir = HIVE / short_name
    script = find_main_script(project_dir)

    if not script:
        comment_lines.append(f"# SKIP {short_name}: no executable script")
        continue

    if short_name in DAILY:
        hour, minute = DAILY[short_name].split(":")
        cron = f"{minute} {hour} * * *"
    else:
        interval = CAT_RULES.get(cat, CAT_RULES["unknown"])["interval"]

        # Derive offset from project number
        try:
            num = int(pid.split("_", 1)[0])
        except (ValueError, TypeError):
            num = 0

        if interval == 30:
            offset = (num * 7) % 30
            cron = f"{offset},{offset+30} * * * *"
        elif interval == 60:
            offset = (num * 7) % 60
            cron = f"{offset} * * * *"
        elif interval == 120:
            offset = (num * 7) % 60
            hour_offset = num % 2
            cron = f"{offset} {hour_offset}-23/2 * * *"
        elif interval == 180:
            offset = (num * 7) % 60
            hour_offset = num % 3
            cron = f"{offset} {hour_offset}-23/3 * * *"
        elif interval == 240:
            offset = (num * 7) % 60
            hour_offset = num % 4
            cron = f"{offset} {hour_offset}-23/4 * * *"
        elif interval == 360:
            offset = (num * 7) % 60
            hour_offset = num % 6
            cron = f"{offset} {hour_offset}-23/6 * * *"
        else:
            offset = (num * 7) % 60
            hour_offset = num % 8
            cron = f"{offset} {hour_offset}-23/8 * * *"

    runner = "python3" if script.suffix == ".py" else "bash"
    cmd = f"cd {project_dir} && {runner} {script.name} >> /dev/null 2>&1"

    entries.append(f"{cron} {cmd}")

# Build output
output = []
output.append("# === PicoShogun Cron Schedule ===")
output.append(f"# Generated for {len(entries)} projects with executable scripts")
output.append("")

if comment_lines:
    output.append("# Skipped projects (no executable scripts):")
    output.extend(comment_lines)
    output.append("")

output.extend(entries)
orch_dir = SEC / "orchestrator"
output.append("")
output.append("# === Orchestrator heartbeat ===")
output.append(f"*/5 * * * * cd {orch_dir} && python3 master.py status >> /dev/null 2>&1")

print("\n".join(output))
