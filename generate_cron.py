#!/usr/bin/env python3
"""
Generate staggered cron schedules for 75 SecDev projects.

Schedule design:
- Projects run in 15-minute windows (batch groups of 4-5)
- 6 windows per day = all 75 projects in ~18 hours
- Critical/high-priority projects run more frequently
- Light projects (monitoring) run continuously
- Heavy projects (GPU cracking) run once daily off-peak
- Stagger offsets: 00, 15, 30, 45 past the hour
"""

import json
from pathlib import Path

CONFIG = Path("/home/kirk/.picoclaw/workspace/PicoShogun/config")
REGISTRY = CONFIG / "project_registry.json"

# Load registry
with open(REGISTRY) as f:
    registry = json.load(f)

# Category scheduling rules
CATEGORY_RULES = {
    "monitoring": {"interval": 30, "priority": 1},    # Every 30 min
    "analysis":   {"interval": 60, "priority": 2},    # Every hour
    "defense":    {"interval": 120, "priority": 3},   # Every 2 hours
    "offense":    {"interval": 180, "priority": 4},   # Every 3 hours
    "crypto":     {"interval": 240, "priority": 5},   # Every 4 hours
    "training":   {"interval": 360, "priority": 6},   # Every 6 hours
    "unknown":    {"interval": 480, "priority": 7},   # Every 8 hours
}

# Special cases: heavy CPU/GPU projects get once-daily off-peak
DAILY_OFFPEAK = {
    "24-gpu-password-cracking": "4",
    "11-firewall-setup": "3",
    "27-full-disk-encryption": "5",
    "28-ml-intrusion-detection": "2",
    "66-vulnerability-scanner": "1",
}

print("# PicoShogun Cron Schedule")
print(f"# Generated for {len(registry)} projects")
print()

# Generate schedule
for pid, meta in registry.items():
    short_name = pid.split("_", 1)[1]
    cat = meta.get("category", "unknown")

    if short_name in DAILY_OFFPEAK:
        # Once daily at off-peak hour (01:00 + offset)
        hour = DAILY_OFFPEAK[short_name]
        cron = f"0 {hour} * * *"
    else:
        # Staggered interval
        interval = CATEGORY_RULES.get(cat, CATEGORY_RULES["unknown"])["interval"]

        # Derive offset from project number to spread load
        try:
            num = int(pid.split("_", 1)[0])
        except (ValueError, TypeError):
            num = 0

        # Map interval to cron expression
        if interval == 30:
            # Every 30 min, offset by project number
            minute_offset = (num * 7) % 30  # Spread across 30-minute window
            cron = f"{minute_offset},{minute_offset+30} * * * *"
        elif interval == 60:
            minute_offset = (num * 7) % 60
            cron = f"{minute_offset} * * * *"
        elif interval == 120:
            minute_offset = (num * 7) % 60
            hour_offset = num % 2
            cron = f"{minute_offset} {hour_offset}-23/2 * * *"
        elif interval == 180:
            minute_offset = (num * 7) % 60
            hour_offset = num % 3
            cron = f"{minute_offset} {hour_offset}-23/3 * * *"
        elif interval == 240:
            minute_offset = (num * 7) % 60
            hour_offset = num % 4
            cron = f"{minute_offset} {hour_offset}-23/4 * * *"
        elif interval == 360:
            minute_offset = (num * 7) % 60
            hour_offset = num % 6
            cron = f"{minute_offset} {hour_offset}-23/6 * * *"
        else:
            minute_offset = (num * 7) % 60
            hour_offset = num % 8
            cron = f"{minute_offset} {hour_offset}-23/8 * * *"

    cmd = f"cd {Path('/home/kirk/.picoclaw/workspace/Hivemind-projects') / short_name} && python3 *.py 2>>1 | logger -t picoshogun-{short_name}"

    # Check if main script is Python or Shell
    project_dir = Path("/home/kirk/.picoclaw/workspace/Hivemind-projects") / short_name
    main_script = None
    if project_dir.exists():
        for ext in [".py", ".sh"]:
            candidates = list(project_dir.glob(f"*{ext}"))
            if candidates:
                main_script = candidates[0]
                break

    if main_script and main_script.suffix == ".sh":
        cmd = f"cd {project_dir} && bash {main_script.name} 2>>1 | logger -t picoshogun-{short_name}"
    elif main_script:
        cmd = f"cd {project_dir} && python3 {main_script.name} 2>>1 | logger -t picoshogun-{short_name}"
    else:
        cmd = f"# No main script found for {short_name}"

    print(f"{cron} {cmd}")

print()
print("# Orchestrator heartbeat + intelligence sweep")
print("*/5 * * * * cd /home/kirk/.picoclaw/workspace/PicoShogun/orchestrator && python3 master.py status 2>>1 | logger -t picoshogun-heartbeat")
print("0 */6 * * * cd /home/kirk/.picoclaw/workspace/PicoShogun/orchestrator && python3 /home/kirk/.picoclaw/workspace/scripts/Intelligence_report_summary.py 2>>1 | logger -t picoshogun-intel")
