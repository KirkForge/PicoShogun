"""Discord notifier plugin — LOG-ONLY (does not send to Discord).

This plugin logs alerts to the Python logger instead of sending them
to Discord. It is a placeholder until a real Discord webhook integration
is implemented. Do not rely on it for actual notifications.
"""
import logging
from typing import Any

from services.plugin_manager import PluginInterface

logger = logging.getLogger("picoshogun.Plugin.TestNotifier")

class TestNotifier(PluginInterface):
    """Logs project completions and alerts to console (NOT a real Discord client)."""

    def initialize(self, config: dict[str, Any]) -> bool:
        logger.info("TestNotifier initialized")
        return True

    def on_project_complete(self, project_id: str, result: dict) -> None:
        status = result.get("status", "unknown")
        duration = result.get("duration", 0)
        logger.info(f"[Plugin] Project {project_id} completed: {status} in {duration:.1f}s")

    def on_alert(self, alert: dict) -> dict | None:
        severity = alert.get("severity", "info")
        msg = alert.get("message", "")
        logger.info(f"[Plugin] Alert [{severity.upper()}]: {msg}")
        return alert

    def health_check(self) -> dict:
        return {"status": "healthy", "version": "1.0.0"}
