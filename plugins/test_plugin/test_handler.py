"""Test plugin for PLUGIN-01 acceptance criteria."""
import logging
import sys
from typing import Any

# Need to import PluginInterface — add project root to path
sys.path.insert(0, '/home/kirk/Madlab/Clean-Live/Shogun')
from services.plugin_manager import PluginInterface

logger = logging.getLogger("shogun.Plugin.Test")

class TestHandler(PluginInterface):
    """Minimal plugin that verifies hook dispatch works."""

    def initialize(self, config: dict[str, Any]) -> bool:
        logger.info("TestHandler initialized")
        return True

    def on_project_complete(self, project_id: str, result: dict) -> None:
        logger.info(f"[TestPlugin] Project {project_id} completed: {result.get('status')}")

    def on_alert(self, alert: dict) -> dict | None:
        logger.info(f"[TestPlugin] Alert: {alert.get('message', '')}")
        return alert

    def health_check(self) -> dict:
        return {"status": "ok", "plugin": "test_plugin"}
