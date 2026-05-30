"""Test plugin for PLUGIN-01 acceptance criteria."""
import logging

# Need to import PluginInterface — add project root to path
import os
import sys
from typing import Any

sys.path.insert(0, os.environ.get('PICOSHOGUN_DIR', '/home/kirk/Madlab/Clean-Live/PicoShogun'))
from services.plugin_manager import PluginInterface

logger = logging.getLogger("picoshogun.Plugin.Test")

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
