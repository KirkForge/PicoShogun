"""Test plugin for PLUGIN-01 acceptance criteria."""
import logging
from typing import Dict, Any, Optional
import sys

# Need to import PluginInterface — add project root to path
sys.path.insert(0, '/home/kirk/.picoclaw/workspace/Secdev_kimi')
from services.plugin_manager import PluginInterface

logger = logging.getLogger("SecdevKimi.Plugin.Test")

class TestHandler(PluginInterface):
    """Minimal plugin that verifies hook dispatch works."""
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        logger.info("TestHandler initialized")
        return True
    
    def on_project_complete(self, project_id: str, result: Dict) -> None:
        logger.info(f"[TestPlugin] Project {project_id} completed: {result.get('status')}")
    
    def on_alert(self, alert: Dict) -> Optional[Dict]:
        logger.info(f"[TestPlugin] Alert: {alert.get('message', '')}")
        return alert
    
    def health_check(self) -> Dict:
        return {"status": "ok", "plugin": "test_plugin"}
