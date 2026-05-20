"""Test plugin for Secdev_kimi plugin system."""
from services.plugin_manager import PluginInterface
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger("SecdevKimi.Plugin.TestNotifier")

class TestNotifier(PluginInterface):
    """Logs project completions and alerts to console."""
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        logger.info("TestNotifier initialized")
        return True
    
    def on_project_complete(self, project_id: str, result: Dict) -> None:
        status = result.get("status", "unknown")
        duration = result.get("duration", 0)
        logger.info(f"[Plugin] Project {project_id} completed: {status} in {duration:.1f}s")
    
    def on_alert(self, alert: Dict) -> Optional[Dict]:
        severity = alert.get("severity", "info")
        msg = alert.get("message", "")
        logger.info(f"[Plugin] Alert [{severity.upper()}]: {msg}")
        return alert
    
    def health_check(self) -> Dict:
        return {"status": "healthy", "version": "1.0.0"}
