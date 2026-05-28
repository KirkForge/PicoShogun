"""Plugin system for extensible project integration."""
import os
import sys
import json
import importlib
import inspect
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger("SecdevKimi.Plugins")

@dataclass
class PluginMetadata:
    name: str
    version: str
    author: str
    description: str
    entry_point: str
    hooks: List[str]
    dependencies: List[str]

class PluginInterface:
    """Base interface all plugins must implement."""
    
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Called once when plugin is loaded."""
        raise NotImplementedError
    
    def on_project_start(self, project_id: str, metadata: Dict) -> None:
        """Hook: Before project execution."""
        pass
    
    def on_project_complete(self, project_id: str, result: Dict) -> None:
        """Hook: After project execution."""
        pass
    
    def on_intelligence(self, intel: Dict) -> Optional[Dict]:
        """Hook: Intelligence signal received."""
        return None
    
    def on_alert(self, alert: Dict) -> Optional[Dict]:
        """Hook: Alert triggered."""
        return None
    
    def health_check(self) -> Dict:
        """Return plugin health status."""
        return {"status": "healthy"}
    
    def shutdown(self) -> None:
        """Cleanup when plugin is unloaded."""
        pass

class PluginManager:
    """Dynamic plugin loader and lifecycle manager."""
    
    def __init__(self, plugin_dir: str = None):
        self.plugin_dir = plugin_dir or os.path.join(os.path.dirname(__file__), "../plugins")
        self.plugins: Dict[str, PluginInterface] = {}
        self.metadata: Dict[str, PluginMetadata] = {}
        self.hooks = {
            "project_start": [],
            "project_complete": [],
            "intelligence": [],
            "alert": [],
        }
        self._load_plugins()
    
    def _load_plugins(self):
        """Discover and load all plugins from plugin directory."""
        if not os.path.exists(self.plugin_dir):
            logger.info(f"Plugin directory not found: {self.plugin_dir}")
            return
        
        for entry in os.listdir(self.plugin_dir):
            plugin_path = os.path.join(self.plugin_dir, entry)
            manifest = os.path.join(plugin_path, "plugin.json")
            
            if os.path.isdir(plugin_path) and os.path.exists(manifest):
                try:
                    with open(manifest) as f:
                        meta = json.load(f)
                    
                    self._load_plugin(plugin_path, meta)
                except Exception as e:
                    logger.error(f"Failed to load plugin {entry}: {e}")
    
    def _load_plugin(self, path: str, meta: Dict):
        """Load a single plugin by its manifest."""
        name = meta["name"]
        entry = meta["entry_point"]
        
        # Add plugin path AND project root to sys.path
        sys.path.insert(0, path)
        project_root = os.path.dirname(self.plugin_dir)
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        try:
            module = importlib.import_module(entry)
            
            # Find plugin class
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (inspect.isclass(attr) and 
                    issubclass(attr, PluginInterface) and
                    attr != PluginInterface):
                    
                    instance = attr()
                    if instance.initialize(meta.get("config", {})):
                        self.plugins[name] = instance
                        self.metadata[name] = PluginMetadata(
                            name=name,
                            version=meta.get("version", "0.0.1"),
                            author=meta.get("author", "unknown"),
                            description=meta.get("description", ""),
                            entry_point=entry,
                            hooks=meta.get("hooks", []),
                            dependencies=meta.get("dependencies", [])
                        )
                        
                        # Register hooks
                        for hook in meta.get("hooks", []):
                            if hook in self.hooks:
                                self.hooks[hook].append(name)
                        
                        logger.info(f"Plugin loaded: {name} v{self.metadata[name].version}")
                    break
        finally:
            sys.path.remove(path)
    
    def dispatch(self, hook: str, **kwargs):
        """Dispatch event to all plugins registered for a hook."""
        results = []
        for plugin_name in self.hooks.get(hook, []):
            plugin = self.plugins.get(plugin_name)
            if not plugin:
                continue
            
            try:
                method = getattr(plugin, f"on_{hook}", None)
                if method:
                    result = method(**kwargs)
                    if result:
                        results.append({"plugin": plugin_name, "result": result})
            except Exception as e:
                logger.error(f"Plugin {plugin_name} hook {hook} failed: {e}")
        
        return results
    
    def get_status(self) -> Dict:
        """Get status of all loaded plugins."""
        status = {}
        for name, plugin in self.plugins.items():
            try:
                health = plugin.health_check()
                status[name] = {
                    "metadata": self.metadata[name].__dict__,
                    "health": health
                }
            except Exception as e:
                status[name] = {
                    "error": str(e),
                    "health": {"status": "unhealthy"}
                }
        return status
    
    def unload_all(self):
        """Gracefully shutdown all plugins."""
        for name, plugin in self.plugins.items():
            try:
                plugin.shutdown()
                logger.info(f"Plugin unloaded: {name}")
            except Exception as e:
                logger.error(f"Plugin {name} shutdown failed: {e}")
        
        self.plugins.clear()
        self.metadata.clear()
        for hook_list in self.hooks.values():
            hook_list.clear()

# Global plugin manager instance
plugin_manager = PluginManager()
