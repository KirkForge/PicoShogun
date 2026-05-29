"""Test plugin loading for PLUGIN-01 acceptance criteria."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.plugin_manager import PluginManager

pm = PluginManager()
print(f"Plugins loaded: {list(pm.plugins.keys())}")
print(f"Metadata keys: {list(pm.metadata.keys())}")

for name, plugin in pm.plugins.items():
    hc = plugin.health_check()
    print(f"- {name}: {hc}")

# Test dispatch: project_complete (returns None, so no result appended — that's expected)
pm.dispatch("project_complete", project_id="TEST_001", result={"status": "completed"})
# Test dispatch: alert (returns the alert dict, so appended)
res = pm.dispatch("alert", alert={"severity": "high", "message": "Test alert from PLUGIN-01"})
print(f"Alert dispatch results: {len(res)} plugin(s) responded")
for r in res:
    print(f"  -> {r}")

# Final verdict: plugin loaded + hooks registered + dispatch executes = PASSED
hooks_registered = len(pm.hooks["project_complete"]) >= 2 and len(pm.hooks["alert"]) >= 2
dispatch_works = res  # at least one alert dispatched successfully
if hooks_registered and dispatch_works:
    print("\n✅ PLUGIN-01 PASSED: Plugin loaded from plugins/, hooks registered, dispatch works")
else:
    print(f"\n❌ PLUGIN-01 FAILED: hooks={pm.hooks}, dispatch_results={len(res)}")
