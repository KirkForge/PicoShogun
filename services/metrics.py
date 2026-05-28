"""Metrics collection and Prometheus export."""
import json
import time
import threading
from typing import Dict, List, Any
from collections import defaultdict
from dataclasses import dataclass

@dataclass
class Metric:
    name: str
    value: float
    labels: Dict[str, str]
    timestamp: float
    metric_type: str = "gauge"  # gauge, counter, histogram, summary

class MetricsCollector:
    """Prometheus-compatible metrics collector."""
    
    def __init__(self):
        self.metrics: Dict[str, List[Metric]] = defaultdict(list)
        self.counters: Dict[str, float] = defaultdict(float)
        self._lock = threading.Lock()
        self._start_time = time.time()
    
    def gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record a gauge metric."""
        with self._lock:
            self.metrics[name].append(Metric(
                name=name,
                value=value,
                labels=labels or {},
                timestamp=time.time(),
                metric_type="gauge"
            ))
            # Keep only last 1000 entries per metric
            if len(self.metrics[name]) > 1000:
                self.metrics[name] = self.metrics[name][-1000:]
    
    def counter(self, name: str, increment: float = 1.0, labels: Dict[str, str] = None):
        """Increment a counter."""
        with self._lock:
            key = f"{name}:{json.dumps(labels or {}, sort_keys=True)}"
            self.counters[key] += increment
            self.metrics[name].append(Metric(
                name=name,
                value=self.counters[key],
                labels=labels or {},
                timestamp=time.time(),
                metric_type="counter"
            ))
    
    def histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Record a histogram observation."""
        with self._lock:
            self.metrics[name].append(Metric(
                name=name,
                value=value,
                labels=labels or {},
                timestamp=time.time(),
                metric_type="histogram"
            ))
    
    def project_run(self, project_id: str, duration: float, status: str):
        """Record project execution metrics."""
        self.counter("project_runs_total", 1, {"project": project_id, "status": status})
        self.histogram("project_duration_seconds", duration, {"project": project_id})
        
        if status == "completed":
            self.counter("project_success_total", 1, {"project": project_id})
        elif status == "failed":
            self.counter("project_failures_total", 1, {"project": project_id})
    
    def api_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record API request metrics."""
        self.counter("api_requests_total", 1, {
            "method": method,
            "endpoint": endpoint,
            "status": str(status_code)
        })
        self.histogram("api_request_duration_seconds", duration, {
            "method": method,
            "endpoint": endpoint
        })
    
    def threat_level(self, score: float):
        """Record aggregate threat score."""
        self.gauge("threat_score", score)
    
    def uptime_seconds(self) -> float:
        return time.time() - self._start_time
    
    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []
        
        # Add uptime
        lines.append("# HELP secdev_uptime_seconds Total uptime in seconds")
        lines.append("# TYPE secdev_uptime_seconds gauge")
        lines.append(f"secdev_uptime_seconds {self.uptime_seconds()}")
        
        with self._lock:
            # Group by metric name
            grouped = defaultdict(list)
            for name, metrics_list in self.metrics.items():
                for m in metrics_list:
                    grouped[m.name].append(m)
            
            for name, metrics_list in sorted(grouped.items()):
                if not metrics_list:
                    continue
                
                metric_type = metrics_list[0].metric_type
                lines.append(f"# HELP secdev_{name} {metric_type} metric")
                lines.append(f"# TYPE secdev_{name} {metric_type}")
                
                for m in metrics_list[-50:]:  # Last 50 per metric
                    label_str = ",".join(f'{k}="{v}"' for k, v in m.labels.items())
                    if label_str:
                        lines.append(f'secdev_{name}{{{label_str}}} {m.value}')
                    else:
                        lines.append(f'secdev_{name} {m.value}')
        
        return "\n".join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as JSON-serializable dict."""
        result = {
            "uptime_seconds": self.uptime_seconds(),
            "metrics": {},
            "counters": dict(self.counters)
        }
        
        with self._lock:
            for name, metrics_list in self.metrics.items():
                result["metrics"][name] = [
                    {
                        "value": m.value,
                        "labels": m.labels,
                        "timestamp": m.timestamp,
                        "type": m.metric_type
                    }
                    for m in metrics_list[-100:]
                ]
        
        return result

# Global metrics instance
metrics = MetricsCollector()
