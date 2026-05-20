"""Event bus for pub/sub communication between components."""
import json
import uuid
import logging
import threading
from typing import Dict, List, Callable, Any, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger("SecdevKimi.EventBus")

@dataclass
class Event:
    id: str
    type: str
    source: str
    payload: Dict[str, Any]
    timestamp: datetime
    priority: str = "normal"  # low, normal, high, critical

class EventBus:
    """Enterprise event bus with priority queues and filtering."""
    
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self.persistent_subscribers: Dict[str, List[str]] = defaultdict(list)
        self.event_history: List[Event] = []
        self.max_history = 1000
        self._lock = threading.Lock()
        self._running = True
    
    def subscribe(self, event_type: str, callback: Callable, 
                  persistent: bool = False, subscriber_id: str = None) -> str:
        """Subscribe to events of a specific type."""
        sub_id = subscriber_id or str(uuid.uuid4())
        
        with self._lock:
            self.subscribers[event_type].append(callback)
            if persistent:
                self.persistent_subscribers[event_type].append(sub_id)
        
        logger.debug(f"Subscriber {sub_id} registered for {event_type}")
        return sub_id
    
    def unsubscribe(self, event_type: str, callback: Callable) -> bool:
        """Unsubscribe a callback."""
        with self._lock:
            if event_type in self.subscribers:
                try:
                    self.subscribers[event_type].remove(callback)
                    return True
                except ValueError:
                    pass
        return False
    
    def publish(self, event_type: str, payload: Dict, source: str = "system",
                priority: str = "normal") -> Event:
        """Publish an event to all subscribers."""
        event = Event(
            id=str(uuid.uuid4()),
            type=event_type,
            source=source,
            payload=payload,
            timestamp=datetime.now(),
            priority=priority
        )
        
        with self._lock:
            self.event_history.append(event)
            if len(self.event_history) > self.max_history:
                self.event_history = self.event_history[-self.max_history:]
        
        # Notify subscribers (outside lock for non-blocking)
        callbacks = []
        with self._lock:
            callbacks = self.subscribers.get(event_type, []).copy()
            callbacks.extend(self.subscribers.get("*", []))  # Wildcard subscribers
        
        for callback in callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event handler failed for {event_type}: {e}")
        
        logger.debug(f"Event published: {event_type} ({event.id})")
        return event
    
    def get_history(self, event_type: str = None, limit: int = 100) -> List[Event]:
        """Get recent event history."""
        with self._lock:
            events = self.event_history
            if event_type:
                events = [e for e in events if e.type == event_type]
            return events[-limit:]
    
    def get_subscribers(self) -> Dict[str, int]:
        """Get subscriber counts per event type."""
        with self._lock:
            return {k: len(v) for k, v in self.subscribers.items()}
    
    def clear_history(self):
        """Clear event history."""
        with self._lock:
            self.event_history.clear()
    
    def shutdown(self):
        """Shutdown event bus."""
        self._running = False
        with self._lock:
            self.subscribers.clear()
            self.persistent_subscribers.clear()
            self.event_history.clear()

# Global event bus instance
event_bus = EventBus()

# Convenience functions
def emit(event_type: str, **kwargs):
    """Quick event emission."""
    return event_bus.publish(event_type, kwargs)

def on(event_type: str, callback: Callable):
    """Quick subscription."""
    return event_bus.subscribe(event_type, callback)
