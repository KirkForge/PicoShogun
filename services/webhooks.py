"""Webhook system for external integrations."""
import json
import hashlib
import hmac
import secrets
import logging
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from database.manager import db

logger = logging.getLogger("SecdevKimi.Webhooks")

# Blocked URL patterns for SSRF protection
SSRF_BLOCKED_SCHEMES = {"file", "ftp", "data", "javascript", "vbscript"}
SSRF_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private
    ipaddress.ip_network("172.16.0.0/12"),     # Private
    ipaddress.ip_network("192.168.0.0/16"),     # Private
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local (AWS metadata)
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 private
]


def _is_safe_webhook_url(url: str) -> tuple:
    """Validate webhook URL against SSRF attacks.
    
    Returns (is_safe, reason) tuple.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"
    
    # Only allow HTTP/HTTPS
    if parsed.scheme not in ("http", "https"):
        return False, f"Scheme '{parsed.scheme}' not allowed. Only http/https."
    
    # Must have a hostname
    if not parsed.hostname:
        return False, "URL must have a hostname"
    
    # Resolve hostname and check against blocked networks
    import socket
    try:
        resolved_ips = socket.getaddrinfo(parsed.hostname, None)
        for _, _, _, _, addr in resolved_ips:
            ip = ipaddress.ip_address(addr[0])
            for network in SSRF_BLOCKED_NETWORKS:
                if ip in network:
                    return False, f"Target IP {ip} is in blocked network {network}"
    except socket.gaierror:
        return False, f"Cannot resolve hostname '{parsed.hostname}'"
    
    return True, "OK"

@dataclass
class Webhook:
    id: int
    name: str
    url: str
    secret: str
    events: List[str]
    active: bool
    retries: int
    created_at: datetime

class WebhookManager:
    """Manage outgoing webhooks with HMAC signing and retry logic."""
    
    def __init__(self):
        self.webhooks: Dict[str, Webhook] = {}
        self._load_webhooks()
    
    def _load_webhooks(self):
        """Load active webhooks from database."""
        rows = db.execute("SELECT * FROM webhooks WHERE active = 1")
        for row in rows:
            webhook = Webhook(
                id=row["id"],
                name=row["name"],
                url=row["url"],
                secret=row["secret"],
                events=json.loads(row["events"]),
                active=row["active"],
                retries=row["retries"],
                created_at=row["created_at"]
            )
            self.webhooks[row["name"]] = webhook
    
    def create(self, name: str, url: str, events: List[str], secret: str = None) -> int:
        """Create a new webhook endpoint."""
        # SSRF protection: validate URL
        is_safe, reason = _is_safe_webhook_url(url)
        if not is_safe:
            raise ValueError(f"Webhook URL rejected: {reason}")
        
        secret = secret or secrets.token_urlsafe(32)
        
        webhook_id = db.execute_insert("""
            INSERT INTO webhooks (name, url, secret, events, active, retries)
            VALUES (?, ?, ?, ?, 1, 0)
        """, (name, url, secret, json.dumps(events)))
        
        self._load_webhooks()
        logger.info(f"Webhook created: {name} -> {url}")
        return webhook_id
    
    def delete(self, webhook_id: int) -> bool:
        """Deactivate a webhook."""
        db.execute("UPDATE webhooks SET active = 0 WHERE id = ?", (webhook_id,))
        self._load_webhooks()
        return True
    
    def _sign_payload(self, payload: Dict, secret: str) -> str:
        """Generate HMAC-SHA256 signature for payload."""
        payload_json = json.dumps(payload, sort_keys=True)
        return hmac.new(
            secret.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def dispatch(self, event: str, payload: Dict) -> List[Dict]:
        """Dispatch event to all matching webhooks."""
        results = []
        
        if not HAS_REQUESTS:
            logger.warning("requests library not available, skipping webhooks")
            return results
        
        for name, webhook in self.webhooks.items():
            if event not in webhook.events:
                continue
            
            event_payload = {
                "event": event,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": payload
            }
            
            signature = self._sign_payload(event_payload, webhook.secret)
            
            try:
                response = requests.post(
                    webhook.url,
                    json=event_payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-Secdev-Signature": f"sha256={signature}",
                        "X-Secdev-Event": event,
                        "User-Agent": "Secdev_kimi-Webhook/2.0"
                    },
                    timeout=10
                )
                
                results.append({
                    "webhook": name,
                    "status": response.status_code,
                    "success": 200 <= response.status_code < 300
                })
                
                logger.info(f"Webhook {name}: {response.status_code}")
                
            except Exception as e:
                logger.error(f"Webhook {name} failed: {e}")
                results.append({
                    "webhook": name,
                    "status": 0,
                    "success": False,
                    "error": str(e)
                })
        
        return results
    
    def verify_signature(self, payload: bytes, signature: str, secret: str) -> bool:
        """Verify incoming webhook signature using constant-time comparison."""
        expected = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        # Use hmac.compare_digest for constant-time comparison (prevents timing attacks)
        return hmac.compare_digest(signature, expected)

# Global webhook manager
webhook_manager = WebhookManager()
