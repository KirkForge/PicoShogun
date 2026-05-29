"""Rate limiting middleware."""
import threading
import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory rate limiter: per-IP + per-org token."""

    def __init__(
        self,
        app,
        max_requests_per_ip: int = 100,
        max_requests_per_org: int = 1000,
        window: int = 60,
        max_buckets: int = 100000,
    ):
        super().__init__(app)
        self.max_requests_per_ip = max_requests_per_ip
        self.max_requests_per_org = max_requests_per_org
        self.window = window
        self.max_buckets = max_buckets
        # Two separate buckets so org calls don't eat the IP budget
        self.ip_requests: dict[str, list] = defaultdict(list)
        self.org_requests: dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()
        self._last_eviction = time.time()

    def _evict_if_needed(self, now: float):
        """Periodically evict stale buckets to prevent memory leak."""
        if now - self._last_eviction < 60:
            return
        self._last_eviction = now

        # Remove buckets with no recent activity
        cutoff = now - self.window
        stale_ips = [k for k, v in self.ip_requests.items() if not v or v[-1] < cutoff]
        stale_orgs = [k for k, v in self.org_requests.items() if not v or v[-1] < cutoff]

        for k in stale_ips:
            del self.ip_requests[k]
        for k in stale_orgs:
            del self.org_requests[k]

        # Hard cap
        if len(self.ip_requests) > self.max_buckets:
            sorted_keys = sorted(self.ip_requests, key=lambda k: self.ip_requests[k][-1] if self.ip_requests[k] else 0)
            for k in sorted_keys[:len(self.ip_requests) - self.max_buckets]:
                del self.ip_requests[k]
        if len(self.org_requests) > self.max_buckets:
            sorted_keys = sorted(self.org_requests, key=lambda k: self.org_requests[k][-1] if self.org_requests[k] else 0)
            for k in sorted_keys[:len(self.org_requests) - self.max_buckets]:
                del self.org_requests[k]

    def _clean_and_count(self, buckets: dict, key: str, now: float) -> int:
        buckets[key] = [t for t in buckets[key] if now - t < self.window]
        return len(buckets[key])

    async def dispatch(self, request: Request, call_next):
        now = time.time()
        client_ip = request.client.host if request.client else "unknown"

        with self._lock:
            self._evict_if_needed(now)

            # ── Per-Org limit (check first — org keys have higher quota) ──
            org_api_key = request.headers.get("X-Org-API-Key", "")
            rate_limited = False
            if org_api_key and isinstance(org_api_key, str) and (org_api_key.startswith("sk_") or org_api_key.startswith("pk_")):
                org_count = self._clean_and_count(self.org_requests, org_api_key, now)
                if org_count >= self.max_requests_per_org:
                    retry_after = int(self.window - (now - self.org_requests[org_api_key][0]) + 1)
                    rate_limited = True
                    rate_limit_response = JSONResponse(
                        {
                            "error": "Organization rate limit exceeded",
                            "limit": self.max_requests_per_org,
                            "window": f"{self.window}s",
                        },
                        status_code=429,
                        headers={"Retry-After": str(max(retry_after, 1))},
                    )
                else:
                    self.org_requests[org_api_key].append(now)

            # ── Per-IP limit ──
            if not rate_limited:
                ip_count = self._clean_and_count(self.ip_requests, client_ip, now)
                if ip_count >= self.max_requests_per_ip:
                    retry_after = int(self.window - (now - self.ip_requests[client_ip][0]) + 1)
                    rate_limited = True
                    rate_limit_response = JSONResponse(
                        {
                            "error": "Rate limit exceeded",
                            "limit": self.max_requests_per_ip,
                            "window": f"{self.window}s",
                        },
                        status_code=429,
                        headers={"Retry-After": str(max(retry_after, 1))},
                    )
                else:
                    self.ip_requests[client_ip].append(now)

        if rate_limited:
            return rate_limit_response
        return await call_next(request)
