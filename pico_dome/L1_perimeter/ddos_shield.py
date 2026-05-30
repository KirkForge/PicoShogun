"""
Layer 1: Perimeter Shield — Adaptive DDoS detection + rate limiting
Deterministic defense against volumetric attacks.
"""
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class RequestFingerprint:
    """Immutable snapshot of a request for analysis."""
    ip: str
    user_agent: str
    path: str
    method: str
    timestamp: float
    body_hash: str  # Hash of request body (not content for privacy)
    size: int
    headers_hash: str


@dataclass
class ClientProfile:
    """Behavioral profile per client IP."""
    ip: str
    request_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    paths_accessed: set = field(default_factory=set)
    error_count: int = 0
    challenge_solved: bool = False
    block_until: float = 0.0
    trust_score: float = 100.0  # 0-100, starts high
    first_seen: float = field(default_factory=time.time)
    geo: str = "unknown"
    isp: str = "unknown"
    is_bot: bool | None = None


class AdaptiveRateLimiter:
    """
    Multi-layer rate limiter with DDoS detection.

    Graduated response:
    - Normal: Allow
    - Elevated (>2x baseline): Add delay
    - High (>5x baseline): Challenge (CAPTCHA)
    - Critical (>10x baseline): Block + alert
    """

    def __init__(
        self,
        window_seconds: int = 60,
        max_requests_per_window: int = 100,
        burst_threshold: float = 10.0,  # 10x normal rate
        challenge_threshold: float = 5.0,
        ddos_threshold: float = 100.0,  # rps
        progressive_delay: bool = True
    ):
        self.window = window_seconds
        self.max_requests = max_requests_per_window
        self.burst_threshold = burst_threshold
        self.challenge_threshold = challenge_threshold
        self.ddos_threshold = ddos_threshold
        self.progressive = progressive_delay

        self._clients: dict[str, ClientProfile] = {}
        self._lock = threading.RLock()
        self._global_window_start = time.time()
        self._global_request_count = 0
        self._baseline_rps: deque = deque(maxlen=60)  # 1 minute of baselines

        # DDoS state
        self._ddos_active: bool = False
        self._ddos_start: float = 0.0
        self._circuit_breaker: dict[str, bool] = {}  # Service health

    def _get_client(self, ip: str) -> ClientProfile:
        """Get or create client profile."""
        with self._lock:
            if ip not in self._clients:
                self._clients[ip] = ClientProfile(ip=ip)
            return self._clients[ip]

    def _update_baseline(self):
        """Compute baseline request rate from recent history."""
        now = time.time()
        with self._lock:
            recent = [r for profile in self._clients.values()
                     for r in profile.request_times
                     if now - r < 300]  # 5 min window
            if recent:
                self._baseline_rps.append(len(recent) / 300.0)

    def _get_baseline_rps(self) -> float:
        """Median baseline RPS over last 5 minutes."""
        if not self._baseline_rps:
            return 1.0  # Conservative default
        return statistics.median(self._baseline_rps) or 1.0

    def _calculate_score(self, profile: ClientProfile) -> dict[str, float]:
        """Calculate threat score components."""
        now = time.time()
        recent_requests = sum(1 for t in profile.request_times
                             if now - t < self.window)

        # Rate score: how fast vs baseline
        baseline = self._get_baseline_rps()
        current_rps = recent_requests / self.window
        rate_score = min(100.0, (current_rps / baseline) * 10) if baseline > 0 else 0.0

        # Diversity score: how many unique paths
        path_score = min(50.0, len(profile.paths_accessed))

        # Error score: error rate
        error_score = min(50.0, profile.error_count * 5)

        # Trust decay: new clients score lower
        age_hours = (now - profile.first_seen) / 3600
        trust_bonus = min(30.0, age_hours * 2)

        total = rate_score + path_score + error_score - trust_bonus
        return {
            "rate": rate_score,
            "path_diversity": path_score,
            "errors": error_score,
            "trust_bonus": trust_bonus,
            "total": max(0.0, min(100.0, total))
        }

    def check_request(self, ip: str, path: str, method: str,
                      user_agent: str, body_size: int = 0) -> tuple[str, float | None, str | None]:
        """
        Check if request should be allowed.

        Returns:
            (action, delay_seconds, challenge_type)
            action: "allow" | "delay" | "challenge" | "block"
            delay_seconds: float (if action == "delay")
            challenge_type: str (if action == "challenge")
        """
        now = time.time()
        client = self._get_client(ip)

        # Already blocked?
        if now < client.block_until:
            return ("block", None, None)

        # Trust recovery: +0.1 per check for legitimate clients (max 100)
        # This prevents permanent trust decay for normal traffic
        if client.trust_score < 100.0:
            client.trust_score = min(100.0, client.trust_score + 0.1)

        # Update profile
        client.request_times.append(now)
        client.paths_accessed.add(path)

        # Compute scores
        scores = self._calculate_score(client)
        trust = client.trust_score - scores["total"]
        client.trust_score = max(0.0, min(100.0, trust))

        # Check DDoS
        current_rps = scores.get("rate", 0) / 10.0  # Back to actual RPS
        if current_rps > self.ddos_threshold:
            self._ddos_active = True
            self._ddos_start = now
            return ("block", None, None)

        # Graduated response
        if trust > 80:
            return ("allow", None, None)
        elif trust > 60:
            # Elevated — add small delay
            delay = min(2.0, (80 - trust) / 10) if self.progressive else 0
            return ("delay", delay, None)
        elif trust > 40:
            # High — challenge
            return ("challenge", None, "captcha")
        elif trust > 20:
            # Critical — block temporarily
            client.block_until = now + 300  # 5 min block
            return ("block", None, None)
        else:
            # Under attack
            client.block_until = now + 3600  # 1 hour
            return ("block", None, None)

    def report_error(self, ip: str, status_code: int):
        """Report error response from backend."""
        client = self._get_client(ip)
        client.error_count += 1
        # Rapid 4xx/5xx from same IP is suspicious
        if client.error_count > 10:
            client.trust_score -= 20

    def solve_challenge(self, ip: str) -> bool:
        """Mark client as solved a challenge."""
        client = self._get_client(ip)
        client.challenge_solved = True
        client.trust_score = min(100, client.trust_score + 30)
        return True

    def get_status(self) -> dict:
        """Current shield status."""
        with self._lock:
            now = time.time()
            active_clients = sum(1 for c in self._clients.values()
                               if now - max(c.request_times or [0]) < 300)
            blocked = sum(1 for c in self._clients.values() if now < c.block_until)

            return {
                "active": self._ddos_active,
                "active_clients_5m": active_clients,
                "blocked_clients": blocked,
                "baseline_rps": self._get_baseline_rps(),
                "ddos_duration": (now - self._ddos_start) if self._ddos_active else 0,
                "circuit_breakers": dict(self._circuit_breaker),
                "total_clients_tracked": len(self._clients)
            }

    def set_circuit_breaker(self, service: str, open_: bool):
        """Open/close circuit breaker for a downstream service."""
        self._circuit_breaker[service] = open_

    def evict_stale_clients(self, max_age_seconds: int = 3600, max_clients: int = 10000) -> int:
        """Remove clients not seen in max_age_seconds. Prevents memory leak.

        Returns number of evicted clients.
        """
        now = time.time()
        with self._lock:
            stale = [
                ip for ip, c in self._clients.items()
                if now - max(c.request_times or [0]) > max_age_seconds
            ]
            for ip in stale:
                del self._clients[ip]

            # Hard cap: if still too many clients, evict oldest
            if len(self._clients) > max_clients:
                sorted_clients = sorted(
                    self._clients.items(),
                    key=lambda x: max(x[1].request_times or [0])
                )
                to_remove = len(self._clients) - max_clients
                for ip, _ in sorted_clients[:to_remove]:
                    del self._clients[ip]

            return len(stale)


# Singleton
limiter = AdaptiveRateLimiter()
