"""DDoS Shield middleware — wraps AdaptiveRateLimiter for FastAPI."""
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from iron_dome.L1_perimeter.ddos_shield import limiter

class DDoSShieldMiddleware(BaseHTTPMiddleware):
    """
    Adaptive DDoS protection middleware.
    
    Integrates the L1 Perimeter shield into FastAPI:
    - Trust scoring per client IP
    - Graduated response: allow → delay → challenge → block
    - Reports 4xx/5xx errors back to shield for trust decay
    """
    
    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
    
    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        method = request.method
        user_agent = request.headers.get("user-agent", "")
        
        # Check with shield
        action, delay, challenge_type = limiter.check_request(
            ip=client_ip,
            path=path,
            method=method,
            user_agent=user_agent
        )
        
        if action == "block":
            return JSONResponse(
                {"error": "Request blocked — suspicious activity detected"},
                status_code=403
            )
        
        elif action == "challenge":
            return JSONResponse(
                {"error": "Challenge required", "type": challenge_type},
                status_code=429,
                headers={"Retry-After": "60"}
            )
        
        elif action == "delay" and delay:
            time.sleep(delay)
        
        # Process request
        response = await call_next(request)
        
        # Report errors back to shield
        if response.status_code >= 400:
            limiter.report_error(client_ip, response.status_code)
        
        return response
