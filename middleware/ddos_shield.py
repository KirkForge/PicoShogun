"""DDoS Shield middleware — placeholder until picodome is installed.

The L1 Perimeter DDoS shield was part of the vendored pico_dome package.
Install picodome to restore this middleware: pip install picodome
"""
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("picoshogun.DDoSShield")


class DDoSShieldMiddleware(BaseHTTPMiddleware):
    """Pass-through DDoS shield placeholder.

    When picodome is installed, this wraps the L1 Perimeter adaptive
    rate limiter. Without it, requests pass through unfiltered — rely
    on the standard RateLimitMiddleware instead.
    """

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        # Pass-through: DDoS shielding requires the picodome package
        return await call_next(request)
