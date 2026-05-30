"""Shared pytest fixtures and configuration for PicoShogun tests."""
import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
os.environ["PICOSHOGUN_ENV"] = "test"
os.environ["PICOSHOGUN_SECRET_KEY"] = "test-key-for-pytest"


def _find_and_clear_rate_limiter(app):
    """Walk the middleware stack to find and reset RateLimitMiddleware."""
    from middleware.rate_limit import RateLimitMiddleware

    if not app.middleware_stack:
        return
    obj = app.middleware_stack
    depth = 0
    while obj is not None and depth < 30:
        if isinstance(obj, RateLimitMiddleware):
            obj.ip_requests.clear()
            obj.org_requests.clear()
            return
        if hasattr(obj, 'app'):
            obj = obj.app
        else:
            break
        depth += 1


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear rate limiter state before each test to avoid 429 accumulation."""
    from fastapi.testclient import TestClient

    from api.server import app

    # Force middleware stack build if not yet built
    if not app.middleware_stack:
        try:
            tc = TestClient(app)
            tc.get("/health/live")
        except Exception:
            pass

    _find_and_clear_rate_limiter(app)
    yield
    _find_and_clear_rate_limiter(app)
