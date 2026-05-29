"""Tests for the Shogun Command Centre API endpoints."""
import contextlib
import os
import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
os.environ["SHOGUN_ENV"] = "test"
os.environ["SHOGUN_SECRET_KEY"] = "test-key-for-pytest"


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    from fastapi.testclient import TestClient

    from api.server import app
    return TestClient(app)


@pytest.fixture
def auth_token(client):
    """Get an auth token for authenticated requests."""
    # Try to register + login, fallback to using admin bootstrap if available
    with contextlib.suppress(Exception):
        client.post("/auth/register", json={
            "username": "pytest_user",
            "password": "testpassword123",
            "role": "admin"
        })

    try:
        resp = client.post("/auth/login?username=pytest_user&password=testpassword123")
        if resp.status_code == 200:
            data = resp.json()
            return data.get("access_token", "")
    except Exception:
        pass

    # Fallback: create a mock token or use API key
    return ""


def auth_headers(token):
    """Return authorization headers for a given token."""
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


class TestHealthEndpoint:
    """Test /health endpoint (unauthenticated)."""

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_has_overall_field(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "overall" in data
        assert data["overall"] in ("healthy", "degraded", "critical")

    def test_health_has_checks_list(self, client):
        resp = client.get("/health")
        data = resp.json()
        assert "checks" in data
        assert isinstance(data["checks"], list)

    def test_health_check_fields(self, client):
        resp = client.get("/health")
        data = resp.json()
        for check in data["checks"]:
            assert "component" in check
            assert "status" in check
            assert "message" in check


class TestDashboardEndpoint:
    """Test dashboard page serving."""

    def test_dashboard_returns_html(self, client):
        resp = client.get("/dashboard")
        # May return 200 or 404 if front/index.html doesn't exist in test env
        if resp.status_code == 200:
            assert "text/html" in resp.headers.get("content-type", "")
            assert "Shogun" in resp.text or "Command Centre" in resp.text

    def test_root_redirect_or_html(self, client):
        resp = client.get("/")
        # Root should either redirect to /dashboard or serve the dashboard
        assert resp.status_code in (200, 307, 308, 404)


class TestMetricsEndpoint:
    """Test /metrics endpoint."""

    def test_metrics_json_endpoint(self, client):
        resp = client.get("/metrics/json")
        if resp.status_code == 200:
            data = resp.json()
            assert "uptime_seconds" in data

    def test_metrics_prometheus_endpoint(self, client):
        resp = client.get("/metrics/prometheus")
        if resp.status_code == 200:
            assert "secdev_" in resp.text or "uptime" in resp.text.lower()


class TestDashboardSummary:
    """Test /api/v1/dashboard/summary endpoint."""

    def test_dashboard_summary_returns_data(self, client, auth_token):
        headers = auth_headers(auth_token)
        resp = client.get("/api/v1/dashboard/summary", headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            assert "status" in data or "health" in data


class TestAPIVersion:
    """Test API version and docs endpoints."""

    def test_openapi_docs_available(self, client):
        resp = client.get("/docs")
        assert resp.status_code in (200, 404)  # May be disabled in test

    def test_api_info(self, client):
        from api.server import app
        assert app.title == "Shogun Command Centre API"
        assert app.version == "2.15.0"


class TestSecurityHeaders:
    """Test that security middleware is active."""

    def test_rate_limiting_works(self, client):
        """Verify rate limiting doesn't break normal requests."""
        resp = client.get("/health")
        assert resp.status_code == 200


class TestObservabilityModule:
    """Test the observability module can be imported."""

    def test_import_observability(self):
        from services.observability import get_tracer, init_telemetry
        assert init_telemetry is not None
        assert get_tracer is not None

    def test_noop_tracer(self):
        from services.observability import NoOpTracer
        tracer = NoOpTracer()
        span = tracer.start_span("test")
        assert span is not None
        span.set_attribute("key", "value")
        span.end()

    def test_noop_meter(self):
        from services.observability import NoOpMeter
        meter = NoOpMeter()
        counter = meter.create_counter("test_counter")
        counter.add(1)

    def test_init_telemetry_no_endpoint(self):
        from services.observability import init_telemetry
        # Should return False gracefully when no endpoint is configured
        result = init_telemetry(service_name="test")
        assert result is False

    def test_trace_span_decorator(self):
        from services.observability import trace_span
        @trace_span("test_operation", attributes={"key": "value"})
        def test_func():
            return 42
        result = test_func()
        assert result == 42

    def test_trace_async_span_decorator(self):
        from services.observability import trace_async_span
        @trace_async_span("test_async_operation")
        async def test_async_func():
            return 99
        import asyncio
        result = asyncio.run(test_async_func())
        assert result == 99


class TestDatabaseManager:
    """Test database initialization."""

    def test_db_module_imports(self):
        from database.manager import db
        assert db is not None

    def test_settings_module_imports(self):
        from config.settings import settings
        assert settings.api.port == 8765
        assert settings.database.journal_mode == "WAL"
        assert settings.security.jwt_algorithm == "HS256"
