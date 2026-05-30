"""PicoShogun load test suite — baseline performance benchmarks.

Run with:
    cd /path/to/PicoShogun
    locust -f tests/load/locustfile.py --host http://127.0.0.1:8000

Or headless:
    locust -f tests/load/locustfile.py --host http://127.0.0.1:8000 \
        --headless -u 50 -r 10 -t 30s --only-summary

This produces baseline throughput and latency numbers for:
  - Health endpoints (unauthenticated)
  - Authenticated read endpoints
  - Write endpoints (register, API keys)

Results are logged to GAPS.md when baselines are established.
"""
import json
import os

from locust import HttpUser, between, task, tag


# Test credentials created by the load-test setup
TEST_USER = os.environ.get("LOCUST_TEST_USER", "loadtest_bot")
TEST_PASS = os.environ.get("LOCUST_TEST_PASS", "LoadTest2024!Secure")
TEST_TOKEN = None  # Cached JWT


class PicoShogunUser(HttpUser):
    """Simulates an authenticated PicoShogun API user."""

    wait_time = between(0.5, 2.0)
    host = os.environ.get("LOCUST_HOST", "http://127.0.0.1:8000")

    def on_start(self):
        """Register and authenticate to get a JWT token."""
        global TEST_TOKEN
        # Try to register (may already exist)
        self.client.post(
            "/auth/register",
            json={"username": TEST_USER, "password": TEST_PASS, "role": "admin"},
            name="/auth/register",
        )
        # Login to get token
        resp = self.client.post(
            f"/auth/login?username={TEST_USER}&password={TEST_PASS}",
            name="/auth/login",
        )
        if resp.status_code == 200:
            TEST_TOKEN = resp.json().get("access_token")

    @task(5)
    @tag("health")
    def health_check(self):
        self.client.get("/health", name="/health")

    @task(3)
    @tag("health")
    def liveness(self):
        self.client.get("/health/live", name="/health/live")

    @task(2)
    @tag("read")
    def get_status(self):
        if TEST_TOKEN:
            self.client.get(
                "/status",
                headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                name="/status",
            )

    @task(4)
    @tag("read")
    def list_projects(self):
        if TEST_TOKEN:
            self.client.get(
                "/projects",
                headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                name="/projects",
            )

    @task(2)
    @tag("read")
    def list_alerts(self):
        if TEST_TOKEN:
            self.client.get(
                "/alerts?limit=10",
                headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                name="/alerts",
            )

    @task(2)
    @tag("read")
    def list_intelligence(self):
        if TEST_TOKEN:
            self.client.get(
                "/intelligence?limit=10",
                headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                name="/intelligence",
            )

    @task(1)
    @tag("read")
    def metrics_json(self):
        if TEST_TOKEN:
            self.client.get(
                "/metrics/json",
                headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                name="/metrics/json",
            )

    @task(1)
    @tag("metrics")
    def metrics_prometheus(self):
        self.client.get("/metrics/prometheus", name="/metrics/prometheus")

    @task(1)
    @tag("read")
    def scheduler_jobs(self):
        if TEST_TOKEN:
            self.client.get(
                "/scheduler/jobs",
                headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                name="/scheduler/jobs",
            )

    @task(1)
    @tag("read")
    def orgs_list(self):
        if TEST_TOKEN:
            self.client.get(
                "/orgs",
                headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                name="/orgs",
            )

    @task(1)
    @tag("write")
    def create_api_key(self):
        if TEST_TOKEN:
            self.client.post(
                "/auth/api-key",
                json={"name": "loadtest-key"},
                headers={"Authorization": f"Bearer {TEST_TOKEN}"},
                name="/auth/api-key",
            )
