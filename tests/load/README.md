# PicoShogun Load Testing

## Quick Start

```bash
# Start PicoShogun in a separate terminal
PICOSHOGUN_SECRET_KEY=$(openssl rand -hex 32) python3 -m uvicorn api.server:app --host 127.0.0.1 --port 8000

# Run headless baseline (50 users, 10/s ramp, 30s)
locust -f tests/load/locustfile.py --host http://127.0.0.1:8000 \
    --headless -u 50 -r 10 -t 30s --only-summary
```

## Web UI

```bash
locust -f tests/load/locustfile.py --host http://127.0.0.1:8000
# Open http://localhost:8089
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `LOCUST_HOST` | `http://127.0.0.1:8000` | Target host |
| `LOCUST_TEST_USER` | `loadtest_bot` | Test username |
| `LOCUST_TEST_PASS` | `LoadTest2024!Secure` | Test password |

## Test Coverage

- **Health endpoints** — `/health`, `/health/live` (unauthenticated)
- **Read endpoints** — `/projects`, `/alerts`, `/intelligence`, `/status`, `/scheduler/jobs`, `/orgs`
- **Write endpoints** — `/auth/api-key`
- **Metrics** — `/metrics/prometheus` (unauthenticated), `/metrics/json`

## Baseline Targets

Results should be recorded in GAPS.md after establishing baselines. Rough targets for a single-core dev machine:

| Endpoint | Target p50 | Target p99 |
|----------|-----------|------------|
| `/health` | < 5ms | < 50ms |
| `/health/live` | < 2ms | < 20ms |
| `/projects` (auth) | < 15ms | < 100ms |
| `/metrics/prometheus` | < 10ms | < 80ms |
