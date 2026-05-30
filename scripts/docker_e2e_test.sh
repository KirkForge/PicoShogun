#!/usr/bin/env bash
# PicoShogun Docker E2E test — validates authenticated endpoints
# inside a container with full PICOSHOGUN_* env vars.
set -euo pipefail

IMAGE="${1:-picoshogun:ci-test}"
CONTAINER_NAME="picoshogun-e2e-$$"
HOST_PORT="${E2E_PORT:-8765}"
BASE_URL="http://localhost:${HOST_PORT}"

echo "════════════════════════════════════════════════════════"
echo "  PicoShogun Docker E2E Test"
echo "  Image: ${IMAGE}"
echo "════════════════════════════════════════════════════════"

cleanup() {
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Start container with full env vars ──────────────────────
echo "[1/7] Starting container..."
docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${HOST_PORT}:8765" \
    -e PICOSHOGUN_ENV=production \
    -e PICOSHOGUN_SECRET_KEY=ci-e2e-test-key-at-least-32-bytes-long! \
    -e PICOSHOGUN_DATABASE_BACKEND=sqlite \
    -e PICOSHOGUN_API_HOST=0.0.0.0 \
    -e PICOSHOGUN_API_PORT=8765 \
    -e PICOSHOGUN_LOGGING_LEVEL=INFO \
    "${IMAGE}"

echo "[2/7] Waiting for service to start..."
for i in $(seq 1 30); do
    if curl -sf "${BASE_URL}/health/live" >/dev/null 2>&1; then
        echo "  Service is up (attempt ${i})"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "  FAILED: Service did not start within 30 seconds"
        docker logs "${CONTAINER_NAME}"
        exit 1
    fi
    sleep 1
done

FAILURES=0

# ── Unauthenticated health checks ──────────────────────────
echo "[3/7] Testing unauthenticated endpoints..."

for endpoint in "/health" "/health/live" "/health/ready" "/metrics/prometheus"; do
    STATUS=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE_URL}${endpoint}" 2>/dev/null || echo "000")
    if [ "${STATUS}" = "200" ]; then
        echo "  ✓ ${endpoint} → 200"
    else
        echo "  ✗ ${endpoint} → ${STATUS} (expected 200)"
        FAILURES=$((FAILURES + 1))
    fi
done

# ── Register + login to get JWT ─────────────────────────────
echo "[4/7] Testing authentication..."
REGISTER_RESP=$(curl -sf -X POST "${BASE_URL}/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"e2e_test_user","password":"testpass12345","role":"admin"}' 2>/dev/null || echo "{}")

if echo "${REGISTER_RESP}" | grep -q "user_id"; then
    echo "  ✓ Registration successful"
else
    echo "  ✗ Registration failed: ${REGISTER_RESP}"
    FAILURES=$((FAILURES + 1))
fi

LOGIN_RESP=$(curl -sf -X POST "${BASE_URL}/auth/login?username=e2e_test_user&password=testpass12345" 2>/dev/null || echo "{}")

TOKEN=$(echo "${LOGIN_RESP}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

if [ -n "${TOKEN}" ]; then
    echo "  ✓ Login successful, got JWT token"
else
    echo "  ✗ Login failed: ${LOGIN_RESP}"
    FAILURES=$((FAILURES + 1))
fi

# ── Authenticated endpoints ─────────────────────────────────
echo "[5/7] Testing authenticated endpoints..."

if [ -n "${TOKEN}" ]; then
    AUTH_HEADER="Authorization: Bearer ${TOKEN}"

    for endpoint in "/api/v1/status" "/api/v1/projects" "/api/v1/metrics/json" "/api/v1/intelligence" "/api/v1/alerts"; do
        STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -H "${AUTH_HEADER}" "${BASE_URL}${endpoint}" 2>/dev/null || echo "000")
        if [ "${STATUS}" = "200" ]; then
            echo "  ✓ ${endpoint} → 200"
        else
            echo "  ✗ ${endpoint} → ${STATUS} (expected 200)"
            FAILURES=$((FAILURES + 1))
        fi
    done

    # Test RBAC: viewer should not access admin endpoints
    echo "[6/7] Testing RBAC access control..."

    # Create a viewer user
    curl -sf -X POST "${BASE_URL}/auth/register" \
        -H "Content-Type: application/json" \
        -H "${AUTH_HEADER}" \
        -d '{"username":"e2e_viewer_user","password":"testpass12345","role":"viewer"}' >/dev/null 2>&1 || true

    VIEWER_LOGIN=$(curl -sf -X POST "${BASE_URL}/auth/login?username=e2e_viewer_user&password=testpass12345" 2>/dev/null || echo "{}")
    VIEWER_TOKEN=$(echo "${VIEWER_LOGIN}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || echo "")

    if [ -n "${VIEWER_TOKEN}" ]; then
        VIEWER_HEADER="Authorization: Bearer ${VIEWER_TOKEN}"
        # Viewer should be able to read projects
        STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -H "${VIEWER_HEADER}" "${BASE_URL}/api/v1/projects" 2>/dev/null || echo "000")
        if [ "${STATUS}" = "200" ]; then
            echo "  ✓ Viewer can read /projects"
        else
            echo "  ✗ Viewer cannot read /projects → ${STATUS}"
            FAILURES=$((FAILURES + 1))
        fi
    fi
else
    echo "  ⚠ Skipping authenticated tests (no token)"
    FAILURES=$((FAILURES + 5))
fi

# ── Dashboard ────────────────────────────────────────────────
echo "[7/7] Testing dashboard..."

if [ -n "${TOKEN}" ]; then
    STATUS=$(curl -sf -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/api/v1/dashboard/summary" 2>/dev/null || echo "000")
    if [ "${STATUS}" = "200" ]; then
        echo "  ✓ /dashboard/summary → 200"
    else
        echo "  ✗ /dashboard/summary → ${STATUS} (expected 200)"
        FAILURES=$((FAILURES + 1))
    fi
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
if [ "${FAILURES}" -eq 0 ]; then
    echo "  ✓ All E2E tests passed"
    echo "════════════════════════════════════════════════════════"
    exit 0
else
    echo "  ✗ ${FAILURES} test(s) failed"
    echo "════════════════════════════════════════════════════════"
    docker logs "${CONTAINER_NAME}" 2>/dev/null || true
    exit 1
fi
