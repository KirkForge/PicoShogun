#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")" || exit 1

VENV=".venv/bin/activate"
if [ ! -f "$VENV" ]; then
  echo "ERROR: Virtual environment not found at .venv/" >&2
  echo "Create one with: python3 -m venv .venv && source .venv/bin/activate && pip install -e ." >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$VENV"

HOST="${SHOGUN_HOST:-0.0.0.0}"
PORT="${SHOGUN_PORT:-8765}"
WORKERS="${SHOGUN_WORKERS:-1}"

uvicorn api.server:app --host "$HOST" --port "$PORT" --workers "$WORKERS" &
API_PID=$!
echo "$API_PID"
sleep 3
curl -sf "http://localhost:${PORT}/health/live" || echo "WARN: Health check failed"
