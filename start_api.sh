#!/bin/bash
# shellcheck disable=SC2097
cd "$(dirname "$0")" || exit
/home/kirk/.picoclaw/workspace/Secdev_kimi/venv/bin/uvicorn api.server:app --host 0.0.0.0 --port 8765 &
API_PID=$!
echo "$API_PID"
sleep 3
curl -s http://localhost:8765/health
