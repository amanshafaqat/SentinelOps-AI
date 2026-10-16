#!/bin/bash

# Clean up any stale uvicorn processes from previous runs
pkill -f "uvicorn backend.app.main:app" 2>/dev/null || true

# Ensure persistent .venv exists with all dependencies
if [ ! -f "/app/applet/.venv/bin/uvicorn" ]; then
    echo "[start-dev] Initializing Python virtual environment in workspace..."
    python3 -m venv --without-pip /app/applet/.venv
    curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    /app/applet/.venv/bin/python /tmp/get-pip.py --quiet
    /app/applet/.venv/bin/pip install --quiet -r backend/requirements.txt
fi

echo "[start-dev] Starting FastAPI backend on port 8001..."
/app/applet/.venv/bin/python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8001 &
BACKEND_PID=$!

cleanup() {
    echo "[start-dev] Shutting down services..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $VITE_PID 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[start-dev] Starting Vite dev server on port 3000..."
npx vite --port=3000 --host=0.0.0.0 &
VITE_PID=$!

wait $VITE_PID
