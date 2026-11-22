#!/bin/sh
# run-demo.sh — Start SecureWatch AI in demo mode with one command.
#
#   ./run-demo.sh
#
# Starts the Flask backend (simulated logs, no PostgreSQL, no API keys)
# on http://localhost:5000 and the React dashboard on http://localhost:3000.
# Stop with Ctrl+C — both services shut down.
#
# Requirements: Python 3.12 + Node.js 18+ (or use the venv at
# ../.venv-securewatch if you created one, see README).
set -e
cd "$(dirname "$0")"
ROOT="$PWD"

# ── Python backend ────────────────────────────────────────────────────────
# Paths are absolute: the backend is started from backend/, so relative
# paths would resolve against the wrong directory.
if [ -x "$ROOT/../.venv-securewatch/bin/python" ]; then
    PY="$ROOT/../.venv-securewatch/bin/python"
elif [ -x "$ROOT/backend/venv/bin/python" ]; then
    PY="$ROOT/backend/venv/bin/python"
else
    PY="python3"
fi

echo "==> Starting backend (demo mode) on http://localhost:5000 ..."
(cd backend && "$PY" main.py --demo > /tmp/securewatch-demo.log 2>&1 & echo $! > /tmp/securewatch-backend.pid)
trap 'kill "$(cat /tmp/securewatch-backend.pid)" 2>/dev/null; exit 0' INT TERM

# Wait until the API answers (max ~30s).
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:5000/api/health >/dev/null 2>&1; then
        echo "==> Backend is up."
        break
    fi
    sleep 1
done

# ── React frontend ────────────────────────────────────────────────────────
cd frontend
if [ ! -d node_modules ]; then
    echo "==> Installing frontend dependencies (first run only) ..."
    npm install
fi
if [ ! -d dist ]; then
    echo "==> Building frontend ..."
    npm run build
fi
echo "==> Dashboard: http://localhost:3000  (backend: http://localhost:5000)"
echo "    Press Ctrl+C to stop."
npm run preview
