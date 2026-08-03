#!/usr/bin/env bash
# Spin up PolicyLens for a local / LAN demo. Zero npm deps.
set -euo pipefail
cd "$(dirname "$0")"

export PORT="${PORT:-4177}"
# 0.0.0.0 so a teammate on the LAN (or a tunnel) can hit the UI
export HOST="${HOST:-0.0.0.0}"

echo "PolicyLens demo → http://localhost:${PORT}"
echo "  (bound to ${HOST}; set HOST=127.0.0.1 to lock to this machine only)"
echo "  Open the app and click “Run the 90-second demo”."
exec node server.js
