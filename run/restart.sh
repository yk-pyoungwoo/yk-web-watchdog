#!/usr/bin/env bash
set -euo pipefail
SERVICE_NAME="yk-web-watchdog"
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE_DIR"

set -a
# shellcheck disable=SC1091
source "$BASE_DIR/.env"
set +a

# Must match healthcheck.py STATE_FILE (from .env)
STATE_FILE="${STATE_FILE:-$BASE_DIR/state.json}"
echo "Setting force_restart_report in: $STATE_FILE"

if [ -f "$STATE_FILE" ]; then
    # Use python to safely update JSON
    python3 << EOF
import json
import os

state_file = "${STATE_FILE}"
if os.path.exists(state_file):
    with open(state_file, 'r', encoding='utf-8') as f:
        state = json.load(f)
    
    if '_global' not in state:
        state['_global'] = {}
    
    state['_global']['force_restart_report'] = True
    
    with open(state_file, 'w', encoding='utf-8') as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
EOF
fi

sudo systemctl restart "${SERVICE_NAME}.timer"
sudo systemctl start "${SERVICE_NAME}.service"

echo ""
echo "=== Service (last run) ==="
systemctl status "${SERVICE_NAME}.service" --no-pager -l | head -20 || true

echo ""
echo "=== Timer ==="
systemctl status "${SERVICE_NAME}.timer" --no-pager

LOG_DIR="${LOG_DIR:-$BASE_DIR/logs}"
TODAY="$(date +%F)"
LOGFILE="${LOG_DIR}/${TODAY}.log"
if [ -f "$LOGFILE" ]; then
    echo ""
    echo "=== Last log lines ($LOGFILE) ==="
    grep -E 'notify=|restart|slack=|force_restart' "$LOGFILE" | tail -5 || true
fi

