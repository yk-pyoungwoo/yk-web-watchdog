#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="yk-web-watchdog"

echo "=== Systemd Timer Status ==="
systemctl status "${SERVICE_NAME}.timer" --no-pager -l || echo "Timer not found"

echo ""
echo "=== Systemd Service Status ==="
systemctl status "${SERVICE_NAME}.service" --no-pager -l || echo "Service not found"

echo ""
echo "=== Recent Logs (last 20 lines) ==="
journalctl -u "${SERVICE_NAME}.service" --no-pager -n 20 || echo "No logs found"

echo ""
echo "=== Timer Schedule ==="
systemctl list-timers "${SERVICE_NAME}.timer" --no-pager || echo "Timer not found"

echo ""
echo "=== Check Log Files ==="
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${LOG_DIR:-$BASE_DIR/logs}"
if [ -d "$LOG_DIR" ]; then
    echo "Log directory: $LOG_DIR"
    echo "Latest log file:"
    ls -lht "$LOG_DIR"/*.log 2>/dev/null | head -5 || echo "No log files found"
else
    echo "Log directory not found: $LOG_DIR"
fi
