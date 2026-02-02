#!/usr/bin/env bash
# Quick check script for yk-web-watchdog status

SERVICE_NAME="yk-web-watchdog"

echo "🔍 YK Web Watchdog Status Check"
echo "=================================="
echo ""

# Check if timer is active
echo "📅 Timer Status:"
if systemctl is-active --quiet "${SERVICE_NAME}.timer"; then
    echo "   ✅ Timer is ACTIVE"
    systemctl list-timers "${SERVICE_NAME}.timer" --no-pager 2>/dev/null | tail -2 || true
else
    echo "   ❌ Timer is INACTIVE"
fi
echo ""

# Check last service run
echo "🔄 Last Service Run:"
systemctl status "${SERVICE_NAME}.service" --no-pager -l 2>/dev/null | head -15 || echo "   Service not found"
echo ""

# Check recent logs
echo "📋 Recent Logs (last 10 lines):"
journalctl -u "${SERVICE_NAME}.service" --no-pager -n 10 2>/dev/null || echo "   No logs found"
echo ""

# Check log files
echo "📁 Log Files:"
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="${LOG_DIR:-$BASE_DIR/logs}"
if [ -d "$LOG_DIR" ]; then
    LATEST_LOG=$(ls -t "$LOG_DIR"/*.log 2>/dev/null | head -1)
    if [ -n "$LATEST_LOG" ]; then
        echo "   Latest: $(basename "$LATEST_LOG")"
        echo "   Size: $(du -h "$LATEST_LOG" | cut -f1)"
        echo "   Last modified: $(stat -c %y "$LATEST_LOG" 2>/dev/null | cut -d. -f1)"
    else
        echo "   No log files found"
    fi
else
    echo "   Log directory not found: $LOG_DIR"
fi
echo ""

# Check state file
echo "💾 State File:"
STATE_FILE="${STATE_FILE:-$BASE_DIR/state.json}"
if [ -f "$STATE_FILE" ]; then
    echo "   ✅ State file exists: $STATE_FILE"
    echo "   Last modified: $(stat -c %y "$STATE_FILE" 2>/dev/null | cut -d. -f1)"
    if command -v jq &> /dev/null; then
        echo "   Current issue status:"
        jq -r '._global.has_issue // "unknown"' "$STATE_FILE" 2>/dev/null || echo "   (cannot parse)"
    fi
else
    echo "   ❌ State file not found: $STATE_FILE"
fi
