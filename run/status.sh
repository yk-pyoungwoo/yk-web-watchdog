#!/usr/bin/env bash
set -euo pipefail
SERVICE_NAME="yk-web-watchdog"

echo "=== timer ==="
sudo systemctl status "${SERVICE_NAME}.timer" --no-pager || true
echo
echo "=== last runs ==="
sudo journalctl -u "${SERVICE_NAME}.service" -n 50 --no-pager || true

