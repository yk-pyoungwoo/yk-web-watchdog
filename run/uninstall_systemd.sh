#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="yk-web-watchdog"
sudo systemctl stop "${SERVICE_NAME}.timer" || true
sudo systemctl disable "${SERVICE_NAME}.timer" || true

sudo rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
sudo rm -f "/etc/systemd/system/${SERVICE_NAME}.timer"

sudo systemctl daemon-reload
echo "Uninstalled systemd units for ${SERVICE_NAME}"

