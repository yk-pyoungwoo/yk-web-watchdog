#!/usr/bin/env bash
set -euo pipefail
SERVICE_NAME="yk-web-watchdog"

sudo systemctl stop "${SERVICE_NAME}.timer"
sudo systemctl disable "${SERVICE_NAME}.timer" || true
sudo systemctl status "${SERVICE_NAME}.timer" --no-pager || true

