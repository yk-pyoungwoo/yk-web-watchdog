#!/usr/bin/env bash
set -euo pipefail
SERVICE_NAME="yk-web-watchdog"

sudo systemctl restart "${SERVICE_NAME}.timer"
sudo systemctl start "${SERVICE_NAME}.service"
sudo systemctl status "${SERVICE_NAME}.timer" --no-pager

