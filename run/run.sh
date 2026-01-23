#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$BASE_DIR"

# Load env
set -a
# shellcheck disable=SC1091
source "$BASE_DIR/.env"
set +a

mkdir -p "${LOG_DIR:-$BASE_DIR/logs}"

# Run (python stdout/stderr)
TODAY="$(date +%F)"
LOGFILE="${LOG_DIR:-$BASE_DIR/logs}/${TODAY}.log"

echo "[$(date '+%F %T %Z')] run.sh start" >> "$LOGFILE"
/usr/bin/python3 -u "$BASE_DIR/healthcheck.py" >> "$LOGFILE" 2>&1
echo "[$(date '+%F %T %Z')] run.sh end" >> "$LOGFILE"

