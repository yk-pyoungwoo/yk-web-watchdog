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

# Ensure log file exists and is writable
touch "$LOGFILE" 2>/dev/null || {
    echo "ERROR: Cannot create log file: $LOGFILE" >&2
    exit 1
}

echo "[$(date '+%F %T %Z')] run.sh start" >> "$LOGFILE" 2>&1 || {
    echo "ERROR: Cannot write to log file: $LOGFILE" >&2
    exit 1
}

/usr/bin/python3 -u "$BASE_DIR/healthcheck.py" >> "$LOGFILE" 2>&1
EXIT_CODE=$?

echo "[$(date '+%F %T %Z')] run.sh end (exit=$EXIT_CODE)" >> "$LOGFILE" 2>&1

exit $EXIT_CODE

