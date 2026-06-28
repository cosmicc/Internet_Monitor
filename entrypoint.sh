#!/bin/sh
set -eu

echo "[entrypoint] Starting Internet Monitor with environment configuration"

python -u -m internet_monitor.monitor &
monitor_pid="$!"

gunicorn \
  --bind "0.0.0.0:${INTERNET_MONITOR_WEB_PORT:-5005}" \
  --workers "${INTERNET_MONITOR_WEB_WORKERS:-1}" \
  --threads "${INTERNET_MONITOR_WEB_THREADS:-2}" \
  --access-logfile - \
  --error-logfile - \
  "internet_monitor.web:create_app()" &
web_pid="$!"

stop_children() {
  kill "$monitor_pid" "$web_pid" 2>/dev/null || true
}

trap stop_children INT TERM

while true; do
  if ! kill -0 "$monitor_pid" 2>/dev/null; then
    wait "$monitor_pid"
    exit "$?"
  fi

  if ! kill -0 "$web_pid" 2>/dev/null; then
    wait "$web_pid"
    exit "$?"
  fi

  sleep 5
done
