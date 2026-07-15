#!/bin/sh
set -eu
umask 077

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) INFO internet_monitor.entrypoint: Starting Internet Monitor processes."

python -u -m internet_monitor.monitor &
monitor_pid="$!"

gunicorn \
  --bind "0.0.0.0:5005" \
  --workers "${WEB_WORKERS:-1}" \
  --threads "${WEB_THREADS:-2}" \
  --worker-tmp-dir /tmp \
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
