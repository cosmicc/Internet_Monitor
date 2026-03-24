#!/usr/bin/env python3
"""
Internet Monitor - Log Viewer Web UI

Features:
- Shows connection log (tail of the configured log file).
- Displays Internet and DNS status indicators based on a shared status file
  written by the monitor process after each check.
- Status is considered valid only if the timestamp is recent; otherwise we
  fall back to "Unknown" to avoid using stale state.
- Auto-refresh interval is tied to [monitor].interval from config.ini.
- Allows clearing the log via a "Clear Log" button.
- Optional IP allow-list based on [web].allowed_hosts in config.ini.
"""

from __future__ import annotations

import os
import json
import configparser
from typing import List, Optional, Dict
from datetime import datetime, timezone

from flask import Flask, request, render_template, abort, redirect, url_for

# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

CONFIG_ENV_VAR = "INTERNET_MONITOR_CONFIG"
DEFAULT_CONFIG_PATH = "/config/internet_monitor/config.ini"
CONFIG_PATH = os.environ.get(CONFIG_ENV_VAR, DEFAULT_CONFIG_PATH)

parser = configparser.ConfigParser()
parser.read(CONFIG_PATH)

if not parser.has_section("web"):
    raise RuntimeError(f"[web] section missing in config file: {CONFIG_PATH}")

WEB = parser["web"]

TITLE: str = WEB.get("title", "Internet Connection Monitor")
LOG_PATH: str = WEB.get("log_path", "/var/log/connection.log")
LOG_LINES: int = WEB.getint("log_lines", 100)
FLASK_PORT: int = WEB.getint("port", 5005)

# Status file: defaults to same directory as log, name "connection_status.json"
DEFAULT_STATUS_PATH = os.path.join(os.path.dirname(LOG_PATH), "connection_status.json")
STATUS_PATH: str = WEB.get("status_path", DEFAULT_STATUS_PATH)

# Max age in seconds for status to be considered "fresh".
# If 0 or negative, the age check is disabled (status is always accepted).
STATUS_MAX_AGE: int = WEB.getint("status_max_age", 300)  # default 5 minutes

_raw_hosts = WEB.get("allowed_hosts", "").replace(",", " ")
ALLOWED_HOSTS: List[str] = [h.strip() for h in _raw_hosts.split() if h.strip()]

LOG_PATH = os.path.abspath(LOG_PATH)
STATUS_PATH = os.path.abspath(STATUS_PATH)

# Auto-refresh interval: follow [monitor].interval if present, otherwise default 60
REFRESH_INTERVAL: int = 60
if parser.has_section("monitor") and parser.has_option("monitor", "interval"):
    try:
        REFRESH_INTERVAL = parser.getint("monitor", "interval")
    except ValueError:
        REFRESH_INTERVAL = 60


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_log_lines(limit: Optional[int] = None) -> List[str]:
    """
    Load lines from the log file.

    If 'limit' is given, return only the last 'limit' lines.
    """
    if not os.path.exists(LOG_PATH):
        return []

    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return []

    if not lines:
        return []

    if limit is not None and limit > 0:
        return lines[-limit:]
    return lines


def load_log_text() -> str:
    """
    Return the last LOG_LINES lines as a single string for display.
    """
    lines = load_log_lines(LOG_LINES)
    if not lines:
        return ""
    return "\n".join(lines)


def _format_status(state: str) -> Dict[str, str]:
    """
    Map a simple state string to the dict the template expects.

    state: one of "up", "down", "warning", "unknown".
    """
    state = (state or "unknown").lower()

    if state == "up":
        return {"state": "up", "text": "Up", "css_class": "status-up"}
    if state == "down":
        return {"state": "down", "text": "Down", "css_class": "status-down"}
    if state == "warning":
        return {"state": "warning", "text": "Degraded", "css_class": "status-warning"}

    return {"state": "unknown", "text": "Unknown", "css_class": "status-unknown"}


def _status_is_fresh(ts_str: str) -> bool:
    """
    Return True if the given ISO8601-like timestamp is within STATUS_MAX_AGE seconds.
    Timestamps are expected like "2025-12-07T12:34:56Z" (UTC).
    """
    if STATUS_MAX_AGE <= 0:
        # Age checking disabled
        return True

    if not ts_str:
        return False

    try:
        # Parse as UTC with trailing Z
        ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False

    now = datetime.now(timezone.utc)
    age = (now - ts).total_seconds()
    return age >= 0 and age <= STATUS_MAX_AGE


def load_status() -> tuple[Dict[str, str], Dict[str, str]]:
    """
    Load Internet + DNS status from STATUS_PATH.

    Expected JSON structure written by the monitor:

        {
          "timestamp": "2025-12-07T12:34:56Z",
          "internet": {"state": "up" | "down" | "warning" | "unknown"},
          "dns":      {"state": "up" | "down" | "warning" | "unknown"}
        }

    Behavior:
      - If the file does not exist, both statuses are "unknown".
      - If the timestamp is older than STATUS_MAX_AGE seconds, both are "unknown".
      - If parsing fails, both are "unknown".
    """
    if not os.path.exists(STATUS_PATH):
        return _format_status("unknown"), _format_status("unknown")

    try:
        with open(STATUS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return _format_status("unknown"), _format_status("unknown")

    if not isinstance(data, dict):
        return _format_status("unknown"), _format_status("unknown")

    ts_str = data.get("timestamp", "")
    stale = not _status_is_fresh(ts_str)

    internet_state = "unknown"
    dns_state = "unknown"

    internet = data.get("internet")
    dns = data.get("dns")

    if isinstance(internet, dict):
        internet_state = internet.get("state", "unknown")
    if isinstance(dns, dict):
        dns_state = dns.get("state", "unknown")

    if stale:
        # Keep last known state when stale data is present
        # so the UI does not show 'unknown' unless truly missing.
        if internet_state not in ("up", "down", "warning"):
            internet_state = "unknown"
        if dns_state not in ("up", "down", "warning"):
            dns_state = "unknown"

        # You can tune staleness behavior with [web].status_max_age.
        log_msg = (
            f"Status at {ts_str} is stale (age > {STATUS_MAX_AGE}s); "
            f"keeping last known states: internet={internet_state}, dns={dns_state}"
        )
        # No logging util imported here; writing to stdout for visibility.
        print(log_msg)

        return _format_status(internet_state), _format_status(dns_state)

    return _format_status(internet_state), _format_status(dns_state)

    if isinstance(internet, dict):
        internet_state = internet.get("state", "unknown")
    if isinstance(dns, dict):
        dns_state = dns.get("state", "unknown")

    return _format_status(internet_state), _format_status(dns_state)


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)


@app.before_request
def limit_remote_addr():
    """
    Optional IP restriction based on [web].allowed_hosts.
    If the list is empty, allow all.
    """
    if not ALLOWED_HOSTS:
        return

    remote = request.remote_addr
    if remote not in ALLOWED_HOSTS:
        abort(403, description="You're not allowed to access this resource")


@app.route("/health")
def health():
    return "ok", 200


@app.route("/")
def index():
    log_text = load_log_text()
    internet_status, dns_status = load_status()

    return render_template(
        "index.html",
        title=TITLE,
        log=log_text,
        log_lines=LOG_LINES,
        log_path=LOG_PATH,
        internet_status=internet_status,
        dns_status=dns_status,
        refresh_interval=REFRESH_INTERVAL,
    )


@app.route("/clear-log", methods=["POST"])
def clear_log():
    """
    Truncate the log file to zero bytes (create if missing),
    then redirect back to the main page.
    """
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "w", encoding="utf-8"):
            pass
    except OSError:
        pass

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=True)
