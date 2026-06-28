"""Flask web UI for viewing Internet Monitor status and logs."""

from __future__ import annotations

import json
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Flask, abort, redirect, render_template, request, url_for

from .settings import Settings, WebSettings, load_settings


TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def load_log_lines(log_path: str, limit: Optional[int] = None) -> list[str]:
    """
    Load lines from the configured log file.

    If limit is given, return only the last limit lines. File read errors return
    an empty list so the dashboard remains available while storage is repaired.
    """
    if not os.path.exists(log_path):
        return []

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
            if limit is not None and limit > 0:
                lines = list(deque(handle, maxlen=limit))
            else:
                lines = handle.readlines()
    except OSError:
        return []

    return [line.rstrip("\n") for line in lines]


def load_log_text(settings: WebSettings) -> str:
    """Return the last configured number of log lines as display text."""
    return "\n".join(load_log_lines(settings.log_path, settings.log_lines))


def _format_status(state: str) -> dict[str, str]:
    """Map a status state to template text and CSS class names."""
    normalized = (state or "unknown").lower()

    if normalized == "up":
        return {"state": "up", "text": "Up", "css_class": "status-up"}
    if normalized == "down":
        return {"state": "down", "text": "Down", "css_class": "status-down"}
    if normalized == "warning":
        return {
            "state": "warning",
            "text": "Degraded",
            "css_class": "status-warning",
        }

    return {
        "state": "unknown",
        "text": "Unknown",
        "css_class": "status-unknown",
    }


def _status_is_fresh(timestamp: str, status_max_age: int) -> bool:
    """Return True when the UTC status timestamp is within the freshness window."""
    if status_max_age <= 0:
        return True
    if not timestamp:
        return False

    try:
        status_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return False

    age = (datetime.now(timezone.utc) - status_time).total_seconds()
    return 0 <= age <= status_max_age


def load_status(settings: WebSettings) -> tuple[dict[str, str], dict[str, str]]:
    """
    Load Internet and DNS status from the monitor status JSON file.

    If the file is missing or malformed, both statuses are unknown. If the file
    is stale but contains a valid last-known state, the UI keeps that state
    instead of hiding useful outage context.
    """
    if not os.path.exists(settings.status_path):
        return _format_status("unknown"), _format_status("unknown")

    try:
        with open(settings.status_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return _format_status("unknown"), _format_status("unknown")

    if not isinstance(data, dict):
        return _format_status("unknown"), _format_status("unknown")

    internet_state = "unknown"
    dns_state = "unknown"
    internet = data.get("internet")
    dns = data.get("dns")

    if isinstance(internet, dict):
        internet_state = internet.get("state", "unknown")
    if isinstance(dns, dict):
        dns_state = dns.get("state", "unknown")

    if not _status_is_fresh(data.get("timestamp", ""), settings.status_max_age):
        if internet_state not in {"up", "down", "warning"}:
            internet_state = "unknown"
        if dns_state not in {"up", "down", "warning"}:
            dns_state = "unknown"

    return _format_status(internet_state), _format_status(dns_state)


def create_app(settings: Settings | None = None) -> Flask:
    """Create the Flask application with explicit or environment-loaded settings."""
    app_settings = settings or load_settings()
    web_settings = app_settings.web
    app = Flask(__name__, template_folder=str(TEMPLATE_DIR))

    @app.before_request
    def limit_remote_addr():
        """
        Optionally restrict access by direct client IP.

        X-Forwarded-For is intentionally ignored because it is spoofable unless
        a trusted reverse proxy has been explicitly configured in front of Flask.
        """
        if not web_settings.allowed_hosts:
            return None

        remote = request.remote_addr
        if remote not in web_settings.allowed_hosts:
            abort(403, description="You are not allowed to access this resource")
        return None

    @app.route("/health")
    def health():
        """Return a lightweight liveness response for Docker healthchecks."""
        return "ok", 200

    @app.route("/")
    def index():
        """Render the log dashboard."""
        internet_status, dns_status = load_status(web_settings)

        return render_template(
            "index.html",
            title=web_settings.title,
            log=load_log_text(web_settings),
            log_lines=web_settings.log_lines,
            log_path=web_settings.log_path,
            internet_status=internet_status,
            dns_status=dns_status,
            refresh_interval=web_settings.refresh_interval,
        )

    @app.route("/clear-log", methods=["POST"])
    def clear_log():
        """Truncate the configured log file and return to the dashboard."""
        try:
            os.makedirs(os.path.dirname(web_settings.log_path), exist_ok=True)
            with open(web_settings.log_path, "w", encoding="utf-8"):
                pass
        except OSError:
            pass

        return redirect(url_for("index"))

    return app


def main() -> None:
    """Start the Flask development server for local debugging."""
    settings = load_settings()
    app = create_app(settings)
    app.run(host="0.0.0.0", port=settings.web.port, debug=False)


if __name__ == "__main__":
    main()
