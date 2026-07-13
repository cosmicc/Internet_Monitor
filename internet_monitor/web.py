"""Flask dashboard for the latest ephemeral Internet Monitor status."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, render_template, request

from . import __version__
from .settings import Settings, load_settings


PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"
MAX_STATUS_BYTES = 256 * 1024
MAX_DISPLAY_TEXT_LENGTH = 256
VALID_STATES = {"up", "down", "warning", "unknown"}


def _format_status(state: object) -> dict[str, str]:
    """Map a status state to safe display text and a CSS class."""
    normalized = str(state or "unknown").lower()
    if normalized not in VALID_STATES:
        normalized = "unknown"

    labels = {
        "up": "Up",
        "down": "Down",
        "warning": "Degraded",
        "unknown": "Unknown",
    }
    return {
        "state": normalized,
        "text": labels[normalized],
        "css_class": f"status-{normalized}",
    }


def _safe_text(value: object, default: str = "") -> str:
    """Return bounded text suitable for escaped HTML and JSON responses."""
    text = str(value or default).strip()
    return text[:MAX_DISPLAY_TEXT_LENGTH]


def _status_timestamp(timestamp: object) -> datetime | None:
    """Parse the monitor's UTC timestamp format."""
    if not isinstance(timestamp, str) or not timestamp:
        return None
    try:
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def _snapshot_age_seconds(timestamp: object) -> float | None:
    """Return a non-negative snapshot age for valid UTC timestamps."""
    status_time = _status_timestamp(timestamp)
    if status_time is None:
        return None
    age = (datetime.now(timezone.utc) - status_time).total_seconds()
    return round(max(0.0, age), 2)


def _status_is_fresh(timestamp: object, status_max_age: int) -> bool:
    """Return whether a UTC status timestamp is inside the freshness window."""
    age = _snapshot_age_seconds(timestamp)
    if age is None:
        return False
    return status_max_age <= 0 or age <= status_max_age


def _number(value: object) -> float | int | None:
    """Return a finite display number or None for malformed snapshot values."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or value in {float("inf"), float("-inf")}:
        return None
    return value


def _empty_ping(host: str = "", *, configured: bool = True) -> dict[str, Any]:
    """Build an unknown ping result for startup or stale status."""
    status = _format_status("unknown")
    if not configured:
        status["text"] = "Not configured"
    return {
        "status": status,
        "host": host,
        "configured": configured,
        "minimum_latency_ms": None,
        "average_latency_ms": None,
        "maximum_latency_ms": None,
        "loss_percent": None,
        "transmitted": None,
        "received": None,
    }


def _sanitize_ping(
    raw_ping: object,
    fallback_host: str,
    *,
    configured: bool = True,
) -> dict[str, Any]:
    """Sanitize one ping result read from the monitor snapshot."""
    if not isinstance(raw_ping, dict):
        return _empty_ping(fallback_host, configured=configured)
    status = _format_status(raw_ping.get("state"))
    if not configured:
        status = _format_status("unknown")
        status["text"] = "Not configured"
    return {
        "status": status,
        "host": _safe_text(raw_ping.get("host"), fallback_host),
        "configured": configured,
        "minimum_latency_ms": _number(raw_ping.get("minimum_latency_ms")),
        "average_latency_ms": _number(raw_ping.get("average_latency_ms")),
        "maximum_latency_ms": _number(raw_ping.get("maximum_latency_ms")),
        "loss_percent": _number(raw_ping.get("loss_percent")),
        "transmitted": _number(raw_ping.get("transmitted")),
        "received": _number(raw_ping.get("received")),
    }


def _path_nodes(
    *,
    server_state: str,
    gateways: list[dict[str, Any]],
    internet: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build the ordered Server-to-Internet topology shown by the dashboard."""
    server = _empty_ping("Monitoring service")
    server.update(
        {
            "id": "server",
            "label": "Server",
            "status": _format_status(server_state),
        }
    )
    nodes = [server]
    for index, gateway in enumerate(gateways, start=1):
        nodes.append(
            {
                **gateway,
                "id": f"gateway-{index}",
                "label": f"Gateway {index}",
            }
        )
    nodes.append({**internet, "id": "internet", "label": "Internet"})
    return nodes


def _empty_dashboard(settings: Settings) -> dict[str, Any]:
    """Build an unknown-state dashboard using the configured targets."""
    unknown = _format_status("unknown")
    gateways = [
        _empty_ping(settings.monitor.gateway_1_ip, configured=bool(settings.monitor.gateway_1_ip)),
        _empty_ping(settings.monitor.gateway_2_ip, configured=bool(settings.monitor.gateway_2_ip)),
    ]
    internet = {
        **_empty_ping(settings.monitor.ping_host),
        "used_backup": False,
        "targets": [
            {
                **_empty_ping(host),
                "role": role,
            }
            for role, host in (
                ("Primary", settings.monitor.ping_host),
                ("Backup", settings.monitor.backup_ping_host),
            )
            if host
        ],
    }
    return {
        "fresh": False,
        "last_updated": "Waiting for the first monitor check",
        "snapshot_age_seconds": None,
        "diagnosis": {
            "status": unknown,
            "title": "Waiting for monitor data",
            "detail": "The first concurrent network and DNS check has not completed.",
        },
        "path_nodes": _path_nodes(
            server_state="unknown",
            gateways=gateways,
            internet=internet,
        ),
        "internet": internet,
        "gateways": gateways,
        "dns": {
            "status": unknown,
            "hostname": settings.monitor.dns_host,
            "record_type": settings.monitor.dns_record_type,
            "slow_threshold_ms": settings.monitor.dns_slow_threshold_ms,
            "resolver": {
                "status": unknown,
                "response_time_ms": None,
                "response_status": "Unknown",
                "answer_count": None,
            },
            "servers": [
                {
                    "server": server,
                    "status": unknown,
                    "response_time_ms": None,
                    "response_status": "Unknown",
                    "answer_count": None,
                }
                for server in settings.monitor.dns_servers
            ],
        },
        "monitor": {
            "interval_seconds": settings.monitor.interval,
            "loop_duration_ms": None,
        },
    }


def _read_status_file(status_path: str) -> dict[str, Any] | None:
    """Read a bounded JSON status snapshot, returning None on invalid input."""
    try:
        with open(status_path, "r", encoding="utf-8") as handle:
            raw_status = handle.read(MAX_STATUS_BYTES + 1)
    except OSError:
        return None

    if len(raw_status.encode("utf-8")) > MAX_STATUS_BYTES:
        return None
    try:
        status = json.loads(raw_status)
    except json.JSONDecodeError:
        return None
    return status if isinstance(status, dict) else None


def load_dashboard(settings: Settings) -> dict[str, Any]:
    """Load and sanitize the current dashboard snapshot."""
    dashboard = _empty_dashboard(settings)
    data = _read_status_file(settings.web.status_path)
    if data is None or not _status_is_fresh(
        data.get("timestamp"), settings.web.status_max_age
    ):
        return dashboard

    internet_data = data.get("internet")
    dns_data = data.get("dns")
    if not isinstance(internet_data, dict) or not isinstance(dns_data, dict):
        return dashboard

    raw_gateways = data.get("gateways")
    gateway_by_position: dict[int, dict[str, Any]] = {}
    if isinstance(raw_gateways, list):
        for raw_gateway in raw_gateways:
            if not isinstance(raw_gateway, dict):
                continue
            position = raw_gateway.get("position")
            if position in {1, 2}:
                gateway_by_position[position] = raw_gateway

    gateway_hosts = (
        settings.monitor.gateway_1_ip,
        settings.monitor.gateway_2_ip,
    )
    gateways: list[dict[str, Any]] = []
    for position, fallback_host in enumerate(gateway_hosts, start=1):
        raw_gateway = gateway_by_position.get(position)
        configured = bool(fallback_host)
        if isinstance(raw_gateway, dict):
            configured = bool(raw_gateway.get("configured", configured))
        gateways.append(
            _sanitize_ping(raw_gateway, fallback_host, configured=configured)
        )

    internet = _sanitize_ping(internet_data, settings.monitor.ping_host)
    internet["used_backup"] = bool(internet_data.get("used_backup", False))
    targets: list[dict[str, Any]] = []
    raw_targets = internet_data.get("targets")
    if isinstance(raw_targets, list):
        for raw_target in raw_targets:
            if not isinstance(raw_target, dict):
                continue
            host = _safe_text(raw_target.get("host"))
            if not host:
                continue
            target = _sanitize_ping(raw_target, host)
            target["role"] = _safe_text(raw_target.get("role"), "Target")
            targets.append(target)
    if not targets:
        targets = dashboard["internet"]["targets"]
    internet["targets"] = targets

    resolver_data = dns_data.get("resolver")
    if not isinstance(resolver_data, dict):
        resolver_data = {}
    resolver_status = _format_status(resolver_data.get("state"))
    resolver_response_labels = {
        "up": "Resolved",
        "down": "Failed",
        "warning": "Degraded",
        "unknown": "Unknown",
    }
    resolver = {
        "status": resolver_status,
        "response_time_ms": _number(resolver_data.get("response_time_ms")),
        "response_status": resolver_response_labels[resolver_status["state"]],
        "answer_count": None,
    }

    sanitized_servers: list[dict[str, Any]] = []
    raw_servers = dns_data.get("servers")
    if isinstance(raw_servers, list):
        for item in raw_servers:
            if not isinstance(item, dict):
                continue
            server = _safe_text(item.get("server"))
            if not server:
                continue
            sanitized_servers.append(
                {
                    "server": server,
                    "status": _format_status(item.get("state")),
                    "response_time_ms": _number(item.get("response_time_ms")),
                    "response_status": _safe_text(
                        item.get("response_status"), "Unknown"
                    ),
                    "answer_count": _number(item.get("answer_count")),
                }
            )

    diagnosis_data = data.get("diagnosis")
    if not isinstance(diagnosis_data, dict):
        diagnosis_data = {}
    diagnosis = {
        "status": _format_status(diagnosis_data.get("state")),
        "title": _safe_text(diagnosis_data.get("title"), "Status unavailable"),
        "detail": _safe_text(
            diagnosis_data.get("detail"),
            "The monitor did not provide a path diagnosis.",
        ),
    }

    dashboard.update(
        {
            "fresh": True,
            "last_updated": _safe_text(data.get("timestamp"), "Unknown"),
            "snapshot_age_seconds": _snapshot_age_seconds(data.get("timestamp")),
            "diagnosis": diagnosis,
            "internet": internet,
            "gateways": gateways,
            "dns": {
                "status": _format_status(dns_data.get("state")),
                "hostname": _safe_text(
                    dns_data.get("hostname"), settings.monitor.dns_host
                ),
                "record_type": _safe_text(
                    dns_data.get("record_type"), settings.monitor.dns_record_type
                ),
                "slow_threshold_ms": _number(dns_data.get("slow_threshold_ms"))
                or settings.monitor.dns_slow_threshold_ms,
                "resolver": resolver,
                "servers": sanitized_servers or dashboard["dns"]["servers"],
            },
            "monitor": {
                "interval_seconds": _number(data.get("interval_seconds"))
                or settings.monitor.interval,
                "loop_duration_ms": _number(data.get("loop_duration_ms")),
            },
        }
    )
    dashboard["path_nodes"] = _path_nodes(
        server_state="up",
        gateways=gateways,
        internet=internet,
    )
    return dashboard


def create_app(settings: Settings | None = None) -> Flask:
    """Create the Flask application with explicit or environment-loaded settings."""
    app_settings = settings or load_settings()
    web_settings = app_settings.web
    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(STATIC_DIR),
    )

    @app.before_request
    def limit_remote_address():
        """Restrict dashboard clients by direct address when configured."""
        if request.endpoint in {"health", "favicon"} or not web_settings.allowed_hosts:
            return None

        # X-Forwarded-For remains intentionally untrusted until a proxy boundary
        # is explicitly configured and documented.
        if request.remote_addr not in web_settings.allowed_hosts:
            abort(403, description="You are not allowed to access this resource")
        return None

    @app.after_request
    def add_security_headers(response):
        """Prevent caching, framing, MIME sniffing, and unexpected content loads."""
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.route("/health")
    def health():
        """Return a lightweight liveness response for Docker health checks."""
        return "ok", 200

    @app.route("/favicon.ico")
    def favicon():
        """Avoid a noisy browser-side 404 when no branded icon is configured."""
        return "", 204

    @app.route("/api/status")
    def status_api():
        """Return the sanitized current snapshot for same-origin live polling."""
        return jsonify(load_dashboard(app_settings))

    @app.route("/")
    def index():
        """Render the latest Internet and DNS status without persisted logs."""
        return render_template(
            "index.html",
            title=web_settings.title,
            version=__version__,
            dashboard=load_dashboard(app_settings),
            refresh_interval=web_settings.refresh_interval,
        )

    return app


def main() -> None:
    """Start the Flask development server for local debugging."""
    settings = load_settings()
    app = create_app(settings)
    app.run(host="0.0.0.0", port=settings.web.port, debug=False)


if __name__ == "__main__":
    main()
