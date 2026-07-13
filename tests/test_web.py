"""Tests for the log-free Flask status dashboard."""

import json
from datetime import datetime, timezone
from pathlib import Path

from internet_monitor.settings import (
    MonitorSettings,
    PushoverSettings,
    Settings,
    WebSettings,
)
from internet_monitor.web import create_app


def _settings(tmp_path: Path, *, allowed_hosts=()):
    """Build isolated app settings backed by an ephemeral snapshot path."""
    status_path = tmp_path / "status.json"
    return Settings(
        monitor=MonitorSettings(
            status_path=str(status_path),
            interval=15,
            gateway_1_ip="10.0.0.1",
            gateway_2_ip="203.0.113.1",
            dns_servers=("1.1.1.1", "8.8.8.8"),
        ),
        web=WebSettings(
            title="Test Monitor",
            status_path=str(status_path),
            allowed_hosts=allowed_hosts,
            refresh_interval=15,
        ),
        pushover=PushoverSettings(),
    )


def test_index_renders_current_status_and_per_server_timings(tmp_path: Path):
    """The dashboard should show current metrics without a log viewer."""
    settings = _settings(tmp_path)
    status_path = tmp_path / "status.json"
    status_path.write_text(
        json.dumps(
                {
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "interval_seconds": 15,
                    "loop_duration_ms": 125.5,
                    "diagnosis": {
                        "state": "warning",
                        "title": "Connection degraded",
                        "detail": "The active Internet target has packet loss.",
                    },
                    "gateways": [
                        {
                            "position": 1,
                            "configured": True,
                            "state": "up",
                            "host": "10.0.0.1",
                            "minimum_latency_ms": 0.8,
                            "average_latency_ms": 1.2,
                            "maximum_latency_ms": 2.1,
                            "loss_percent": 0,
                            "transmitted": 5,
                            "received": 5,
                        },
                        {
                            "position": 2,
                            "configured": True,
                            "state": "up",
                            "host": "203.0.113.1",
                            "minimum_latency_ms": 7.0,
                            "average_latency_ms": 8.2,
                            "maximum_latency_ms": 9.4,
                            "loss_percent": 0,
                            "transmitted": 5,
                            "received": 5,
                        },
                    ],
                    "internet": {
                        "state": "warning",
                        "host": "8.8.8.8",
                        "minimum_latency_ms": 20.0,
                        "average_latency_ms": 24.5,
                        "maximum_latency_ms": 30.0,
                        "loss_percent": 10,
                        "transmitted": 5,
                        "received": 4,
                        "used_backup": True,
                        "targets": [
                            {
                                "role": "Primary",
                                "state": "down",
                                "host": "1.1.1.1",
                                "loss_percent": 100,
                                "transmitted": 5,
                                "received": 0,
                            },
                            {
                                "role": "Backup",
                                "state": "warning",
                                "host": "8.8.8.8",
                                "minimum_latency_ms": 20.0,
                                "average_latency_ms": 24.5,
                                "maximum_latency_ms": 30.0,
                                "loss_percent": 10,
                                "transmitted": 5,
                                "received": 4,
                            },
                        ],
                    },
                "dns": {
                    "state": "warning",
                    "hostname": "www.google.com",
                    "record_type": "A",
                    "slow_threshold_ms": 500,
                    "resolver": {"state": "up", "response_time_ms": 5.25},
                    "servers": [
                            {
                                "server": "1.1.1.1",
                                "state": "up",
                                "response_time_ms": 11,
                                "response_status": "NOERROR",
                                "answer_count": 1,
                            },
                            {
                                "server": "8.8.8.8",
                                "state": "warning",
                                "response_time_ms": 725,
                                "response_status": "NOERROR",
                                "answer_count": 1,
                        },
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    response = create_app(settings).test_client().get("/")

    assert response.status_code == 200
    assert b"Test Monitor" in response.data
    assert b"Connection Path" in response.data
    assert b"Gateway Details" in response.data
    assert b"Internet Performance" in response.data
    assert b"DNS Health" in response.data
    assert b"Connection degraded" in response.data
    assert b"10.0.0.1" in response.data
    assert b"203.0.113.1" in response.data
    assert b"1.1.1.1" in response.data
    assert b"11.00 ms" in response.data
    assert b"725.00 ms" in response.data
    assert b"red marks loss" in response.data
    assert b"data-loss-series" in response.data
    assert b"Packet loss" in response.data
    assert b"Connection Log" not in response.data
    assert b"Clear Log" not in response.data
    assert b"http-equiv=\"refresh\"" not in response.data
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]

    script_response = create_app(settings).test_client().get(
        "/static/dashboard.js"
    )
    assert script_response.status_code == 200
    assert b"chart-segment-loss" in script_response.data
    assert b"chart-loss-outage" in script_response.data
    assert b"no latency response" in script_response.data

    api_response = create_app(settings).test_client().get("/api/status")
    assert api_response.status_code == 200
    api_data = api_response.get_json()
    assert api_data["diagnosis"]["title"] == "Connection degraded"
    assert api_data["path_nodes"][1]["label"] == "Gateway 1"
    assert api_data["internet"]["targets"][1]["role"] == "Backup"
    assert api_data["dns"]["servers"][0]["response_status"] == "NOERROR"


def test_missing_snapshot_renders_configured_targets_as_unknown(tmp_path: Path):
    """Startup should show configured servers without implying stale health."""
    response = create_app(_settings(tmp_path)).test_client().get("/")

    assert response.status_code == 200
    assert b"Waiting for the first monitor check" in response.data
    assert response.data.count(b"Unknown") >= 7
    assert b"Connection Path" in response.data
    assert b"10.0.0.1" in response.data
    assert b"203.0.113.1" in response.data
    assert b"1.1.1.1" in response.data
    assert b"8.8.8.8" in response.data


def test_allowed_hosts_blocks_dashboard_but_not_local_health_check(tmp_path: Path):
    """The direct-IP allow-list should protect status data without breaking health."""
    client = create_app(
        _settings(tmp_path, allowed_hosts=("127.0.0.1",))
    ).test_client()

    blocked = client.get("/", environ_base={"REMOTE_ADDR": "10.0.0.2"})
    health = client.get("/health", environ_base={"REMOTE_ADDR": "10.0.0.2"})
    favicon = client.get("/favicon.ico", environ_base={"REMOTE_ADDR": "10.0.0.2"})
    api = client.get("/api/status", environ_base={"REMOTE_ADDR": "10.0.0.2"})

    assert blocked.status_code == 403
    assert health.status_code == 200
    assert favicon.status_code == 204
    assert api.status_code == 403
