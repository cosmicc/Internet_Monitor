"""Tests for the log-free Flask status dashboard."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from internet_monitor.history import HistorySeries, HistoryStore, HistoryValue
from internet_monitor.settings import (
    MonitorSettings,
    PushoverSettings,
    Settings,
    WebSettings,
)
from internet_monitor.storage import StorageStatus
from internet_monitor.web import create_app


def _settings(tmp_path: Path, *, allowed_hosts=(), important_hosts=()):
    """Build isolated app settings backed by an ephemeral snapshot path."""
    status_path = tmp_path / "status.json"
    history_path = tmp_path / "history.json"
    return Settings(
        monitor=MonitorSettings(
            status_path=str(status_path),
            history_path=str(history_path),
            interval=15,
            gateway_1_ip="10.0.0.1",
            gateway_2_ip="203.0.113.1",
            dns_servers=("1.1.1.1", "8.8.8.8"),
            important_hosts=important_hosts,
        ),
        web=WebSettings(
            title="Test Monitor",
            status_path=str(status_path),
            history_path=str(history_path),
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
                    "container": {
                        "cpu_usage_percent": 3.25,
                        "memory_usage_bytes": 52_428_800,
                        "memory_limit_bytes": 209_715_200,
                        "memory_usage_percent": 25.0,
                        "memory_usage_mib": 50.0,
                        "memory_limit_mib": 200.0,
                    },
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
    assert response.data.count(b'class="details-column"') == 1
    internet_card = response.data.index(b'data-details-card="internet"')
    secondary_column = response.data.index(b'data-details-column="secondary"')
    important_card = response.data.index(b'data-details-card="important-hosts"')
    assert internet_card < response.data.index(b"Internet Performance")
    assert response.data.index(b"Internet Performance") < secondary_column
    assert secondary_column < response.data.index(b"Gateway Details")
    assert response.data.index(b"Gateway Details") < response.data.index(
        b"DNS Health"
    )
    assert response.data.index(b"DNS Health") < important_card
    assert important_card < response.data.index(b"Important Hosts")
    assert b"Connection degraded" in response.data
    assert b"10.0.0.1" in response.data
    assert b"203.0.113.1" in response.data
    assert b"1.1.1.1" in response.data
    assert b"11.00 ms" in response.data
    assert b"725.00 ms" in response.data
    assert b"3.25%" in response.data
    assert b"50.00 / 200.00 MiB (25.00%)" in response.data
    assert b'data-sparkline="container-cpu"' in response.data
    assert b'data-sparkline="container-memory"' in response.data
    assert b'data-y-axis-maximum' in response.data
    assert b'data-y-axis-two-thirds' in response.data
    assert b'data-y-axis-one-third' in response.data
    assert b'data-y-axis-high' in response.data
    assert b'data-y-axis-mid' in response.data
    assert b'data-y-axis-low' in response.data
    assert b'data-y-axis="compact"' in response.data
    assert b'x1="28" y1="14" x2="100" y2="14"' in response.data
    assert b"red marks loss" in response.data
    assert b"data-loss-series" in response.data
    assert b"Monitoring History" in response.data
    assert b'data-history-range="24h"' in response.data
    assert b'data-history-range="30d"' in response.data
    assert b'data-history-range="7d"' not in response.data
    assert b'data-history-range="all"' not in response.data
    assert b">All</button>" not in response.data
    assert b'aria-label="Color theme"' in response.data
    assert b'data-theme-option="light"' in response.data
    assert b'data-theme-option="dark"' in response.data
    assert b">Light</span>" in response.data
    assert b">Dark</span>" in response.data
    assert b'data-sparkline="internet-target-0"' in response.data
    assert b'data-sparkline="dns-server-0"' in response.data
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
    assert b"loadHistory" in script_response.data
    assert b"failed DNS check" in script_response.data
    assert b"prefers-color-scheme: dark" in script_response.data
    assert b"internet-monitor-theme" in script_response.data
    assert b"localStorage.setItem" in script_response.data
    assert b"Latest usage is" in script_response.data
    assert b"data-y-axis-maximum" in script_response.data
    assert b"data-y-axis-two-thirds" in script_response.data
    assert b"data-y-axis-one-third" in script_response.data
    assert b"data-y-axis-high" in script_response.data
    assert b"data-y-axis-mid" in script_response.data
    assert b"data-y-axis-low" in script_response.data
    assert b"chartAxisUnit" in script_response.data
    assert b"updateChartAxis" in script_response.data

    api_response = create_app(settings).test_client().get("/api/status")
    assert api_response.status_code == 200
    api_data = api_response.get_json()
    assert api_data["diagnosis"]["title"] == "Connection degraded"
    assert api_data["path_nodes"][1]["label"] == "Gateway 1"
    assert api_data["path_nodes"][0]["resources"]["cpu_usage_percent"] == 3.25
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


def test_tmpfs_alert_and_dns_gated_important_hosts_render_on_web(
    tmp_path: Path,
    monkeypatch,
):
    """The live page and API should expose capacity pressure and skipped hosts."""
    settings = _settings(
        tmp_path,
        important_hosts=("status.example.com", "api.example.com"),
    )
    Path(settings.monitor.status_path).write_text(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "interval_seconds": 15,
                "loop_duration_ms": 100,
                "diagnosis": {
                    "state": "warning",
                    "title": "DNS issue",
                    "detail": "Configured DNS paths are unavailable.",
                },
                "internet": {
                    "state": "up",
                    "host": "1.1.1.1",
                    "average_latency_ms": 10,
                    "loss_percent": 0,
                    "targets": [],
                },
                "dns": {
                    "state": "down",
                    "hostname": "www.google.com",
                    "record_type": "A",
                    "slow_threshold_ms": 500,
                    "resolver": {"state": "down", "response_time_ms": 5},
                    "servers": [],
                },
                "important_hosts": {
                    "state": "warning",
                    "skipped": True,
                    "skip_reason": (
                        "System DNS and at least one configured DNS server "
                        "must be available."
                    ),
                    "hosts": [
                        {"host": "status.example.com", "state": "unknown"},
                        {"host": "api.example.com", "state": "unknown"},
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "internet_monitor.web.read_storage_status",
        lambda path: StorageStatus(
            "warning",
            85.0,
            16 * 1024 * 1024,
            2 * 1024 * 1024,
        ),
    )
    client = create_app(settings).test_client()

    response = client.get("/")
    api_data = client.get("/api/status").get_json()

    assert response.status_code == 200
    assert b"Important Hosts" in response.data
    assert b"status.example.com" in response.data
    assert b"api.example.com" in response.data
    assert b'class="important-sparkline"' in response.data
    assert b"DNS unavailable" in response.data
    assert b"Temporary storage is filling up" in response.data
    assert b"85.00% used" in response.data
    assert api_data["storage"]["state"] == "warning"
    assert api_data["important_hosts"]["skipped"] is True
    assert api_data["important_hosts"]["hosts"][0]["status"]["text"] == "Skipped"


def test_allowed_hosts_blocks_dashboard_but_not_local_health_check(tmp_path: Path):
    """The direct-IP allow-list should protect status data without breaking health."""
    client = create_app(
        _settings(tmp_path, allowed_hosts=("127.0.0.1",))
    ).test_client()

    blocked = client.get("/", environ_base={"REMOTE_ADDR": "10.0.0.2"})
    health = client.get("/health", environ_base={"REMOTE_ADDR": "10.0.0.2"})
    favicon = client.get("/favicon.ico", environ_base={"REMOTE_ADDR": "10.0.0.2"})
    api = client.get("/api/status", environ_base={"REMOTE_ADDR": "10.0.0.2"})
    history_api = client.get(
        "/api/history?range=24h",
        environ_base={"REMOTE_ADDR": "10.0.0.2"},
    )

    assert blocked.status_code == 403
    assert health.status_code == 200
    assert favicon.status_code == 204
    assert api.status_code == 403
    assert history_api.status_code == 403


def test_history_api_serves_sanitized_container_history(tmp_path: Path):
    """The dashboard API should expose bounded history for configured ranges."""
    settings = _settings(tmp_path)
    timestamp = datetime.now(timezone.utc)
    store = HistoryStore(
        settings.monitor.history_path,
        [HistorySeries("internet", "Active Internet", "ping", "1.1.1.1")],
        started_at=timestamp,
    )
    store.record(timestamp, {"internet": HistoryValue(18.25, 10)})
    client = create_app(settings).test_client()

    response = client.get("/api/history?range=24h")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["available"] is True
    assert payload["range"] == "24h"
    assert payload["point_count"] == 1
    assert payload["series"][0]["id"] == "internet"
    assert payload["points"][0][1][0] == [18.25, 10.0, 18.25, 18.25]
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("range_name", ["7d", "all", "forever"])
def test_history_api_rejects_unsupported_ranges(tmp_path: Path, range_name: str):
    """History range input should be constrained to the explicit allow-list."""
    response = create_app(_settings(tmp_path)).test_client().get(
        f"/api/history?range={range_name}"
    )

    assert response.status_code == 400
