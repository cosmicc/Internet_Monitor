"""Tests for the Flask web dashboard."""

import json
from datetime import datetime, timezone

from internet_monitor.settings import MonitorSettings, PushoverSettings, Settings, WebSettings
from internet_monitor.web import create_app


def _settings(tmp_path, *, allowed_hosts=()):
    """Build isolated app settings backed by a temporary data directory."""
    log_path = tmp_path / "connection.log"
    status_path = tmp_path / "connection_status.json"
    return Settings(
        monitor=MonitorSettings(
            log_path=str(log_path),
            status_path=str(status_path),
            interval=15,
        ),
        web=WebSettings(
            title="Test Monitor",
            log_path=str(log_path),
            status_path=str(status_path),
            log_lines=1,
            allowed_hosts=allowed_hosts,
            refresh_interval=15,
        ),
        pushover=PushoverSettings(),
    )


def test_index_renders_latest_log_line_and_status(tmp_path):
    """The dashboard should render the newest log line and status state."""
    settings = _settings(tmp_path)
    log_path = tmp_path / "connection.log"
    status_path = tmp_path / "connection_status.json"
    log_path.write_text("old line\nnew line\n", encoding="utf-8")
    status_path.write_text(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "internet": {"state": "warning"},
                "dns": {"state": "up"},
            }
        ),
        encoding="utf-8",
    )

    client = create_app(settings).test_client()
    response = client.get("/")

    assert response.status_code == 200
    assert b"Test Monitor" in response.data
    assert b"new line" in response.data
    assert b"old line" not in response.data
    assert b"Degraded" in response.data
    assert b"Up" in response.data


def test_allowed_hosts_blocks_unlisted_remote_addr(tmp_path):
    """Configured allow-lists should reject direct clients outside the list."""
    settings = _settings(tmp_path, allowed_hosts=("127.0.0.1",))
    client = create_app(settings).test_client()

    response = client.get("/", environ_base={"REMOTE_ADDR": "10.0.0.2"})

    assert response.status_code == 403
