"""Tests for monitor helpers that do not require live network access."""

import json
from types import SimpleNamespace

from internet_monitor import monitor
from internet_monitor.settings import load_settings


def test_parse_fping_output_extracts_latency_and_loss():
    """The fping summary parser should extract packet loss and average latency."""
    raw = "1.1.1.1 : xmt/rcv/%loss = 5/4/20%, min/avg/max = 8.1/9.4/11.2"

    avg_latency, loss = monitor.parse_fping_output(raw)

    assert avg_latency == 9.4
    assert loss == 20


def test_write_status_uses_configured_status_path(tmp_path):
    """Status JSON should be written to the path supplied by environment settings."""
    status_path = tmp_path / "connection_status.json"
    settings = load_settings(
        {
            "INTERNET_MONITOR_LOG_PATH": str(tmp_path / "connection.log"),
            "INTERNET_MONITOR_STATUS_PATH": str(status_path),
        }
    )
    monitor.apply_settings(settings)

    monitor.write_status("warning", "up")

    data = json.loads(status_path.read_text(encoding="utf-8"))
    assert data["internet"]["state"] == "warning"
    assert data["dns"]["state"] == "up"
    assert data["timestamp"].endswith("Z")


def test_run_ping_uses_backup_when_primary_reports_loss(monkeypatch, tmp_path):
    """A clean backup host should suppress primary-host packet-loss false positives."""
    calls = []

    def fake_run(cmd, capture_output, text, check):
        calls.append(cmd)
        host = cmd[-1]
        if host == "1.1.1.1":
            return SimpleNamespace(
                returncode=0,
                stdout="",
                stderr=(
                    "1.1.1.1 : xmt/rcv/%loss = 5/4/20%, "
                    "min/avg/max = 8.1/9.4/11.2"
                ),
            )
        return SimpleNamespace(
            returncode=0,
            stdout="",
            stderr=(
                "8.8.8.8 : xmt/rcv/%loss = 5/5/0%, "
                "min/avg/max = 9.1/10.4/12.2"
            ),
        )

    settings = load_settings(
        {
            "INTERNET_MONITOR_LOG_PATH": str(tmp_path / "connection.log"),
            "INTERNET_MONITOR_STATUS_PATH": str(tmp_path / "status.json"),
            "INTERNET_MONITOR_PING_HOST": "1.1.1.1",
            "INTERNET_MONITOR_BACKUP_PING_HOST": "8.8.8.8",
            "INTERNET_MONITOR_PING_PERIOD_MS": "1000",
            "INTERNET_MONITOR_PING_TIMEOUT_MS": "1000",
        }
    )
    monitor.apply_settings(settings)
    monkeypatch.setattr(monitor.subprocess, "run", fake_run)

    result = monitor.run_ping()

    assert result.success is True
    assert result.host == "8.8.8.8"
    assert result.loss_percent == 0
    assert result.used_backup is True
    assert calls[0] == [
        "fping",
        "-c",
        "5",
        "-p",
        "1000",
        "-t",
        "1000",
        "1.1.1.1",
    ]
    assert calls[1][-1] == "8.8.8.8"


def test_flush_queue_keeps_failed_and_later_notifications(tmp_path):
    """Queue retry should not drop notifications after the first retry failure."""
    settings = load_settings(
        {
            "INTERNET_MONITOR_LOG_PATH": str(tmp_path / "connection.log"),
            "INTERNET_MONITOR_STATUS_PATH": str(tmp_path / "status.json"),
        }
    )
    monitor.apply_settings(settings)
    notifier = monitor.PushoverNotifier(token="token", user="user")
    notifier.queue = [
        monitor.QueuedNotification("sent", "message", monitor.utcnow()),
        monitor.QueuedNotification("failed", "message", monitor.utcnow()),
        monitor.QueuedNotification("later", "message", monitor.utcnow()),
    ]

    def fake_send(title, message):
        return title == "sent"

    notifier._send_http = fake_send

    notifier.flush_queue()

    assert [item.title for item in notifier.queue] == ["failed", "later"]
