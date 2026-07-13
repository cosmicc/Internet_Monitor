"""Tests for connectivity, dig, status, and notification helpers."""

import json
from pathlib import Path
from types import SimpleNamespace

from internet_monitor import monitor
from internet_monitor.settings import MonitorSettings, PushoverSettings


def test_parse_fping_output_extracts_latency_and_loss():
    """The fping parser should extract packet counts, loss, and latency statistics."""
    raw = "1.1.1.1 : xmt/rcv/%loss = 5/4/20%, min/avg/max = 8.1/9.4/11.2"

    metrics = monitor.parse_fping_output(raw)

    assert metrics.transmitted == 5
    assert metrics.received == 4
    assert metrics.loss_percent == 20
    assert metrics.min_latency_ms == 8.1
    assert metrics.avg_latency_ms == 9.4
    assert metrics.max_latency_ms == 11.2


def test_write_status_uses_ephemeral_path_and_includes_dns_timings(tmp_path: Path):
    """The current snapshot should contain Internet and per-server DNS results."""
    status_path = tmp_path / "status.json"
    settings = MonitorSettings(status_path=str(status_path))
    ping_result = monitor.PingResult(
        True,
        12.5,
        0,
        "",
        host="1.1.1.1",
        min_latency_ms=10.0,
        max_latency_ms=14.0,
        transmitted=5,
        received=5,
    )
    resolver_result = monitor.ResolverResult("up", 8.2)
    dns_results = [monitor.DnsQueryResult("1.1.1.1", "up", 10.0, "NOERROR", 1)]

    monitor.write_status(
        settings,
        "up",
        ping_result,
        {"1.1.1.1": ping_result, "8.8.8.8": ping_result},
        "up",
        resolver_result,
        dns_results,
        monitor.Diagnosis("up", "Connection healthy", "Everything responds."),
        123.45,
    )

    data = json.loads(status_path.read_text(encoding="utf-8"))
    assert data["internet"]["state"] == "up"
    assert data["internet"]["average_latency_ms"] == 12.5
    assert data["internet"]["minimum_latency_ms"] == 10.0
    assert data["internet"]["maximum_latency_ms"] == 14.0
    assert data["internet"]["transmitted"] == 5
    assert data["diagnosis"]["title"] == "Connection healthy"
    assert data["loop_duration_ms"] == 123.45
    assert data["dns"]["resolver"]["response_time_ms"] == 8.2
    assert data["dns"]["servers"][0]["server"] == "1.1.1.1"
    assert data["dns"]["servers"][0]["response_time_ms"] == 10.0
    assert status_path.stat().st_mode & 0o777 == 0o600


def test_run_ping_uses_backup_when_primary_reports_loss(monkeypatch):
    """A clean backup host should suppress a primary-host false positive."""
    calls = []

    def fake_run(command, capture_output, text, check, timeout):
        calls.append(command)
        if command[-1] == "1.1.1.1":
            return SimpleNamespace(
                returncode=1,
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

    settings = MonitorSettings(
        ping_host="1.1.1.1",
        backup_ping_host="8.8.8.8",
        ping_period_ms=1000,
        ping_timeout_ms=1000,
    )
    monkeypatch.setattr(monitor.subprocess, "run", fake_run)

    result = monitor.run_ping(settings)

    assert result.success is True
    assert result.host == "8.8.8.8"
    assert result.loss_percent == 0
    assert result.used_backup is True
    assert {command[-1] for command in calls} == {"1.1.1.1", "8.8.8.8"}
    assert all(command[1:7] == ["-c", "5", "-p", "1000", "-t", "1000"] for command in calls)


def test_probe_cycle_collects_both_internet_targets_gateways_and_dns(monkeypatch):
    """One probe cycle should return every configured check in stable order."""
    settings = MonitorSettings(
        gateway_1_ip="10.0.0.1",
        gateway_2_ip="203.0.113.1",
        dns_servers=("1.1.1.1", "8.8.8.8"),
    )
    ping_calls = []
    dig_calls = []

    def fake_ping(host, _settings):
        ping_calls.append(host)
        return monitor.PingResult(True, 1.0, 0, "", host=host)

    def fake_dig(server, _settings):
        dig_calls.append(server)
        return monitor.DnsQueryResult(server, "up", 2.0, "NOERROR", 1)

    monkeypatch.setattr(monitor, "_run_single_ping", fake_ping)
    monkeypatch.setattr(
        monitor,
        "check_system_resolver",
        lambda hostname: monitor.ResolverResult("up", 3.0),
    )
    monkeypatch.setattr(monitor, "run_dig", fake_dig)

    result = monitor.run_probe_cycle(settings)

    assert set(ping_calls) == {
        "1.1.1.1",
        "8.8.8.8",
        "10.0.0.1",
        "203.0.113.1",
    }
    assert set(result.ping_results) == set(ping_calls)
    assert set(dig_calls) == {"1.1.1.1", "8.8.8.8"}
    assert [item.server for item in result.dns_results] == ["1.1.1.1", "8.8.8.8"]
    assert result.resolver_result.state == "up"


def test_history_series_and_values_cover_every_dashboard_check():
    """Retained history should align gateways, targets, resolver, and DNS servers."""
    settings = MonitorSettings(
        gateway_1_ip="10.0.0.1",
        gateway_2_ip="203.0.113.1",
        dns_servers=("1.1.1.1", "8.8.8.8"),
    )
    successful = lambda host, latency: monitor.PingResult(
        True,
        latency,
        0,
        "",
        host=host,
        min_latency_ms=latency - 1,
        max_latency_ms=latency + 1,
    )
    failed = monitor.PingResult(
        False,
        None,
        100,
        "",
        host="8.8.8.8",
        transmitted=5,
        received=0,
    )
    ping_results = {
        "1.1.1.1": successful("1.1.1.1", 12.0),
        "8.8.8.8": failed,
        "10.0.0.1": successful("10.0.0.1", 1.0),
        "203.0.113.1": successful("203.0.113.1", 5.0),
    }
    series = monitor.build_history_series(settings)
    values = monitor.build_history_values(
        settings,
        ping_results["1.1.1.1"],
        ping_results,
        monitor.ResolverResult("up", 4.0),
        [
            monitor.DnsQueryResult("1.1.1.1", "up", 8.0, "NOERROR", 1),
            monitor.DnsQueryResult("8.8.8.8", "down", None, error="timeout"),
        ],
    )

    assert [item.id for item in series] == [
        "gateway-1",
        "gateway-2",
        "internet",
        "internet-target-0",
        "internet-target-1",
        "dns-resolver",
        "dns-server-0",
        "dns-server-1",
    ]
    assert set(values) == {item.id for item in series}
    assert values["gateway-1"].average == 1.0
    assert values["internet-target-1"].loss == 100
    assert values["dns-server-1"].average is None
    assert values["dns-server-1"].loss == 100


def test_run_dig_extracts_query_time_and_marks_slow_response(monkeypatch):
    """dig output should produce a server-specific slow result."""
    calls = []

    def fake_run(command, capture_output, text, check, timeout):
        calls.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout=(
                ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 123\n"
                ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
                "www.google.com. 60 IN A 142.250.190.4\n"
                ";; Query time: 750 msec\n"
            ),
            stderr="",
        )

    settings = MonitorSettings(dns_slow_threshold_ms=500)
    monkeypatch.setattr(monitor.subprocess, "run", fake_run)

    result = monitor.run_dig("1.1.1.1", settings)

    assert result.state == "warning"
    assert result.response_time_ms == 750
    assert result.response_status == "NOERROR"
    assert result.answer_count == 1
    assert calls[0][:4] == ["dig", "@1.1.1.1", "www.google.com", "A"]
    assert "+tries=1" in calls[0]


def test_run_dig_treats_servfail_as_down(monkeypatch):
    """A responding server with SERVFAIL should fail the resolution check."""

    def fake_run(command, capture_output, text, check, timeout):
        return SimpleNamespace(
            returncode=0,
            stdout=(
                ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 123\n"
                ";; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
                ";; Query time: 12 msec\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(monitor.subprocess, "run", fake_run)

    result = monitor.run_dig("8.8.8.8", MonitorSettings())

    assert result.state == "down"
    assert result.response_time_ms == 12
    assert result.error == "DNS response status was SERVFAIL"


class RecordingNotifier:
    """Minimal notifier test double that records alert titles and messages."""

    def __init__(self):
        self.notifications = []

    def notify(self, title, message):
        self.notifications.append((title, message))


def test_each_dns_server_tracker_sends_its_own_alert_and_recovery():
    """Each configured resolver should have an independent alert lifecycle."""
    settings = MonitorSettings(dns_failure_trigger=2)
    notifier = RecordingNotifier()
    cloudflare_tracker = monitor.IssueTracker()
    google_tracker = monitor.IssueTracker()

    failed_cloudflare = monitor.DnsQueryResult(
        "1.1.1.1", "down", None, error="timed out"
    )
    slow_google = monitor.DnsQueryResult("8.8.8.8", "warning", 650.0)
    for _ in range(2):
        monitor.update_dns_server_tracker(
            cloudflare_tracker, failed_cloudflare, settings, notifier
        )
        monitor.update_dns_server_tracker(
            google_tracker, slow_google, settings, notifier
        )

    monitor.update_dns_server_tracker(
        cloudflare_tracker,
        monitor.DnsQueryResult("1.1.1.1", "up", 11.0, "NOERROR", 1),
        settings,
        notifier,
    )

    titles = [title for title, _message in notifier.notifications]
    assert titles == [
        "DNS Server Failure: 1.1.1.1",
        "Slow DNS Server: 8.8.8.8",
        "DNS Server Recovered: 1.1.1.1",
    ]


def test_flush_queue_keeps_failed_and_later_notifications():
    """Queue retry should not drop notifications after the first retry failure."""
    notifier = monitor.PushoverNotifier(
        PushoverSettings(token="token", user="user"),
        max_alerts_per_hour=0,
    )
    notifier.queue = [
        monitor.QueuedNotification("sent", "message", monitor.utcnow()),
        monitor.QueuedNotification("failed", "message", monitor.utcnow()),
        monitor.QueuedNotification("later", "message", monitor.utcnow()),
    ]
    notifier._send_http = lambda title, message: title == "sent"

    notifier.flush_queue()

    assert [item.title for item in notifier.queue] == ["failed", "later"]


def test_gateway_tracker_sends_independent_alert_and_recovery():
    """A gateway should alert after its trigger and recover independently."""
    settings = MonitorSettings(trigger=2, outage_alert_delay_seconds=0)
    notifier = RecordingNotifier()
    tracker = monitor.IssueTracker()
    failed = monitor.PingResult(
        False,
        None,
        100,
        "",
        host="10.0.0.1",
        transmitted=5,
        received=0,
    )

    monitor.update_gateway_tracker(tracker, "Gateway 1", failed, settings, notifier)
    monitor.update_gateway_tracker(tracker, "Gateway 1", failed, settings, notifier)
    monitor.update_gateway_tracker(
        tracker,
        "Gateway 1",
        monitor.PingResult(True, 1.2, 0, "", host="10.0.0.1"),
        settings,
        notifier,
    )

    assert [title for title, _message in notifier.notifications] == [
        "Gateway 1 Unreachable",
        "Gateway 1 Recovered",
    ]


def test_connection_diagnosis_prioritizes_closest_failed_segment():
    """Diagnosis should distinguish local, upstream, Internet, and DNS failures."""
    settings = MonitorSettings(
        gateway_1_ip="10.0.0.1",
        gateway_2_ip="203.0.113.1",
    )
    healthy = lambda host: monitor.PingResult(True, 5.0, 0, "", host=host)
    failed = lambda host: monitor.PingResult(False, None, 100, "", host=host)

    local_results = {
        "10.0.0.1": failed("10.0.0.1"),
        "203.0.113.1": failed("203.0.113.1"),
    }
    upstream_results = {
        "10.0.0.1": healthy("10.0.0.1"),
        "203.0.113.1": failed("203.0.113.1"),
    }
    healthy_results = {
        "10.0.0.1": healthy("10.0.0.1"),
        "203.0.113.1": healthy("203.0.113.1"),
    }

    assert monitor.determine_connection_diagnosis(
        settings, local_results, "down", "unknown"
    ).title == "Local network issue"
    assert monitor.determine_connection_diagnosis(
        settings, upstream_results, "down", "unknown"
    ).title == "Upstream gateway issue"
    assert monitor.determine_connection_diagnosis(
        settings, healthy_results, "down", "unknown"
    ).title == "ISP or Internet issue"
    assert monitor.determine_connection_diagnosis(
        settings, healthy_results, "up", "warning"
    ).title == "DNS issue"
    assert monitor.determine_connection_diagnosis(
        MonitorSettings(), {}, "down", "unknown"
    ).title == "Internet connection issue"


def test_pushover_retry_uses_backoff_until_delivery(monkeypatch):
    """Failed messages should remain queued and retry with capped backoff."""
    current_time = [monitor.utcnow()]
    monkeypatch.setattr(monitor, "utcnow", lambda: current_time[0])
    notifier = monitor.PushoverNotifier(
        PushoverSettings(
            token="token",
            user="user",
            retry_initial_seconds=30,
            retry_max_seconds=60,
        ),
        max_alerts_per_hour=0,
    )
    attempts = []

    def send(title, message):
        attempts.append((title, message))
        return len(attempts) >= 3

    notifier._send_http = send
    notifier.notify("Outage", "message")
    assert len(notifier.queue) == 1
    assert notifier.queue[0].attempt_count == 1

    notifier.flush_queue()
    assert len(attempts) == 1
    current_time[0] += monitor.timedelta(seconds=30)
    notifier.flush_queue()
    assert notifier.queue[0].attempt_count == 2
    current_time[0] += monitor.timedelta(seconds=60)
    notifier.flush_queue()

    assert len(attempts) == 3
    assert notifier.queue == []


def test_rate_limited_pushover_notification_is_queued(monkeypatch):
    """The hourly application limit should defer notifications instead of dropping them."""
    notifier = monitor.PushoverNotifier(
        PushoverSettings(token="token", user="user"),
        max_alerts_per_hour=1,
    )
    monkeypatch.setattr(notifier, "_send_http", lambda title, message: True)

    notifier.notify("First", "message")
    notifier.notify("Second", "message")

    assert [item.title for item in notifier.queue] == ["Second"]
    assert notifier.queue[0].next_attempt_at is not None
