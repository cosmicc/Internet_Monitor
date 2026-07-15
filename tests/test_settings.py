"""Tests for validated Docker environment configuration."""

from pathlib import Path

import pytest

from internet_monitor.settings import ConfigurationError, load_settings


def test_default_settings_match_docker_defaults():
    """Code defaults should match the documented container contract."""
    settings = load_settings({})

    assert settings.monitor.log_level == "INFO"
    assert settings.monitor.ping_host == "1.1.1.1"
    assert settings.monitor.backup_ping_host == "8.8.8.8"
    assert settings.monitor.gateway_1_ip == ""
    assert settings.monitor.gateway_2_ip == ""
    assert settings.monitor.important_hosts == ()
    assert settings.monitor.dns_servers == ("1.1.1.1", "8.8.8.8")
    assert settings.monitor.dns_slow_threshold_ms == 500
    assert settings.monitor.ping_period_ms == 1000
    assert settings.monitor.status_path == "/tmp/internet-monitor/status.json"
    assert settings.monitor.history_path == "/tmp/internet-monitor/history.json"
    assert settings.web.title == "Internet Monitor"
    assert settings.web.port == 5005
    assert settings.web.status_path == settings.monitor.status_path
    assert settings.web.history_path == settings.monitor.history_path
    assert settings.web.history_max_points == 720
    assert settings.pushover.retry_initial_seconds == 30
    assert settings.pushover.retry_max_seconds == 900


def test_environment_overrides_are_parsed_and_dns_servers_are_deduplicated():
    """Operator values should override defaults with normalized DNS addresses."""
    settings = load_settings(
        {
            "LOG_LEVEL": "debug",
            "BACKUP_PING_HOST": "9.9.9.9",
            "GATEWAY_1_IP": "10.0.0.1",
            "GATEWAY_2_IP": "2001:0db8::1",
            "IMPORTANT_HOST_1": "status.example.com",
            "IMPORTANT_HOST_2": "api.example.com",
            "IMPORTANT_HOST_3": "status.example.com",
            "DNS_SERVERS": "1.1.1.1, 2606:4700:4700::1111 1.1.1.1",
            "DNS_RECORD_TYPE": "aaaa",
            "DNS_SLOW_THRESHOLD_MS": "250.5",
            "INTERVAL": "30",
            "HISTORY_PATH": "/tmp/custom-history.json",
            "HISTORY_MAX_POINTS": "600",
            "WEB_PORT": "6000",
            "WEB_ALLOWED_HOSTS": "127.0.0.1, 10.0.0.5",
            "PUSHOVER_TOKEN": "token-from-alias",
            "PUSHOVER_USER": "user-from-alias",
            "PUSHOVER_RETRY_INITIAL_SECONDS": "15",
            "PUSHOVER_RETRY_MAX_SECONDS": "120",
        }
    )

    assert settings.monitor.log_level == "DEBUG"
    assert settings.monitor.backup_ping_host == "9.9.9.9"
    assert settings.monitor.gateway_1_ip == "10.0.0.1"
    assert settings.monitor.gateway_2_ip == "2001:db8::1"
    assert settings.monitor.important_hosts == (
        "status.example.com",
        "api.example.com",
    )
    assert settings.monitor.dns_servers == ("1.1.1.1", "2606:4700:4700::1111")
    assert settings.monitor.dns_record_type == "AAAA"
    assert settings.monitor.dns_slow_threshold_ms == 250.5
    assert settings.monitor.interval == 30
    assert settings.monitor.history_path == "/tmp/custom-history.json"
    assert settings.web.refresh_interval == 30
    assert settings.web.history_path == "/tmp/custom-history.json"
    assert settings.web.history_max_points == 600
    assert settings.web.port == 5005
    assert settings.web.allowed_hosts == ("127.0.0.1", "10.0.0.5")
    assert settings.pushover.token == "token-from-alias"
    assert settings.pushover.user == "user-from-alias"
    assert settings.pushover.retry_initial_seconds == 15
    assert settings.pushover.retry_max_seconds == 120


def test_docker_secret_files_take_precedence(tmp_path: Path):
    """Swarm secret files should override directly supplied credentials."""
    token_file = tmp_path / "token"
    user_file = tmp_path / "user"
    token_file.write_text("secret-token\n", encoding="utf-8")
    user_file.write_text("secret-user\n", encoding="utf-8")

    settings = load_settings(
        {
            "PUSHOVER_TOKEN": "direct-token",
            "PUSHOVER_TOKEN_FILE": str(token_file),
            "PUSHOVER_USER": "direct-user",
            "PUSHOVER_USER_FILE": str(user_file),
        }
    )

    assert settings.pushover.token == "secret-token"
    assert settings.pushover.user == "secret-user"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("INTERVAL", "0"),
        ("INTERVAL", "4"),
        ("PING_HOST", ""),
        ("PING_HOST", "-c"),
        ("PINGS", "11"),
        ("PING_PERIOD_MS", "1"),
        ("PING_TIMEOUT_MS", "10"),
        ("STATUS_PATH", ""),
        ("HISTORY_PATH", ""),
        ("HISTORY_MAX_POINTS", "119"),
        ("HISTORY_MAX_POINTS", "721"),
        ("WEB_WORKERS", "5"),
        ("WEB_THREADS", "9"),
        ("LOG_LEVEL", "verbose"),
        ("DNS_SERVERS", "resolver.example.com"),
        (
            "DNS_SERVERS",
            "1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 "
            "149.112.112.112 208.67.222.222 208.67.220.220 76.76.2.0",
        ),
        ("DNS_RECORD_TYPE", "TXT"),
        ("DNS_TIMEOUT_SECONDS", "0"),
        ("DNS_SLOW_THRESHOLD_MS", "0"),
        ("GATEWAY_1_IP", "gateway.example.com"),
        ("GATEWAY_2_IP", "999.1.1.1"),
        ("PUSHOVER_RETRY_INITIAL_SECONDS", "0"),
        ("TIMEZONE", "Not/AZone"),
    ],
)
def test_invalid_environment_values_raise_configuration_error(name, value):
    """Invalid settings should fail before either long-running process starts."""
    with pytest.raises(ConfigurationError):
        load_settings({name: value})


def test_missing_secret_file_raises_without_exposing_a_secret():
    """A bad secret mount should fail closed."""
    with pytest.raises(ConfigurationError, match="Unable to read the secret"):
        load_settings(
            {"PUSHOVER_TOKEN_FILE": "/does/not/exist"}
        )


def test_pushover_retry_maximum_cannot_be_shorter_than_initial_delay():
    """Retry backoff bounds should fail closed when their order is invalid."""
    with pytest.raises(ConfigurationError, match="RETRY_MAX_SECONDS"):
        load_settings(
            {
                "PUSHOVER_RETRY_INITIAL_SECONDS": "120",
                "PUSHOVER_RETRY_MAX_SECONDS": "60",
            }
        )


def test_monitor_interval_must_cover_the_configured_probe_window():
    """Probe settings should not create a permanently busy monitoring loop."""
    with pytest.raises(ConfigurationError, match="longest configured probe window"):
        load_settings(
            {
                "INTERVAL": "10",
                "PINGS": "10",
                "PING_PERIOD_MS": "5000",
                "PING_TIMEOUT_MS": "5000",
            }
        )


def test_history_and_status_paths_must_be_distinct():
    """Independent atomic snapshots must never overwrite one another."""
    with pytest.raises(ConfigurationError, match="must differ"):
        load_settings(
            {
                "STATUS_PATH": "/tmp/shared.json",
                "HISTORY_PATH": "/tmp/shared.json",
            }
        )


def test_legacy_prefixed_variables_are_ignored_after_clean_break():
    """Version 0.2.0 must not silently accept the removed variable names."""
    settings = load_settings(
        {
            "INTERNET_MONITOR_PING_HOST": "9.9.9.9",
            "INTERNET_MONITOR_IMPORTANT_HOST_1": "legacy.example.com",
            "INTERNET_MONITOR_WEB_PORT": "6000",
        }
    )

    assert settings.monitor.ping_host == "1.1.1.1"
    assert settings.monitor.important_hosts == ()
    assert settings.web.port == 5005
