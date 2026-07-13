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
    assert settings.monitor.dns_servers == ("1.1.1.1", "8.8.8.8")
    assert settings.monitor.dns_slow_threshold_ms == 500
    assert settings.monitor.ping_period_ms == 1000
    assert settings.monitor.status_path == "/tmp/internet-monitor/status.json"
    assert settings.web.title == "Internet Monitor"
    assert settings.web.port == 5005
    assert settings.web.status_path == settings.monitor.status_path
    assert settings.pushover.retry_initial_seconds == 30
    assert settings.pushover.retry_max_seconds == 900


def test_environment_overrides_are_parsed_and_dns_servers_are_deduplicated():
    """Operator values should override defaults with normalized DNS addresses."""
    settings = load_settings(
        {
            "INTERNET_MONITOR_LOG_LEVEL": "debug",
            "INTERNET_MONITOR_BACKUP_PING_HOST": "9.9.9.9",
            "INTERNET_MONITOR_GATEWAY_1_IP": "10.0.0.1",
            "INTERNET_MONITOR_GATEWAY_2_IP": "2001:0db8::1",
            "INTERNET_MONITOR_DNS_SERVERS": "1.1.1.1, 2606:4700:4700::1111 1.1.1.1",
            "INTERNET_MONITOR_DNS_RECORD_TYPE": "aaaa",
            "INTERNET_MONITOR_DNS_SLOW_THRESHOLD_MS": "250.5",
            "INTERNET_MONITOR_INTERVAL": "30",
            "INTERNET_MONITOR_WEB_ALLOWED_HOSTS": "127.0.0.1, 10.0.0.5",
            "PUSHOVER_TOKEN": "token-from-alias",
            "PUSHOVER_USER": "user-from-alias",
            "INTERNET_MONITOR_PUSHOVER_RETRY_INITIAL_SECONDS": "15",
            "INTERNET_MONITOR_PUSHOVER_RETRY_MAX_SECONDS": "120",
        }
    )

    assert settings.monitor.log_level == "DEBUG"
    assert settings.monitor.backup_ping_host == "9.9.9.9"
    assert settings.monitor.gateway_1_ip == "10.0.0.1"
    assert settings.monitor.gateway_2_ip == "2001:db8::1"
    assert settings.monitor.dns_servers == ("1.1.1.1", "2606:4700:4700::1111")
    assert settings.monitor.dns_record_type == "AAAA"
    assert settings.monitor.dns_slow_threshold_ms == 250.5
    assert settings.monitor.interval == 30
    assert settings.web.refresh_interval == 30
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
            "INTERNET_MONITOR_PUSHOVER_TOKEN": "direct-token",
            "INTERNET_MONITOR_PUSHOVER_TOKEN_FILE": str(token_file),
            "INTERNET_MONITOR_PUSHOVER_USER": "direct-user",
            "INTERNET_MONITOR_PUSHOVER_USER_FILE": str(user_file),
        }
    )

    assert settings.pushover.token == "secret-token"
    assert settings.pushover.user == "secret-user"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("INTERNET_MONITOR_WEB_PORT", "70000"),
        ("INTERNET_MONITOR_INTERVAL", "0"),
        ("INTERNET_MONITOR_PING_HOST", ""),
        ("INTERNET_MONITOR_PING_PERIOD_MS", "1"),
        ("INTERNET_MONITOR_PING_TIMEOUT_MS", "10"),
        ("INTERNET_MONITOR_STATUS_PATH", ""),
        ("INTERNET_MONITOR_LOG_LEVEL", "verbose"),
        ("INTERNET_MONITOR_DNS_SERVERS", "resolver.example.com"),
        ("INTERNET_MONITOR_DNS_RECORD_TYPE", "TXT"),
        ("INTERNET_MONITOR_DNS_TIMEOUT_SECONDS", "0"),
        ("INTERNET_MONITOR_DNS_SLOW_THRESHOLD_MS", "0"),
        ("INTERNET_MONITOR_GATEWAY_1_IP", "gateway.example.com"),
        ("INTERNET_MONITOR_GATEWAY_2_IP", "999.1.1.1"),
        ("INTERNET_MONITOR_PUSHOVER_RETRY_INITIAL_SECONDS", "0"),
        ("INTERNET_MONITOR_TIMEZONE", "Not/AZone"),
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
            {"INTERNET_MONITOR_PUSHOVER_TOKEN_FILE": "/does/not/exist"}
        )


def test_pushover_retry_maximum_cannot_be_shorter_than_initial_delay():
    """Retry backoff bounds should fail closed when their order is invalid."""
    with pytest.raises(ConfigurationError, match="RETRY_MAX_SECONDS"):
        load_settings(
            {
                "INTERNET_MONITOR_PUSHOVER_RETRY_INITIAL_SECONDS": "120",
                "INTERNET_MONITOR_PUSHOVER_RETRY_MAX_SECONDS": "60",
            }
        )
