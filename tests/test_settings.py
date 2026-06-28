"""Tests for environment-backed application settings."""

import pytest

from internet_monitor.settings import ConfigurationError, load_settings


def test_default_settings_match_docker_defaults():
    """Defaults should match the values documented in .env.example."""
    settings = load_settings({})

    assert settings.monitor.ping_host == "1.1.1.1"
    assert settings.monitor.backup_ping_host == "8.8.8.8"
    assert settings.monitor.ping_period_ms == 1000
    assert settings.monitor.ping_timeout_ms == 1000
    assert settings.monitor.interval == 10
    assert settings.monitor.max_alerts_per_hour == 5
    assert settings.monitor.log_path == "/data/connection.log"
    assert settings.web.port == 5005
    assert settings.web.log_lines == 200
    assert settings.web.status_path == "/data/connection_status.json"


def test_environment_overrides_and_pushover_aliases():
    """Docker environment values should override defaults and parse safely."""
    settings = load_settings(
        {
            "INTERNET_MONITOR_DEBUG": "true",
            "INTERNET_MONITOR_BACKUP_PING_HOST": "9.9.9.9",
            "INTERNET_MONITOR_PING_PERIOD_MS": "500",
            "INTERNET_MONITOR_PING_TIMEOUT_MS": "1500",
            "INTERNET_MONITOR_INTERVAL": "30",
            "INTERNET_MONITOR_WEB_ALLOWED_HOSTS": "127.0.0.1, 10.0.0.5",
            "INTERNET_MONITOR_WEB_LOG_LINES": "25",
            "PUSHOVER_TOKEN": "token-from-alias",
            "PUSHOVER_USER": "user-from-alias",
        }
    )

    assert settings.monitor.debug is True
    assert settings.monitor.backup_ping_host == "9.9.9.9"
    assert settings.monitor.ping_period_ms == 500
    assert settings.monitor.ping_timeout_ms == 1500
    assert settings.monitor.interval == 30
    assert settings.web.refresh_interval == 30
    assert settings.web.allowed_hosts == ("127.0.0.1", "10.0.0.5")
    assert settings.web.log_lines == 25
    assert settings.pushover.token == "token-from-alias"
    assert settings.pushover.user == "user-from-alias"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("INTERNET_MONITOR_WEB_PORT", "70000"),
        ("INTERNET_MONITOR_INTERVAL", "0"),
        ("INTERNET_MONITOR_PING_HOST", ""),
        ("INTERNET_MONITOR_PING_PERIOD_MS", "1"),
        ("INTERNET_MONITOR_PING_TIMEOUT_MS", "10"),
        ("INTERNET_MONITOR_LOG_PATH", ""),
        ("INTERNET_MONITOR_STATUS_PATH", ""),
        ("INTERNET_MONITOR_WEB_LOG_PATH", ""),
        ("INTERNET_MONITOR_WEB_STATUS_PATH", ""),
        ("INTERNET_MONITOR_DEBUG", "maybe"),
        ("INTERNET_MONITOR_TIMEZONE", "Not/AZone"),
    ],
)
def test_invalid_environment_values_raise_configuration_error(name, value):
    """Invalid settings should fail fast before starting long-running services."""
    with pytest.raises(ConfigurationError):
        load_settings({name: value})
