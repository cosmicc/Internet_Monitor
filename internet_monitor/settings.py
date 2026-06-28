"""Environment-backed application settings for Internet Monitor."""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from typing import Mapping, Sequence

import pytz


DEFAULT_LOG_PATH = "/data/connection.log"
DEFAULT_STATUS_PATH = "/data/connection_status.json"


class ConfigurationError(ValueError):
    """Raised when an environment variable contains an invalid setting."""


@dataclass(frozen=True)
class MonitorSettings:
    """Settings used by the long-running connectivity monitor."""

    debug: bool = False
    ping_host: str = "1.1.1.1"
    backup_ping_host: str = "8.8.8.8"
    dns_host: str = "www.google.com"
    pings: int = 5
    ping_period_ms: int = 1000
    ping_timeout_ms: int = 1000
    interval: int = 10
    trigger: int = 3
    high_latency_ms: float = 1000.0
    dns_failure_trigger: int = 3
    max_alerts_per_hour: int = 5
    loss_alert_delay_seconds: int = 300
    latency_alert_delay_seconds: int = 300
    outage_alert_delay_seconds: int = 300
    log_path: str = DEFAULT_LOG_PATH
    status_path: str = DEFAULT_STATUS_PATH
    timezone: str = "America/Detroit"


@dataclass(frozen=True)
class WebSettings:
    """Settings used by the Flask log viewer."""

    title: str = "Internet Connection Log"
    port: int = 5005
    log_path: str = DEFAULT_LOG_PATH
    log_lines: int = 200
    allowed_hosts: tuple[str, ...] = ()
    status_path: str = DEFAULT_STATUS_PATH
    status_max_age: int = 300
    refresh_interval: int = 10


@dataclass(frozen=True)
class PushoverSettings:
    """Settings for optional Pushover notifications."""

    token: str = ""
    user: str = ""
    device: str = ""
    priority: int = 0


@dataclass(frozen=True)
class Settings:
    """Complete application settings loaded from Docker environment variables."""

    monitor: MonitorSettings
    web: WebSettings
    pushover: PushoverSettings


def _raw_env(
    env: Mapping[str, str],
    name: str,
    default: str,
    aliases: Sequence[str] = (),
) -> str:
    """Return the first configured value for name or its aliases."""
    for key in (name, *aliases):
        value = env.get(key)
        if value is not None:
            return value
    return default


def _env_str(
    env: Mapping[str, str],
    name: str,
    default: str = "",
    aliases: Sequence[str] = (),
) -> str:
    """Read a string environment variable."""
    return _raw_env(env, name, default, aliases).strip()


def _env_required_str(
    env: Mapping[str, str],
    name: str,
    default: str,
    aliases: Sequence[str] = (),
) -> str:
    """Read a required string environment variable."""
    value = _env_str(env, name, default, aliases)
    if not value:
        raise ConfigurationError(f"{name} must not be empty.")
    return value


def _env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    """Read a boolean environment variable using common Docker-friendly values."""
    raw = _raw_env(env, name, "true" if default else "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(
        f"{name} must be a boolean value such as true, false, 1, or 0."
    )


def _env_int(
    env: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    aliases: Sequence[str] = (),
) -> int:
    """Read and validate an integer environment variable."""
    raw = _raw_env(env, name, str(default), aliases).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer.") from exc

    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{name} must be greater than or equal to {minimum}.")
    if maximum is not None and value > maximum:
        raise ConfigurationError(f"{name} must be less than or equal to {maximum}.")
    return value


def _env_float(
    env: Mapping[str, str],
    name: str,
    default: float,
    *,
    minimum: float | None = None,
) -> float:
    """Read and validate a floating-point environment variable."""
    raw = _raw_env(env, name, str(default)).strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number.") from exc

    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{name} must be greater than or equal to {minimum}.")
    return value


def _env_hosts(env: Mapping[str, str], name: str) -> tuple[str, ...]:
    """Read comma-, shell-, or whitespace-separated host/IP allow-list values."""
    raw = _raw_env(env, name, "").replace(",", " ").strip()
    if not raw:
        return ()
    try:
        return tuple(part.strip() for part in shlex.split(raw) if part.strip())
    except ValueError as exc:
        raise ConfigurationError(f"{name} contains invalid quoting.") from exc


def _validate_timezone(timezone_name: str) -> str:
    """Validate a pytz timezone name while preserving the configured string."""
    try:
        pytz.timezone(timezone_name)
    except Exception as exc:
        raise ConfigurationError(f"INTERNET_MONITOR_TIMEZONE is invalid: {exc}") from exc
    return timezone_name


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Load all application settings from environment variables."""
    source = os.environ if env is None else env

    monitor_log_path = _env_required_str(
        source, "INTERNET_MONITOR_LOG_PATH", DEFAULT_LOG_PATH
    )
    monitor_status_path = _env_required_str(
        source, "INTERNET_MONITOR_STATUS_PATH", DEFAULT_STATUS_PATH
    )
    interval = _env_int(source, "INTERNET_MONITOR_INTERVAL", 10, minimum=1)

    monitor = MonitorSettings(
        debug=_env_bool(source, "INTERNET_MONITOR_DEBUG", False),
        ping_host=_env_required_str(source, "INTERNET_MONITOR_PING_HOST", "1.1.1.1"),
        backup_ping_host=_env_str(
            source, "INTERNET_MONITOR_BACKUP_PING_HOST", "8.8.8.8"
        ),
        dns_host=_env_required_str(
            source, "INTERNET_MONITOR_DNS_HOST", "www.google.com"
        ),
        pings=_env_int(source, "INTERNET_MONITOR_PINGS", 5, minimum=1),
        ping_period_ms=_env_int(
            source, "INTERNET_MONITOR_PING_PERIOD_MS", 1000, minimum=10
        ),
        ping_timeout_ms=_env_int(
            source, "INTERNET_MONITOR_PING_TIMEOUT_MS", 1000, minimum=50
        ),
        interval=interval,
        trigger=_env_int(source, "INTERNET_MONITOR_TRIGGER", 3, minimum=1),
        high_latency_ms=_env_float(
            source, "INTERNET_MONITOR_HIGH_LATENCY_MS", 1000.0, minimum=0.0
        ),
        dns_failure_trigger=_env_int(
            source, "INTERNET_MONITOR_DNS_FAILURE_TRIGGER", 3, minimum=1
        ),
        max_alerts_per_hour=_env_int(
            source, "INTERNET_MONITOR_MAX_ALERTS_PER_HOUR", 5, minimum=0
        ),
        loss_alert_delay_seconds=_env_int(
            source, "INTERNET_MONITOR_LOSS_ALERT_DELAY_SECONDS", 300, minimum=0
        ),
        latency_alert_delay_seconds=_env_int(
            source, "INTERNET_MONITOR_LATENCY_ALERT_DELAY_SECONDS", 300, minimum=0
        ),
        outage_alert_delay_seconds=_env_int(
            source, "INTERNET_MONITOR_OUTAGE_ALERT_DELAY_SECONDS", 300, minimum=0
        ),
        log_path=monitor_log_path,
        status_path=monitor_status_path,
        timezone=_validate_timezone(
            _env_str(source, "INTERNET_MONITOR_TIMEZONE", "America/Detroit")
        ),
    )

    web = WebSettings(
        title=_env_str(source, "INTERNET_MONITOR_WEB_TITLE", "Internet Connection Log"),
        port=_env_int(source, "INTERNET_MONITOR_WEB_PORT", 5005, minimum=1, maximum=65535),
        log_path=_env_required_str(
            source, "INTERNET_MONITOR_WEB_LOG_PATH", monitor_log_path
        ),
        log_lines=_env_int(source, "INTERNET_MONITOR_WEB_LOG_LINES", 200, minimum=1),
        allowed_hosts=_env_hosts(source, "INTERNET_MONITOR_WEB_ALLOWED_HOSTS"),
        status_path=_env_required_str(
            source, "INTERNET_MONITOR_WEB_STATUS_PATH", monitor_status_path
        ),
        status_max_age=_env_int(
            source, "INTERNET_MONITOR_WEB_STATUS_MAX_AGE", 300, minimum=0
        ),
        refresh_interval=interval,
    )

    pushover = PushoverSettings(
        token=_env_str(
            source,
            "INTERNET_MONITOR_PUSHOVER_TOKEN",
            "",
            aliases=("PUSHOVER_TOKEN",),
        ),
        user=_env_str(
            source,
            "INTERNET_MONITOR_PUSHOVER_USER",
            "",
            aliases=("PUSHOVER_USER",),
        ),
        device=_env_str(
            source,
            "INTERNET_MONITOR_PUSHOVER_DEVICE",
            "",
            aliases=("PUSHOVER_DEVICE",),
        ),
        priority=_env_int(
            source,
            "INTERNET_MONITOR_PUSHOVER_PRIORITY",
            0,
            minimum=-2,
            maximum=2,
            aliases=("PUSHOVER_PRIORITY",),
        ),
    )

    return Settings(monitor=monitor, web=web, pushover=pushover)
