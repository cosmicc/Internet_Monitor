"""Validated environment-backed configuration for Internet Monitor."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import pytz


DEFAULT_STATUS_PATH = "/tmp/internet-monitor/status.json"
DEFAULT_HISTORY_PATH = "/tmp/internet-monitor/history.json"
MAX_SECRET_BYTES = 4096
MAX_DNS_SERVERS = 8
SAFE_PROBE_HOST_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


class ConfigurationError(ValueError):
    """Raised when runtime configuration is missing or invalid."""


@dataclass(frozen=True)
class MonitorSettings:
    """Settings used by the long-running connectivity monitor."""

    log_level: str = "INFO"
    ping_host: str = "1.1.1.1"
    backup_ping_host: str = "8.8.8.8"
    gateway_1_ip: str = ""
    gateway_2_ip: str = ""
    important_hosts: tuple[str, ...] = ()
    dns_host: str = "www.google.com"
    dns_servers: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
    dns_record_type: str = "A"
    dns_timeout_seconds: int = 5
    dns_slow_threshold_ms: float = 500.0
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
    status_path: str = DEFAULT_STATUS_PATH
    history_path: str = DEFAULT_HISTORY_PATH
    timezone: str = "America/Detroit"


@dataclass(frozen=True)
class WebSettings:
    """Settings used by the Flask status dashboard."""

    title: str = "Internet Monitor"
    port: int = 5005
    workers: int = 1
    threads: int = 2
    allowed_hosts: tuple[str, ...] = ()
    status_path: str = DEFAULT_STATUS_PATH
    history_path: str = DEFAULT_HISTORY_PATH
    history_max_points: int = 720
    status_max_age: int = 300
    refresh_interval: int = 10


@dataclass(frozen=True)
class PushoverSettings:
    """Settings for optional Pushover notifications."""

    token: str = ""
    user: str = ""
    device: str = ""
    priority: int = 0
    timeout_seconds: int = 10
    retry_initial_seconds: int = 30
    retry_max_seconds: int = 900


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
) -> str:
    """Return one environment value without legacy-name fallbacks."""
    return env.get(name, default)


def _env_str(
    env: Mapping[str, str],
    name: str,
    default: str = "",
) -> str:
    """Read a stripped string environment variable."""
    return _raw_env(env, name, default).strip()


def _env_required_str(
    env: Mapping[str, str],
    name: str,
    default: str,
) -> str:
    """Read a non-empty string environment variable."""
    value = _env_str(env, name, default)
    if not value:
        raise ConfigurationError(f"{name} must not be empty.")
    return value


def _env_probe_host(
    env: Mapping[str, str],
    name: str,
    default: str = "",
    *,
    required: bool = True,
) -> str:
    """Read a bounded host or IP value safe for argument-based probe tools."""
    value = _env_str(env, name, default)
    if not value:
        if required:
            raise ConfigurationError(f"{name} must not be empty.")
        return ""
    if value.startswith("-") or not SAFE_PROBE_HOST_PATTERN.fullmatch(value):
        raise ConfigurationError(
            f"{name} must be a valid host name or IP address without options, "
            "whitespace, or control characters."
        )
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


def _env_int(
    env: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Read and range-check an integer environment variable."""
    raw = _raw_env(env, name, str(default)).strip()
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
    """Read and range-check a floating-point environment variable."""
    raw = _raw_env(env, name, str(default)).strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number.") from exc

    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{name} must be greater than or equal to {minimum}.")
    return value


def _env_items(env: Mapping[str, str], name: str) -> tuple[str, ...]:
    """Read comma-, shell-, or whitespace-separated values."""
    raw = _raw_env(env, name, "").replace(",", " ").strip()
    if not raw:
        return ()
    try:
        return tuple(part.strip() for part in shlex.split(raw) if part.strip())
    except ValueError as exc:
        raise ConfigurationError(f"{name} contains invalid quoting.") from exc


def _env_dns_servers(env: Mapping[str, str]) -> tuple[str, ...]:
    """Read a required, de-duplicated list of DNS server IP addresses."""
    configured = _env_items(env, "DNS_SERVERS")
    values = configured or ("1.1.1.1", "8.8.8.8")
    servers: list[str] = []

    for value in values:
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ConfigurationError(
                "DNS_SERVERS must contain only IPv4 or IPv6 "
                f"addresses; invalid value: {value!r}."
            ) from exc
        if normalized not in servers:
            servers.append(normalized)

    if len(servers) > MAX_DNS_SERVERS:
        raise ConfigurationError(
            "DNS_SERVERS must contain no more than "
            f"{MAX_DNS_SERVERS} unique addresses."
        )

    return tuple(servers)


def _env_important_hosts(env: Mapping[str, str]) -> tuple[str, ...]:
    """Read up to three optional, de-duplicated important ping hosts."""
    hosts: list[str] = []
    for position in range(1, 4):
        host = _env_probe_host(
            env,
            f"IMPORTANT_HOST_{position}",
            required=False,
        )
        if host and host not in hosts:
            hosts.append(host)
    return tuple(hosts)


def _env_optional_ip(env: Mapping[str, str], name: str) -> str:
    """Read an optional normalized IPv4 or IPv6 address."""
    value = _env_str(env, name)
    if not value:
        return ""

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ConfigurationError(
            f"{name} must be a valid IPv4 or IPv6 address when configured."
        ) from exc


def _env_choice(
    env: Mapping[str, str],
    name: str,
    default: str,
    choices: set[str],
) -> str:
    """Read an uppercase string constrained to an explicit allow-list."""
    value = _env_required_str(env, name, default).upper()
    if value not in choices:
        allowed = ", ".join(sorted(choices))
        raise ConfigurationError(f"{name} must be one of: {allowed}.")
    return value


def _env_secret(
    env: Mapping[str, str],
    name: str,
) -> str:
    """Read a secret from ``NAME_FILE`` or directly from ``NAME``.

    Docker secret files take precedence over direct environment values. Reads are
    deliberately bounded so an incorrect path cannot load an arbitrary large file.
    """
    file_variable = f"{name}_FILE"
    file_path = _env_str(env, file_variable)
    if not file_path:
        return _env_str(env, name)

    try:
        with Path(file_path).open("r", encoding="utf-8") as handle:
            value = handle.read(MAX_SECRET_BYTES + 1)
    except OSError as exc:
        raise ConfigurationError(f"Unable to read the secret configured by {file_variable}.") from exc

    if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
        raise ConfigurationError(f"The secret configured by {file_variable} is too large.")

    value = value.strip()
    if not value:
        raise ConfigurationError(f"The secret configured by {file_variable} is empty.")
    return value


def _validate_timezone(timezone_name: str) -> str:
    """Validate a pytz timezone name while preserving the configured string."""
    try:
        pytz.timezone(timezone_name)
    except pytz.UnknownTimeZoneError as exc:
        raise ConfigurationError(
            f"TIMEZONE is invalid: {timezone_name!r}."
        ) from exc
    return timezone_name


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Load and validate all application settings from the environment."""
    source = os.environ if env is None else env
    interval = _env_int(
        source,
        "INTERVAL",
        10,
        minimum=5,
        maximum=3600,
    )
    status_path = _env_required_str(
        source, "STATUS_PATH", DEFAULT_STATUS_PATH
    )
    history_path = _env_required_str(
        source, "HISTORY_PATH", DEFAULT_HISTORY_PATH
    )
    if history_path == status_path:
        raise ConfigurationError(
            "HISTORY_PATH must differ from "
            "STATUS_PATH."
        )

    monitor = MonitorSettings(
        log_level=_env_choice(
            source,
            "LOG_LEVEL",
            "INFO",
            {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"},
        ),
        ping_host=_env_probe_host(
            source,
            "PING_HOST",
            "1.1.1.1",
        ),
        backup_ping_host=_env_probe_host(
            source,
            "BACKUP_PING_HOST",
            "8.8.8.8",
            required=False,
        ),
        gateway_1_ip=_env_optional_ip(source, "GATEWAY_1_IP"),
        gateway_2_ip=_env_optional_ip(source, "GATEWAY_2_IP"),
        important_hosts=_env_important_hosts(source),
        dns_host=_env_probe_host(
            source,
            "DNS_HOST",
            "www.google.com",
        ),
        dns_servers=_env_dns_servers(source),
        dns_record_type=_env_choice(
            source, "DNS_RECORD_TYPE", "A", {"A", "AAAA"}
        ),
        dns_timeout_seconds=_env_int(
            source, "DNS_TIMEOUT_SECONDS", 5, minimum=1, maximum=30
        ),
        dns_slow_threshold_ms=_env_float(
            source, "DNS_SLOW_THRESHOLD_MS", 500.0, minimum=1.0
        ),
        pings=_env_int(
            source,
            "PINGS",
            5,
            minimum=1,
            maximum=10,
        ),
        ping_period_ms=_env_int(
            source,
            "PING_PERIOD_MS",
            1000,
            minimum=100,
            maximum=5000,
        ),
        ping_timeout_ms=_env_int(
            source,
            "PING_TIMEOUT_MS",
            1000,
            minimum=50,
            maximum=5000,
        ),
        interval=interval,
        trigger=_env_int(source, "TRIGGER", 3, minimum=1),
        high_latency_ms=_env_float(
            source, "HIGH_LATENCY_MS", 1000.0, minimum=0.0
        ),
        dns_failure_trigger=_env_int(
            source, "DNS_FAILURE_TRIGGER", 3, minimum=1
        ),
        max_alerts_per_hour=_env_int(
            source, "MAX_ALERTS_PER_HOUR", 5, minimum=0
        ),
        loss_alert_delay_seconds=_env_int(
            source, "LOSS_ALERT_DELAY_SECONDS", 300, minimum=0
        ),
        latency_alert_delay_seconds=_env_int(
            source, "LATENCY_ALERT_DELAY_SECONDS", 300, minimum=0
        ),
        outage_alert_delay_seconds=_env_int(
            source, "OUTAGE_ALERT_DELAY_SECONDS", 300, minimum=0
        ),
        status_path=status_path,
        history_path=history_path,
        timezone=_validate_timezone(
            _env_required_str(
                source, "TIMEZONE", "America/Detroit"
            )
        ),
    )

    ping_window_seconds = (
        (monitor.pings - 1) * monitor.ping_period_ms
        + monitor.ping_timeout_ms
        + 999
    ) // 1000
    minimum_probe_interval = max(
        monitor.dns_timeout_seconds,
        ping_window_seconds,
    )
    if monitor.interval < minimum_probe_interval:
        raise ConfigurationError(
            "INTERVAL must be at least the longest configured "
            f"probe window ({minimum_probe_interval} seconds)."
        )

    web = WebSettings(
        title=_env_required_str(
            source, "WEB_TITLE", "Internet Monitor"
        ),
        workers=_env_int(
            source,
            "WEB_WORKERS",
            1,
            minimum=1,
            maximum=4,
        ),
        threads=_env_int(
            source,
            "WEB_THREADS",
            2,
            minimum=1,
            maximum=8,
        ),
        allowed_hosts=_env_items(source, "WEB_ALLOWED_HOSTS"),
        status_path=status_path,
        history_path=history_path,
        history_max_points=_env_int(
            source,
            "HISTORY_MAX_POINTS",
            720,
            minimum=120,
            maximum=720,
        ),
        status_max_age=_env_int(
            source, "WEB_STATUS_MAX_AGE", 300, minimum=0
        ),
        refresh_interval=interval,
    )

    pushover_retry_initial_seconds = _env_int(
        source,
        "PUSHOVER_RETRY_INITIAL_SECONDS",
        30,
        minimum=1,
        maximum=3600,
    )
    pushover_retry_max_seconds = _env_int(
        source,
        "PUSHOVER_RETRY_MAX_SECONDS",
        900,
        minimum=1,
        maximum=86400,
    )
    if pushover_retry_max_seconds < pushover_retry_initial_seconds:
        raise ConfigurationError(
            "PUSHOVER_RETRY_MAX_SECONDS must be greater than "
            "or equal to PUSHOVER_RETRY_INITIAL_SECONDS."
        )

    pushover = PushoverSettings(
        token=_env_secret(source, "PUSHOVER_TOKEN"),
        user=_env_secret(source, "PUSHOVER_USER"),
        device=_env_str(source, "PUSHOVER_DEVICE"),
        priority=_env_int(
            source,
            "PUSHOVER_PRIORITY",
            0,
            minimum=-2,
            maximum=2,
        ),
        timeout_seconds=_env_int(
            source,
            "PUSHOVER_TIMEOUT_SECONDS",
            10,
            minimum=1,
            maximum=60,
        ),
        retry_initial_seconds=pushover_retry_initial_seconds,
        retry_max_seconds=pushover_retry_max_seconds,
    )

    return Settings(monitor=monitor, web=web, pushover=pushover)
