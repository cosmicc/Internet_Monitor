#!/usr/bin/env python3
"""Run Internet, latency, packet-loss, resolver, and DNS-server checks.

Human-readable events are written to the container console. Atomic current and
30-day tiered-history JSON snapshots in tmpfs allow the colocated web process to
render live results without durable storage.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Optional

import pytz
import requests

from .history import HistorySeries, HistoryStore, HistoryValue
from .settings import (
    ConfigurationError,
    MonitorSettings,
    PushoverSettings,
    Settings,
    load_settings,
)
from .storage import StorageStatus, read_storage_status


LOGGER = logging.getLogger("internet_monitor.monitor")


def configure_logging(log_level: str) -> None:
    """Configure human-readable UTC logging for Docker stdout."""
    logging.Formatter.converter = time.gmtime
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)sZ %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
        force=True,
    )


def utcnow() -> datetime:
    """Return the current timezone-aware UTC time."""
    return datetime.now(tz=pytz.utc)


def format_local(timestamp: datetime, timezone_name: str) -> str:
    """Format a timestamp in the configured local timezone."""
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=pytz.utc)
    local_timezone = pytz.timezone(timezone_name)
    return timestamp.astimezone(local_timezone).strftime("%Y-%m-%d %H:%M:%S %Z")


def format_duration(seconds: int) -> str:
    """Format a duration as readable hours, minutes, and seconds."""
    total_seconds = max(0, int(timedelta(seconds=int(seconds)).total_seconds()))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, remaining_seconds = divmod(remainder, 60)

    parts: list[str] = []
    if hours:
        parts.append(f"{hours} hour" + ("s" if hours != 1 else ""))
    if minutes:
        parts.append(f"{minutes} minute" + ("s" if minutes != 1 else ""))
    if remaining_seconds or not parts:
        parts.append(
            f"{remaining_seconds} second" + ("s" if remaining_seconds != 1 else "")
        )
    return ", ".join(parts)


def log_probe_issue(
    occurrence_count: int,
    message: str,
    *arguments: object,
) -> None:
    """Warn on a new issue, then keep repeated per-cycle details at debug."""
    level = logging.WARNING if occurrence_count == 1 else logging.DEBUG
    LOGGER.log(level, message, *arguments)


@dataclass(frozen=True)
class PingResult:
    """Result of an fping invocation."""

    success: bool
    avg_latency_ms: Optional[float]
    loss_percent: Optional[int]
    raw_output: str
    host: str = ""
    error: Optional[str] = None
    used_backup: bool = False
    min_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None
    transmitted: Optional[int] = None
    received: Optional[int] = None


@dataclass(frozen=True)
class PingMetrics:
    """Parsed packet and latency statistics from one fping summary."""

    transmitted: Optional[int] = None
    received: Optional[int] = None
    loss_percent: Optional[int] = None
    min_latency_ms: Optional[float] = None
    avg_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None


def parse_fping_output(output: str) -> PingMetrics:
    """Extract packet counts, loss, and latency values from fping output."""
    transmitted = None
    received = None
    loss_percent = None
    minimum_latency = None
    average_latency = None
    maximum_latency = None

    loss_match = re.search(r"=\s*(\d+)/(\d+)/(\d+)%", output)
    if loss_match:
        transmitted = int(loss_match.group(1))
        received = int(loss_match.group(2))
        loss_percent = int(loss_match.group(3))

    latency_match = re.search(
        r"min/avg/max.*=\s*([\d.]+)/([\d.]+)/([\d.]+)", output
    )
    if latency_match:
        minimum_latency = float(latency_match.group(1))
        average_latency = float(latency_match.group(2))
        maximum_latency = float(latency_match.group(3))

    return PingMetrics(
        transmitted=transmitted,
        received=received,
        loss_percent=loss_percent,
        min_latency_ms=minimum_latency,
        avg_latency_ms=average_latency,
        max_latency_ms=maximum_latency,
    )


def _run_single_ping(host: str, settings: MonitorSettings) -> PingResult:
    """Run fping against one host with explicit container-safe timing."""
    command = [
        "fping",
        "-c",
        str(settings.pings),
        "-p",
        str(settings.ping_period_ms),
        "-t",
        str(settings.ping_timeout_ms),
        "--",
        host,
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(5, settings.pings * settings.ping_period_ms / 1000 + 5),
        )
    except FileNotFoundError:
        return PingResult(
            success=False,
            avg_latency_ms=None,
            loss_percent=None,
            raw_output="",
            host=host,
            error="fping is not installed",
        )
    except subprocess.TimeoutExpired:
        return PingResult(
            success=False,
            avg_latency_ms=None,
            loss_percent=100,
            raw_output="",
            host=host,
            error="fping timed out",
            transmitted=settings.pings,
            received=0,
        )
    except OSError as exc:
        return PingResult(
            success=False,
            avg_latency_ms=None,
            loss_percent=None,
            raw_output="",
            host=host,
            error=f"unable to execute fping: {exc}",
        )

    output = "\n".join(part for part in (process.stdout, process.stderr) if part)
    metrics = parse_fping_output(output)
    received_a_reply = (
        metrics.loss_percent is not None and metrics.loss_percent < 100
    )
    success = process.returncode == 0 or received_a_reply

    LOGGER.debug(
        "fping host=%s return_code=%s average_latency_ms=%s loss_percent=%s",
        host,
        process.returncode,
        metrics.avg_latency_ms,
        metrics.loss_percent,
    )

    return PingResult(
        success=success,
        avg_latency_ms=metrics.avg_latency_ms,
        loss_percent=metrics.loss_percent,
        raw_output=output,
        host=host,
        error=None if success else f"fping failed with code {process.returncode}",
        min_latency_ms=metrics.min_latency_ms,
        max_latency_ms=metrics.max_latency_ms,
        transmitted=metrics.transmitted,
        received=metrics.received,
    )


def _ping_result_is_clean(result: PingResult, settings: MonitorSettings) -> bool:
    """Return whether a ping result has no loss and acceptable latency."""
    if not result.success or result.loss_percent not in (None, 0):
        return False
    return (
        result.avg_latency_ms is None
        or result.avg_latency_ms <= settings.high_latency_ms
    )


def _ping_result_score(result: PingResult) -> tuple[int, int, float]:
    """Return a sort key where lower values represent a healthier result."""
    if not result.success:
        return (1, 100, float("inf"))
    loss = result.loss_percent if result.loss_percent is not None else 0
    latency = result.avg_latency_ms if result.avg_latency_ms is not None else 0.0
    return (0, loss, latency)


def configured_ping_hosts(settings: MonitorSettings) -> tuple[str, ...]:
    """Return all unique Internet and gateway targets in display order."""
    hosts = (
        settings.ping_host,
        settings.backup_ping_host,
        settings.gateway_1_ip,
        settings.gateway_2_ip,
    )
    return tuple(dict.fromkeys(host for host in hosts if host))


def select_internet_result(
    settings: MonitorSettings,
    results: dict[str, PingResult],
) -> PingResult:
    """Choose the healthiest Internet target while preferring a clean primary."""
    primary = results[settings.ping_host]
    backup_enabled = bool(
        settings.backup_ping_host
        and settings.backup_ping_host != settings.ping_host
    )
    if _ping_result_is_clean(primary, settings) or not backup_enabled:
        return primary

    backup = replace(results[settings.backup_ping_host], used_backup=True)

    if _ping_result_is_clean(backup, settings):
        LOGGER.info(
            "Primary ping host %s is degraded; backup host %s is healthy.",
            settings.ping_host,
            settings.backup_ping_host,
        )
        return backup

    if primary.success or backup.success:
        return min((primary, backup), key=_ping_result_score)

    return PingResult(
        success=False,
        avg_latency_ms=None,
        loss_percent=100,
        raw_output=f"primary:\n{primary.raw_output}\nbackup:\n{backup.raw_output}",
        host=f"{settings.ping_host}, {settings.backup_ping_host}",
        error=(
            f"primary ping host {settings.ping_host} and backup ping host "
            f"{settings.backup_ping_host} failed"
        ),
        transmitted=(primary.transmitted or 0) + (backup.transmitted or 0),
        received=(primary.received or 0) + (backup.received or 0),
    )


def run_ping(settings: MonitorSettings) -> PingResult:
    """Compatibility helper that checks all targets and selects Internet health."""
    results = run_ping_checks(settings)
    return select_internet_result(settings, results)


@dataclass(frozen=True)
class ResolverResult:
    """Result of resolving the configured hostname through the system resolver."""

    state: str
    response_time_ms: Optional[float]
    error: Optional[str] = None


def check_system_resolver(
    hostname: str,
    timeout_seconds: int = 5,
) -> ResolverResult:
    """Resolve through NSS with a hard timeout so a cycle cannot hang."""
    started = time.monotonic()
    try:
        process = subprocess.run(
            ["getent", "ahosts", hostname],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        elapsed_ms = (time.monotonic() - started) * 1000
        return ResolverResult("down", round(elapsed_ms, 2), "getent is not installed")
    except subprocess.TimeoutExpired:
        elapsed_ms = (time.monotonic() - started) * 1000
        return ResolverResult(
            "down",
            round(elapsed_ms, 2),
            f"system resolver timed out after {timeout_seconds} seconds",
        )
    except OSError as exc:
        elapsed_ms = (time.monotonic() - started) * 1000
        return ResolverResult("down", round(elapsed_ms, 2), str(exc))

    elapsed_ms = (time.monotonic() - started) * 1000
    if process.returncode != 0 or not process.stdout.strip():
        return ResolverResult(
            "down",
            round(elapsed_ms, 2),
            f"system resolver exited with code {process.returncode}",
        )
    return ResolverResult("up", round(elapsed_ms, 2))


@dataclass(frozen=True)
class DnsQueryResult:
    """Result of querying one explicit DNS server with dig."""

    server: str
    state: str
    response_time_ms: Optional[float]
    response_status: str = "UNKNOWN"
    answer_count: int = 0
    error: Optional[str] = None


def run_dig(server: str, settings: MonitorSettings) -> DnsQueryResult:
    """Query one DNS server with dig and classify failures and slow responses."""
    command = [
        "dig",
        f"@{server}",
        settings.dns_host,
        settings.dns_record_type,
        "+noall",
        "+comments",
        "+answer",
        "+stats",
        f"+time={settings.dns_timeout_seconds}",
        "+tries=1",
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=settings.dns_timeout_seconds + 2,
        )
    except FileNotFoundError:
        return DnsQueryResult(
            server=server,
            state="down",
            response_time_ms=None,
            error="dig is not installed",
        )
    except subprocess.TimeoutExpired:
        return DnsQueryResult(
            server=server,
            state="down",
            response_time_ms=None,
            error=f"dig timed out after {settings.dns_timeout_seconds} seconds",
        )
    except OSError as exc:
        return DnsQueryResult(
            server=server,
            state="down",
            response_time_ms=None,
            error=f"unable to execute dig: {exc}",
        )

    output = "\n".join(part for part in (process.stdout, process.stderr) if part)
    status_match = re.search(r"status:\s*([A-Z]+)", output)
    answer_match = re.search(r"ANSWER:\s*(\d+)", output)
    time_match = re.search(r"Query time:\s*([\d.]+)\s*msec", output)

    response_status = status_match.group(1) if status_match else "UNKNOWN"
    answer_count = int(answer_match.group(1)) if answer_match else 0
    response_time_ms = float(time_match.group(1)) if time_match else None
    successful_response = (
        process.returncode == 0
        and response_status == "NOERROR"
        and answer_count > 0
        and response_time_ms is not None
    )

    if not successful_response:
        if process.returncode != 0:
            error = f"dig exited with code {process.returncode}"
        elif response_status != "NOERROR":
            error = f"DNS response status was {response_status}"
        elif answer_count <= 0:
            error = "DNS response contained no answers"
        else:
            error = "DNS response did not include query timing"
        return DnsQueryResult(
            server=server,
            state="down",
            response_time_ms=response_time_ms,
            response_status=response_status,
            answer_count=answer_count,
            error=error,
        )

    state = (
        "warning"
        if response_time_ms > settings.dns_slow_threshold_ms
        else "up"
    )
    return DnsQueryResult(
        server=server,
        state=state,
        response_time_ms=response_time_ms,
        response_status=response_status,
        answer_count=answer_count,
    )


def run_dns_server_checks(settings: MonitorSettings) -> list[DnsQueryResult]:
    """Run every configured dig query concurrently in configuration order."""
    if not settings.dns_servers:
        return []
    with ThreadPoolExecutor(max_workers=len(settings.dns_servers)) as executor:
        futures = {
            server: executor.submit(run_dig, server, settings)
            for server in settings.dns_servers
        }
        return [futures[server].result() for server in settings.dns_servers]


def run_ping_checks(settings: MonitorSettings) -> dict[str, PingResult]:
    """Run every configured Internet and gateway ping concurrently."""
    hosts = configured_ping_hosts(settings)
    with ThreadPoolExecutor(max_workers=len(hosts)) as executor:
        futures = {
            host: executor.submit(_run_single_ping, host, settings) for host in hosts
        }
        return {host: futures[host].result() for host in hosts}


@dataclass(frozen=True)
class ProbeCycleResult:
    """All network and DNS observations from one monitoring cycle."""

    ping_results: dict[str, PingResult]
    resolver_result: ResolverResult
    dns_results: list[DnsQueryResult]
    important_results: dict[str, PingResult]
    important_hosts_skipped: bool


def probe_worker_count(settings: MonitorSettings) -> int:
    """Return the fixed worker count required by one concurrent probe cycle."""
    return (
        len(configured_ping_hosts(settings))
        + len(settings.dns_servers)
        + len(settings.important_hosts)
        + 1
    )


def dns_can_resolve_important_hosts(
    resolver_result: ResolverResult,
    dns_results: list[DnsQueryResult],
) -> bool:
    """Require the system resolver and at least one direct DNS server."""
    return resolver_result.state == "up" and any(
        result.state in {"up", "warning"} for result in dns_results
    )


def run_probe_cycle(
    settings: MonitorSettings,
    executor: ThreadPoolExecutor | None = None,
) -> ProbeCycleResult:
    """Collect every configured probe concurrently for a comparable snapshot."""
    ping_hosts = configured_ping_hosts(settings)
    owns_executor = executor is None
    active_executor = executor or ThreadPoolExecutor(
        max_workers=probe_worker_count(settings),
        thread_name_prefix="internet-monitor-probe",
    )
    try:
        ping_futures = {
            host: active_executor.submit(_run_single_ping, host, settings)
            for host in ping_hosts
        }
        resolver_future = active_executor.submit(
            check_system_resolver,
            settings.dns_host,
            settings.dns_timeout_seconds,
        )
        dns_futures = {
            server: active_executor.submit(run_dig, server, settings)
            for server in settings.dns_servers
        }

        resolver_result = resolver_future.result()
        important_futures = {}
        dns_results_by_server: dict[str, DnsQueryResult] = {}
        for completed_future in as_completed(dns_futures.values()):
            dns_result = completed_future.result()
            dns_results_by_server[dns_result.server] = dns_result
            if (
                settings.important_hosts
                and not important_futures
                and dns_can_resolve_important_hosts(
                    resolver_result,
                    list(dns_results_by_server.values()),
                )
            ):
                # Start hostname pings as soon as one direct DNS path works.
                # Slower DNS checks continue in parallel and remain part of the
                # completed cycle snapshot.
                important_futures = {
                    host: active_executor.submit(_run_single_ping, host, settings)
                    for host in settings.important_hosts
                }

        dns_results = [
            dns_results_by_server[server] for server in settings.dns_servers
        ]
        important_hosts_skipped = bool(settings.important_hosts) and not (
            important_futures
        )

        ping_results = {
            host: ping_futures[host].result() for host in ping_hosts
        }
        important_results = {
            host: important_futures[host].result()
            for host in settings.important_hosts
            if host in important_futures
        }
    finally:
        if owns_executor:
            active_executor.shutdown(wait=True, cancel_futures=True)
    return ProbeCycleResult(
        ping_results,
        resolver_result,
        dns_results,
        important_results,
        important_hosts_skipped,
    )


def determine_dns_state(
    resolver_result: ResolverResult,
    server_results: list[DnsQueryResult],
) -> str:
    """Derive the aggregate dashboard DNS state from resolver and server checks."""
    if not server_results:
        return "down" if resolver_result.state == "down" else "warning"

    all_servers_down = all(result.state == "down" for result in server_results)
    if resolver_result.state == "down" and all_servers_down:
        return "down"
    if resolver_result.state != "up" or any(
        result.state != "up" for result in server_results
    ):
        return "warning"
    return "up"


def determine_ping_state(result: PingResult, settings: MonitorSettings) -> str:
    """Classify a ping result as healthy, degraded, or unreachable."""
    if not result.success:
        return "down"
    if (result.loss_percent or 0) > 0:
        return "warning"
    if (
        result.avg_latency_ms is not None
        and result.avg_latency_ms > settings.high_latency_ms
    ):
        return "warning"
    return "up"


@dataclass(frozen=True)
class Diagnosis:
    """Human-readable interpretation of the currently failing path segment."""

    state: str
    title: str
    detail: str


def determine_connection_diagnosis(
    settings: MonitorSettings,
    ping_results: dict[str, PingResult],
    internet_state: str,
    dns_state: str,
) -> Diagnosis:
    """Identify the closest unhealthy segment using the configured path order."""
    gateway_1 = ping_results.get(settings.gateway_1_ip) if settings.gateway_1_ip else None
    gateway_2 = ping_results.get(settings.gateway_2_ip) if settings.gateway_2_ip else None
    gateway_1_state = (
        determine_ping_state(gateway_1, settings) if gateway_1 else "unknown"
    )
    gateway_2_state = (
        determine_ping_state(gateway_2, settings) if gateway_2 else "unknown"
    )

    if gateway_1_state == "down":
        return Diagnosis(
            "down",
            "Local network issue",
            "Gateway 1 is unreachable from the monitoring server.",
        )
    if gateway_2_state == "down":
        if not settings.gateway_1_ip:
            return Diagnosis(
                "down",
                "Gateway 2 unreachable",
                "Gateway 1 is not configured, so the failing segment cannot be isolated.",
            )
        return Diagnosis(
            "down",
            "Upstream gateway issue",
            "Gateway 1 responds, but Gateway 2 is unreachable.",
        )
    if internet_state == "down":
        if not settings.gateway_1_ip and not settings.gateway_2_ip:
            return Diagnosis(
                "down",
                "Internet connection issue",
                "Internet targets are unreachable; configure gateways to isolate the failing segment.",
            )
        return Diagnosis(
            "down",
            "ISP or Internet issue",
            "Configured gateways respond, but the Internet targets are unreachable.",
        )
    if dns_state in {"down", "warning"}:
        return Diagnosis(
            dns_state,
            "DNS issue",
            "Internet connectivity responds, but one or more DNS checks are unhealthy.",
        )
    if "warning" in {gateway_1_state, gateway_2_state, internet_state}:
        return Diagnosis(
            "warning",
            "Connection degraded",
            "One or more path segments have packet loss or high latency.",
        )
    return Diagnosis(
        "up",
        "Connection healthy",
        "All configured network hops and DNS services are responding.",
    )


def _ping_snapshot(result: PingResult, settings: MonitorSettings) -> dict[str, object]:
    """Convert one ping result into the bounded dashboard snapshot shape."""
    return {
        "state": determine_ping_state(result, settings),
        "host": result.host,
        "minimum_latency_ms": result.min_latency_ms,
        "average_latency_ms": result.avg_latency_ms,
        "maximum_latency_ms": result.max_latency_ms,
        "loss_percent": result.loss_percent,
        "transmitted": result.transmitted,
        "received": result.received,
    }


def configured_internet_targets(
    settings: MonitorSettings,
) -> list[tuple[str, str]]:
    """Return unique primary and backup targets in dashboard order."""
    targets: list[tuple[str, str]] = []
    included_hosts: set[str] = set()
    for role, host in (
        ("Primary", settings.ping_host),
        ("Backup", settings.backup_ping_host),
    ):
        if host and host not in included_hosts:
            included_hosts.add(host)
            targets.append((role, host))
    return targets


def build_history_series(settings: MonitorSettings) -> list[HistorySeries]:
    """Build stable metadata for every retained ping and DNS series."""
    series = [
        HistorySeries("gateway-1", "Gateway 1", "ping", settings.gateway_1_ip),
        HistorySeries("gateway-2", "Gateway 2", "ping", settings.gateway_2_ip),
        HistorySeries("internet", "Active Internet", "ping", "Selected target"),
    ]
    series.extend(
        HistorySeries(
            f"internet-target-{index}",
            f"{role} Internet",
            "ping",
            host,
        )
        for index, (role, host) in enumerate(configured_internet_targets(settings))
    )
    series.append(
        HistorySeries(
            "dns-resolver",
            "System Resolver",
            "dns",
            settings.dns_host,
        )
    )
    series.extend(
        HistorySeries(
            f"dns-server-{index}",
            f"DNS {server}",
            "dns",
            server,
        )
        for index, server in enumerate(settings.dns_servers)
    )
    series.extend(
        HistorySeries(
            f"important-host-{index}",
            f"Important Host {index + 1}",
            "ping",
            host,
        )
        for index, host in enumerate(settings.important_hosts)
    )
    return series


def _ping_history_value(result: PingResult) -> HistoryValue:
    """Convert one fping result into a loss-preserving history value."""
    loss = result.loss_percent
    if loss is None:
        loss = 0 if result.success else 100
    return HistoryValue(
        average=result.avg_latency_ms,
        loss=float(loss),
        minimum=result.min_latency_ms,
        maximum=result.max_latency_ms,
    )


def build_history_values(
    settings: MonitorSettings,
    ping_result: PingResult,
    ping_results: dict[str, PingResult],
    resolver_result: ResolverResult,
    dns_results: list[DnsQueryResult],
    important_results: dict[str, PingResult] | None = None,
) -> dict[str, HistoryValue]:
    """Build one aligned history observation from a completed probe cycle."""
    values: dict[str, HistoryValue] = {
        "internet": _ping_history_value(ping_result),
        "dns-resolver": HistoryValue(
            average=resolver_result.response_time_ms,
            loss=100.0 if resolver_result.state == "down" else 0.0,
        ),
    }
    for position, host in (
        (1, settings.gateway_1_ip),
        (2, settings.gateway_2_ip),
    ):
        if host and host in ping_results:
            values[f"gateway-{position}"] = _ping_history_value(
                ping_results[host]
            )
    for index, (_role, host) in enumerate(configured_internet_targets(settings)):
        values[f"internet-target-{index}"] = _ping_history_value(
            ping_results[host]
        )
    for index, result in enumerate(dns_results):
        values[f"dns-server-{index}"] = HistoryValue(
            average=result.response_time_ms,
            loss=100.0 if result.state == "down" else 0.0,
        )
    for index, host in enumerate(settings.important_hosts):
        result = (important_results or {}).get(host)
        if result is not None:
            values[f"important-host-{index}"] = _ping_history_value(result)
    return values


def determine_important_hosts_state(
    settings: MonitorSettings,
    results: dict[str, PingResult],
    skipped: bool,
) -> str:
    """Summarize configured important-host checks without false DNS failures."""
    if not settings.important_hosts:
        return "unknown"
    if skipped:
        return "warning"
    states = [determine_ping_state(results[host], settings) for host in settings.important_hosts]
    if all(state == "down" for state in states):
        return "down"
    if any(state != "up" for state in states):
        return "warning"
    return "up"


def write_status(
    settings: MonitorSettings,
    internet_state: str,
    ping_result: PingResult,
    ping_results: dict[str, PingResult],
    dns_state: str,
    resolver_result: ResolverResult,
    dns_results: list[DnsQueryResult],
    diagnosis: Diagnosis,
    loop_duration_ms: float,
    snapshot_time: datetime | None = None,
    *,
    important_results: dict[str, PingResult] | None = None,
    important_hosts_skipped: bool = False,
) -> None:
    """Atomically write the latest non-persistent dashboard snapshot."""
    internet_targets: list[dict[str, object]] = []
    for role, host in configured_internet_targets(settings):
        target_snapshot = _ping_snapshot(ping_results[host], settings)
        target_snapshot["role"] = role
        internet_targets.append(target_snapshot)

    gateway_snapshots: list[dict[str, object]] = []
    for position, host in (
        (1, settings.gateway_1_ip),
        (2, settings.gateway_2_ip),
    ):
        if host:
            gateway_snapshot = _ping_snapshot(ping_results[host], settings)
            gateway_snapshot["configured"] = True
        else:
            gateway_snapshot = {
                "state": "unknown",
                "host": "",
                "minimum_latency_ms": None,
                "average_latency_ms": None,
                "maximum_latency_ms": None,
                "loss_percent": None,
                "transmitted": None,
                "received": None,
                "configured": False,
            }
        gateway_snapshot["position"] = position
        gateway_snapshots.append(gateway_snapshot)

    important_snapshots: list[dict[str, object]] = []
    for host in settings.important_hosts:
        result = (important_results or {}).get(host)
        if result is None:
            important_snapshot: dict[str, object] = {
                "state": "unknown",
                "host": host,
                "minimum_latency_ms": None,
                "average_latency_ms": None,
                "maximum_latency_ms": None,
                "loss_percent": None,
                "transmitted": None,
                "received": None,
                "skipped": important_hosts_skipped,
            }
        else:
            important_snapshot = _ping_snapshot(result, settings)
            important_snapshot["skipped"] = False
        important_snapshots.append(important_snapshot)

    data = {
        "timestamp": (snapshot_time or utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "interval_seconds": settings.interval,
        "loop_duration_ms": round(loop_duration_ms, 2),
        "diagnosis": {
            "state": diagnosis.state,
            "title": diagnosis.title,
            "detail": diagnosis.detail,
        },
        "gateways": gateway_snapshots,
        "internet": {
            "state": internet_state,
            "host": ping_result.host,
            "minimum_latency_ms": ping_result.min_latency_ms,
            "average_latency_ms": ping_result.avg_latency_ms,
            "maximum_latency_ms": ping_result.max_latency_ms,
            "loss_percent": ping_result.loss_percent,
            "transmitted": ping_result.transmitted,
            "received": ping_result.received,
            "used_backup": ping_result.used_backup,
            "targets": internet_targets,
        },
        "dns": {
            "state": dns_state,
            "hostname": settings.dns_host,
            "record_type": settings.dns_record_type,
            "slow_threshold_ms": settings.dns_slow_threshold_ms,
            "resolver": {
                "state": resolver_result.state,
                "response_time_ms": resolver_result.response_time_ms,
            },
            "servers": [
                {
                    "server": result.server,
                    "state": result.state,
                    "response_time_ms": result.response_time_ms,
                    "response_status": result.response_status,
                    "answer_count": result.answer_count,
                }
                for result in dns_results
            ],
        },
        "important_hosts": {
            "state": determine_important_hosts_state(
                settings,
                important_results or {},
                important_hosts_skipped,
            ),
            "skipped": important_hosts_skipped,
            "skip_reason": (
                "System DNS and at least one configured DNS server must be available."
                if important_hosts_skipped
                else ""
            ),
            "hosts": important_snapshots,
        },
    }

    status_directory = os.path.dirname(settings.status_path) or "/"
    temporary_path = f"{settings.status_path}.tmp.{os.getpid()}"
    try:
        os.makedirs(status_directory, mode=0o700, exist_ok=True)
        with open(temporary_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, separators=(",", ":"))
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, settings.status_path)
    except OSError as exc:
        LOGGER.error("Unable to write ephemeral status snapshot: %s", exc)
        try:
            os.unlink(temporary_path)
        except OSError:
            pass


@dataclass(frozen=True)
class QueuedNotification:
    """A Pushover message retained in memory for a later retry."""

    title: str
    message: str
    queued_at: datetime
    attempt_count: int = 0
    next_attempt_at: Optional[datetime] = None


class PushoverNotifier:
    """Send rate-limited Pushover messages with a process-local retry queue."""

    API_URL = "https://api.pushover.net/1/messages.json"

    def __init__(
        self,
        settings: PushoverSettings,
        max_alerts_per_hour: int,
    ) -> None:
        self.token = settings.token.strip()
        self.user = settings.user.strip()
        self.device = settings.device.strip()
        self.priority = settings.priority
        self.timeout_seconds = settings.timeout_seconds
        self.retry_initial_seconds = settings.retry_initial_seconds
        self.retry_max_seconds = settings.retry_max_seconds
        self.max_alerts_per_hour = max_alerts_per_hour
        self.queue: list[QueuedNotification] = []
        self.alert_history: list[datetime] = []
        self.enabled = bool(self.token and self.user)
        self._delivery_executor = (
            ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix="internet-monitor-pushover",
            )
            if self.enabled
            else None
        )
        self._delivery_future: Future[bool] | None = None
        self._delivery_notification: QueuedNotification | None = None

        if not self.enabled:
            LOGGER.info("Pushover is disabled because no complete credentials are configured.")

    def _prune_history(self) -> None:
        """Remove successful deliveries outside the one-hour rate window."""
        cutoff = utcnow() - timedelta(hours=1)
        self.alert_history = [timestamp for timestamp in self.alert_history if timestamp > cutoff]

    def _is_rate_limited(self) -> bool:
        """Return whether the configured hourly limit has been reached."""
        if self.max_alerts_per_hour <= 0:
            return False
        self._prune_history()
        return len(self.alert_history) >= self.max_alerts_per_hour

    def _rate_limit_release_time(self) -> datetime:
        """Return the earliest time another notification may be delivered."""
        self._prune_history()
        if not self.alert_history:
            return utcnow()
        return min(self.alert_history) + timedelta(hours=1)

    def _retry_delay(self, attempt_count: int) -> int:
        """Return a bounded exponential retry delay for a failed delivery."""
        exponent = min(max(0, attempt_count - 1), 20)
        return min(
            self.retry_initial_seconds * (2**exponent),
            self.retry_max_seconds,
        )

    def _queue_notification(
        self,
        title: str,
        message: str,
        *,
        attempt_count: int = 0,
        next_attempt_at: Optional[datetime] = None,
    ) -> None:
        """Append a notification to the process-local ordered retry queue."""
        self.queue.append(
            QueuedNotification(
                title=title,
                message=message,
                queued_at=utcnow(),
                attempt_count=attempt_count,
                next_attempt_at=next_attempt_at,
            )
        )
        LOGGER.debug(
            "Enqueued Pushover notification %r in memory (queue_size=%s).",
            title,
            len(self.queue),
        )

    def _send_http(self, title: str, message: str) -> bool:
        """Send one message without logging credentials or response bodies."""
        payload = {
            "token": self.token,
            "user": self.user,
            "message": message,
            "title": title,
            "priority": str(self.priority),
            "timestamp": str(int(time.time())),
        }
        if self.device:
            payload["device"] = self.device

        try:
            response = requests.post(
                self.API_URL,
                data=payload,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            LOGGER.warning("Pushover request failed for %r: %s", title, exc)
            return False

        if response.status_code != 200:
            LOGGER.warning(
                "Pushover returned HTTP %s for %r.", response.status_code, title
            )
            return False

        try:
            response_data = response.json()
        except ValueError:
            LOGGER.warning("Pushover returned invalid JSON for %r.", title)
            return False

        if response_data.get("status") != 1:
            LOGGER.warning("Pushover rejected notification %r.", title)
            return False

        LOGGER.debug("Pushover notification sent: %s", title)
        return True

    def notify(self, title: str, message: str) -> None:
        """Queue a notification for non-blocking ordered delivery."""
        if not self.enabled:
            LOGGER.info("Pushover disabled; notification %r was not sent.", title)
            return
        next_attempt_at: datetime | None = None
        if self._is_rate_limited():
            LOGGER.warning(
                "Alert rate limit reached (%s/hour); queueing %r.",
                self.max_alerts_per_hour,
                title,
            )
            next_attempt_at = self._rate_limit_release_time()
        self._queue_notification(
            title,
            message,
            next_attempt_at=next_attempt_at,
        )
        self.flush_queue()

    def flush_queue(self) -> None:
        """Advance one non-blocking ordered delivery without delaying probes."""
        if not self.enabled or self._delivery_executor is None:
            return

        if self._delivery_future is not None:
            if not self._delivery_future.done():
                return
            notification = self._delivery_notification
            try:
                delivered = self._delivery_future.result()
            except Exception:
                LOGGER.exception("Unexpected Pushover delivery worker failure.")
                delivered = False
            self._delivery_future = None
            self._delivery_notification = None
            if notification is None or not self.queue:
                return
            if delivered:
                if self.max_alerts_per_hour > 0:
                    self.alert_history.append(utcnow())
                age = int((utcnow() - notification.queued_at).total_seconds())
                LOGGER.info(
                    "Sent queued notification %r after %s.",
                    notification.title,
                    format_duration(age),
                )
                self.queue.pop(0)
                return
            attempt_count = notification.attempt_count + 1
            delay_seconds = self._retry_delay(attempt_count)
            self.queue[0] = replace(
                notification,
                attempt_count=attempt_count,
                next_attempt_at=utcnow() + timedelta(seconds=delay_seconds),
            )
            LOGGER.warning(
                "Pushover retry for %r failed; next attempt in %s.",
                notification.title,
                format_duration(delay_seconds),
            )
            return

        if not self.queue:
            return
        notification = self.queue[0]
        now = utcnow()
        if (
            notification.next_attempt_at is not None
            and now < notification.next_attempt_at
        ):
            return
        if self._is_rate_limited():
            self.queue[0] = replace(
                notification,
                next_attempt_at=self._rate_limit_release_time(),
            )
            return

        self._delivery_notification = notification
        self._delivery_future = self._delivery_executor.submit(
            self._send_http,
            notification.title,
            notification.message,
        )


def _format_mebibytes(byte_count: int | None) -> str:
    """Format a storage byte count without unnecessary precision."""
    if byte_count is None:
        return "an unknown amount of space"
    return f"{byte_count / (1024 * 1024):.2f} MiB"


def update_storage_alert(
    previous_state: str | None,
    status: StorageStatus,
    notifier: PushoverNotifier,
) -> str:
    """Notify once for tmpfs warning, critical, unknown, and recovery changes."""
    if status.state == previous_state:
        return status.state

    if status.state == "warning":
        message = (
            f"Ephemeral monitoring storage is {status.used_percent:.2f}% used; "
            f"{_format_mebibytes(status.available_bytes)} remains. Status and "
            "history writes may fail if usage continues to increase."
        )
        notifier.notify("Temporary Storage Warning", message)
        LOGGER.warning(message)
    elif status.state == "down":
        message = (
            f"Ephemeral monitoring storage is critically full at "
            f"{status.used_percent:.2f}% used; "
            f"{_format_mebibytes(status.available_bytes)} remains."
        )
        notifier.notify("Temporary Storage Critical", message)
        LOGGER.error(message)
    elif status.state == "unknown":
        message = "Unable to measure ephemeral monitoring storage capacity."
        notifier.notify("Temporary Storage Check Failed", message)
        LOGGER.error(message)
    elif previous_state in {"warning", "down", "unknown"}:
        message = (
            f"Ephemeral monitoring storage recovered to "
            f"{status.used_percent:.2f}% used with "
            f"{_format_mebibytes(status.available_bytes)} available."
        )
        notifier.notify("Temporary Storage Recovered", message)
        LOGGER.info(message)

    return status.state


@dataclass
class IssueTracker:
    """Track consecutive observations and one active alert for a condition."""

    count: int = 0
    started_at: Optional[datetime] = None
    alert_sent: bool = False
    issue_kind: str = ""

    def reset(self) -> None:
        """Return the tracker to its healthy state."""
        self.count = 0
        self.started_at = None
        self.alert_sent = False
        self.issue_kind = ""


def update_resolver_tracker(
    tracker: IssueTracker,
    result: ResolverResult,
    settings: MonitorSettings,
    notifier: PushoverNotifier,
) -> None:
    """Update system-resolver alert state while preserving existing semantics."""
    if result.state == "up":
        if tracker.alert_sent and tracker.started_at is not None:
            duration = int((utcnow() - tracker.started_at).total_seconds())
            message = (
                f"System DNS resolution for {settings.dns_host} recovered after "
                f"{format_duration(duration)}."
            )
            notifier.notify("DNS Resolver Recovered", message)
            LOGGER.info(message)
        tracker.reset()
        LOGGER.debug(
            "System resolver answered for %s in %.2f ms.",
            settings.dns_host,
            result.response_time_ms or 0.0,
        )
        return

    tracker.count += 1
    tracker.issue_kind = "failure"
    if tracker.started_at is None:
        tracker.started_at = utcnow()
    log_probe_issue(
        tracker.count,
        "System resolver failed for %s (%s/%s).",
        settings.dns_host,
        tracker.count,
        settings.dns_failure_trigger,
    )

    if tracker.count >= settings.dns_failure_trigger and not tracker.alert_sent:
        message = (
            f"System DNS resolution for {settings.dns_host} failed for "
            f"{settings.dns_failure_trigger} consecutive checks."
        )
        notifier.notify("DNS Resolver Failure", message)
        LOGGER.warning(message)
        tracker.alert_sent = True


def update_dns_server_tracker(
    tracker: IssueTracker,
    result: DnsQueryResult,
    settings: MonitorSettings,
    notifier: PushoverNotifier,
) -> None:
    """Update the independent alert state for one configured DNS server."""
    if result.state == "up":
        LOGGER.debug(
            "DNS server %s answered %s %s in %.2f ms.",
            result.server,
            settings.dns_host,
            settings.dns_record_type,
            result.response_time_ms or 0.0,
        )
        if tracker.alert_sent and tracker.started_at is not None:
            duration = int((utcnow() - tracker.started_at).total_seconds())
            message = (
                f"DNS server {result.server} recovered and answered "
                f"{settings.dns_host} in {result.response_time_ms:.2f} ms after "
                f"{format_duration(duration)}."
            )
            notifier.notify(f"DNS Server Recovered: {result.server}", message)
            LOGGER.info(message)
        tracker.reset()
        return

    tracker.count += 1
    if tracker.started_at is None:
        tracker.started_at = utcnow()
    tracker.issue_kind = "slow" if result.state == "warning" else "failure"

    if result.state == "warning":
        log_probe_issue(
            tracker.count,
            "DNS server %s was slow: %.2f ms exceeds %.2f ms (%s/%s).",
            result.server,
            result.response_time_ms or 0.0,
            settings.dns_slow_threshold_ms,
            tracker.count,
            settings.dns_failure_trigger,
        )
    else:
        log_probe_issue(
            tracker.count,
            "DNS server %s failed for %s (%s/%s): %s.",
            result.server,
            settings.dns_host,
            tracker.count,
            settings.dns_failure_trigger,
            result.error or "unknown error",
        )

    if tracker.count < settings.dns_failure_trigger or tracker.alert_sent:
        return

    if tracker.issue_kind == "slow":
        title = f"Slow DNS Server: {result.server}"
        message = (
            f"DNS server {result.server} exceeded the "
            f"{settings.dns_slow_threshold_ms:.2f} ms threshold for "
            f"{settings.dns_failure_trigger} consecutive checks. Latest response: "
            f"{result.response_time_ms:.2f} ms for {settings.dns_host}."
        )
    else:
        title = f"DNS Server Failure: {result.server}"
        message = (
            f"DNS server {result.server} failed to answer {settings.dns_host} for "
            f"{settings.dns_failure_trigger} consecutive checks."
        )
    notifier.notify(title, message)
    LOGGER.warning(message)
    tracker.alert_sent = True


def _gateway_issue_kind(result: PingResult, settings: MonitorSettings) -> str:
    """Describe the most important unhealthy characteristic of a gateway."""
    if not result.success:
        return "unreachable"
    if (result.loss_percent or 0) > 0:
        return "packet_loss"
    if (
        result.avg_latency_ms is not None
        and result.avg_latency_ms > settings.high_latency_ms
    ):
        return "high_latency"
    return ""


def update_gateway_tracker(
    tracker: IssueTracker,
    label: str,
    result: PingResult,
    settings: MonitorSettings,
    notifier: PushoverNotifier,
) -> None:
    """Update one gateway's independent outage, degradation, and recovery alert."""
    issue_kind = _gateway_issue_kind(result, settings)
    if not issue_kind:
        if tracker.alert_sent and tracker.started_at is not None:
            duration = int((utcnow() - tracker.started_at).total_seconds())
            message = (
                f"{label} ({result.host}) recovered after "
                f"{format_duration(duration)}."
            )
            notifier.notify(f"{label} Recovered", message)
            LOGGER.info(message)
        tracker.reset()
        return

    if tracker.issue_kind and tracker.issue_kind != issue_kind:
        LOGGER.info(
            "%s condition changed from %s to %s; starting a new alert window.",
            label,
            tracker.issue_kind,
            issue_kind,
        )
        tracker.reset()

    tracker.issue_kind = issue_kind
    tracker.count += 1
    tracker.started_at = tracker.started_at or utcnow()
    duration_seconds = (utcnow() - tracker.started_at).total_seconds()

    if issue_kind == "unreachable":
        delay_seconds = settings.outage_alert_delay_seconds
        title = f"{label} Unreachable"
        message = (
            f"{label} ({result.host}) has been unreachable for "
            f"{format_duration(int(duration_seconds))}."
        )
    elif issue_kind == "packet_loss":
        delay_seconds = settings.loss_alert_delay_seconds
        title = f"{label} Packet Loss"
        message = (
            f"{label} ({result.host}) has {result.loss_percent}% packet loss, "
            f"persisting for {format_duration(int(duration_seconds))}."
        )
    else:
        delay_seconds = settings.latency_alert_delay_seconds
        title = f"{label} High Latency"
        message = (
            f"{label} ({result.host}) average latency is "
            f"{result.avg_latency_ms:.2f} ms, persisting for "
            f"{format_duration(int(duration_seconds))}."
        )

    log_probe_issue(
        tracker.count,
        "%s is %s (%s/%s), duration=%.1fs.",
        label,
        issue_kind.replace("_", " "),
        tracker.count,
        settings.trigger,
        duration_seconds,
    )
    if (
        tracker.count >= settings.trigger
        and duration_seconds >= delay_seconds
        and not tracker.alert_sent
    ):
        notifier.notify(title, message)
        LOGGER.warning(message)
        tracker.alert_sent = True


def run_monitor(settings: Settings) -> None:
    """Run the monitor loop until interrupted or a required executable is missing."""
    monitor = settings.monitor
    notifier = PushoverNotifier(settings.pushover, monitor.max_alerts_per_hour)
    history_store = HistoryStore(
        monitor.history_path,
        build_history_series(monitor),
        started_at=utcnow(),
    )

    ping_fail_count = 0
    outage_start: Optional[datetime] = None
    outage_alert_sent = False

    loss_iter_count = 0
    loss_start: Optional[datetime] = None
    loss_alert_sent = False

    latency_iter_count = 0
    latency_start: Optional[datetime] = None
    latency_alert_sent = False

    resolver_tracker = IssueTracker()
    dns_server_trackers = {
        server: IssueTracker() for server in monitor.dns_servers
    }
    gateway_trackers = {
        position: IssueTracker()
        for position, host in (
            (1, monitor.gateway_1_ip),
            (2, monitor.gateway_2_ip),
        )
        if host
    }
    important_host_trackers = {
        host: IssueTracker() for host in monitor.important_hosts
    }
    storage_alert_state: str | None = None

    LOGGER.info(
        "Starting Internet Monitor: interval=%ss ping_hosts=%s gateways=%s "
        "dns_host=%s dns_servers=%s important_hosts=%s "
        "slow_dns_threshold_ms=%.2f",
        monitor.interval,
        ",".join(
            host
            for host in (monitor.ping_host, monitor.backup_ping_host)
            if host
        ),
        ",".join(
            host for host in (monitor.gateway_1_ip, monitor.gateway_2_ip) if host
        )
        or "not configured",
        monitor.dns_host,
        ",".join(monitor.dns_servers),
        ",".join(monitor.important_hosts) or "not configured",
        monitor.dns_slow_threshold_ms,
    )

    probe_executor = ThreadPoolExecutor(
        max_workers=probe_worker_count(monitor),
        thread_name_prefix="internet-monitor-probe",
    )
    while True:
        loop_started = time.monotonic()
        probe_cycle = run_probe_cycle(monitor, probe_executor)
        if any(
            result.error == "fping is not installed"
            for result in probe_cycle.ping_results.values()
        ):
            raise RuntimeError("fping is required but is not installed")
        if any(
            result.error == "dig is not installed"
            for result in probe_cycle.dns_results
        ):
            raise RuntimeError("dig is required but is not installed")

        ping_results = probe_cycle.ping_results
        ping_result = select_internet_result(monitor, ping_results)
        resolver_result = probe_cycle.resolver_result
        dns_results = probe_cycle.dns_results
        important_results = probe_cycle.important_results

        connectivity_up = ping_result.success
        if connectivity_up:
            if ping_fail_count >= monitor.trigger and outage_start and outage_alert_sent:
                downtime = int((utcnow() - outage_start).total_seconds())
                message = (
                    "Internet connectivity recovered. The outage lasted "
                    f"{format_duration(downtime)} and began at "
                    f"{format_local(outage_start, monitor.timezone)}."
                )
                notifier.notify("Internet Outage Resolved", message)
                LOGGER.info(message)
            ping_fail_count = 0
            outage_start = None
            outage_alert_sent = False
        else:
            ping_fail_count += 1
            outage_start = outage_start or utcnow()
            outage_duration = (utcnow() - outage_start).total_seconds()
            log_probe_issue(
                ping_fail_count,
                "Ping check failed for %s (%s/%s), duration=%.1fs.",
                ping_result.host or monitor.ping_host,
                ping_fail_count,
                monitor.trigger,
                outage_duration,
            )
            if (
                ping_fail_count >= monitor.trigger
                and outage_duration >= monitor.outage_alert_delay_seconds
                and not outage_alert_sent
            ):
                message = (
                    "Internet outage has persisted for at least "
                    f"{format_duration(int(outage_duration))}."
                )
                notifier.notify("Internet Outage Detected", message)
                LOGGER.warning(message)
                outage_alert_sent = True

        if connectivity_up:
            loss = ping_result.loss_percent or 0
            latency = ping_result.avg_latency_ms
            ping_host = ping_result.host or monitor.ping_host

            if loss > 0:
                loss_iter_count += 1
                loss_start = loss_start or utcnow()
                loss_duration = (utcnow() - loss_start).total_seconds()
                log_probe_issue(
                    loss_iter_count,
                    "Packet loss is %s%% to %s (count=%s duration=%.1fs).",
                    loss,
                    ping_host,
                    loss_iter_count,
                    loss_duration,
                )
                if (
                    loss_iter_count >= monitor.trigger
                    and loss_duration >= monitor.loss_alert_delay_seconds
                    and not loss_alert_sent
                ):
                    message = (
                        f"Packet loss of {loss}% to {ping_host} persisted for "
                        f"{format_duration(int(loss_duration))}."
                    )
                    notifier.notify("Internet Packet Loss Detected", message)
                    LOGGER.warning(message)
                    loss_alert_sent = True
            else:
                if loss_alert_sent and loss_start:
                    duration = int((utcnow() - loss_start).total_seconds())
                    message = (
                        f"Packet loss to {ping_host} recovered after "
                        f"{format_duration(duration)}."
                    )
                    notifier.notify("Internet Packet Loss Resolved", message)
                    LOGGER.info(message)
                loss_iter_count = 0
                loss_start = None
                loss_alert_sent = False

            if latency is not None and latency > monitor.high_latency_ms:
                latency_iter_count += 1
                latency_start = latency_start or utcnow()
                latency_duration = (utcnow() - latency_start).total_seconds()
                log_probe_issue(
                    latency_iter_count,
                    "High latency is %.2f ms to %s (count=%s duration=%.1fs).",
                    latency,
                    ping_host,
                    latency_iter_count,
                    latency_duration,
                )
                if (
                    latency_iter_count >= monitor.trigger
                    and latency_duration >= monitor.latency_alert_delay_seconds
                    and not latency_alert_sent
                ):
                    message = (
                        f"Average latency to {ping_host} remained at {latency:.2f} ms "
                        f"for {format_duration(int(latency_duration))}."
                    )
                    notifier.notify("High Internet Latency Detected", message)
                    LOGGER.warning(message)
                    latency_alert_sent = True
            else:
                if latency_alert_sent and latency_start:
                    duration = int((utcnow() - latency_start).total_seconds())
                    message = (
                        f"Latency to {ping_host} recovered below "
                        f"{monitor.high_latency_ms:.2f} ms after "
                        f"{format_duration(duration)}."
                    )
                    notifier.notify("Internet Latency Recovered", message)
                    LOGGER.info(message)
                latency_iter_count = 0
                latency_start = None
                latency_alert_sent = False

        internet_state = determine_ping_state(ping_result, monitor)

        for position, gateway_host in (
            (1, monitor.gateway_1_ip),
            (2, monitor.gateway_2_ip),
        ):
            if not gateway_host:
                continue
            update_gateway_tracker(
                gateway_trackers[position],
                f"Gateway {position}",
                ping_results[gateway_host],
                monitor,
                notifier,
            )

        update_resolver_tracker(
            resolver_tracker, resolver_result, monitor, notifier
        )
        for result in dns_results:
            update_dns_server_tracker(
                dns_server_trackers[result.server],
                result,
                monitor,
                notifier,
            )
        if not probe_cycle.important_hosts_skipped:
            for host, result in important_results.items():
                update_gateway_tracker(
                    important_host_trackers[host],
                    f"Important host {host}",
                    result,
                    monitor,
                    notifier,
                )
        dns_state = determine_dns_state(resolver_result, dns_results)
        diagnosis = determine_connection_diagnosis(
            monitor,
            ping_results,
            internet_state,
            dns_state,
        )
        storage_status = read_storage_status(monitor.history_path)
        storage_alert_state = update_storage_alert(
            storage_alert_state,
            storage_status,
            notifier,
        )
        notifier.flush_queue()

        elapsed = time.monotonic() - loop_started
        snapshot_time = utcnow()

        history_store.record(
            snapshot_time,
            build_history_values(
                monitor,
                ping_result,
                ping_results,
                resolver_result,
                dns_results,
                important_results,
            ),
            publish_snapshot=storage_status.state != "down",
        )

        if storage_status.available_bytes != 0:
            write_status(
                monitor,
                internet_state,
                ping_result,
                ping_results,
                dns_state,
                resolver_result,
                dns_results,
                diagnosis,
                elapsed * 1000,
                snapshot_time,
                important_results=important_results,
                important_hosts_skipped=probe_cycle.important_hosts_skipped,
            )
        else:
            LOGGER.debug(
                "Skipping status snapshot because no temporary storage is available."
            )

        elapsed = time.monotonic() - loop_started
        sleep_seconds = max(0.0, monitor.interval - elapsed)
        LOGGER.debug(
            "Monitor loop completed in %.2fs; sleeping %.2fs.", elapsed, sleep_seconds
        )
        time.sleep(sleep_seconds)


def main() -> None:
    """Load Docker configuration, configure logging, and start monitoring."""
    settings = load_settings()
    configure_logging(settings.monitor.log_level)
    run_monitor(settings)


if __name__ == "__main__":
    configure_logging("INFO")
    try:
        main()
    except KeyboardInterrupt:
        LOGGER.info("Internet Monitor stopped by user.")
        sys.exit(0)
    except ConfigurationError as exc:
        LOGGER.critical("Configuration error: %s", exc)
        sys.exit(1)
    except Exception:
        LOGGER.exception("Internet Monitor stopped after an unrecoverable error.")
        sys.exit(1)
