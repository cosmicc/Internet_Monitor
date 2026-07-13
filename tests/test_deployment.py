"""Tests that keep version and Docker deployment contracts synchronized."""

from pathlib import Path
import re
import tomllib

from internet_monitor import __version__


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ENVIRONMENT_VARIABLES = {
    "INTERNET_MONITOR_LOG_LEVEL",
    "INTERNET_MONITOR_PING_HOST",
    "INTERNET_MONITOR_BACKUP_PING_HOST",
    "INTERNET_MONITOR_GATEWAY_1_IP",
    "INTERNET_MONITOR_GATEWAY_2_IP",
    "INTERNET_MONITOR_DNS_HOST",
    "INTERNET_MONITOR_DNS_SERVERS",
    "INTERNET_MONITOR_DNS_RECORD_TYPE",
    "INTERNET_MONITOR_DNS_TIMEOUT_SECONDS",
    "INTERNET_MONITOR_DNS_SLOW_THRESHOLD_MS",
    "INTERNET_MONITOR_PINGS",
    "INTERNET_MONITOR_PING_PERIOD_MS",
    "INTERNET_MONITOR_PING_TIMEOUT_MS",
    "INTERNET_MONITOR_INTERVAL",
    "INTERNET_MONITOR_TRIGGER",
    "INTERNET_MONITOR_HIGH_LATENCY_MS",
    "INTERNET_MONITOR_DNS_FAILURE_TRIGGER",
    "INTERNET_MONITOR_MAX_ALERTS_PER_HOUR",
    "INTERNET_MONITOR_LOSS_ALERT_DELAY_SECONDS",
    "INTERNET_MONITOR_LATENCY_ALERT_DELAY_SECONDS",
    "INTERNET_MONITOR_OUTAGE_ALERT_DELAY_SECONDS",
    "INTERNET_MONITOR_STATUS_PATH",
    "INTERNET_MONITOR_TIMEZONE",
    "INTERNET_MONITOR_WEB_TITLE",
    "INTERNET_MONITOR_WEB_PORT",
    "INTERNET_MONITOR_WEB_WORKERS",
    "INTERNET_MONITOR_WEB_THREADS",
    "INTERNET_MONITOR_WEB_ALLOWED_HOSTS",
    "INTERNET_MONITOR_WEB_STATUS_MAX_AGE",
    "INTERNET_MONITOR_PUSHOVER_TOKEN",
    "INTERNET_MONITOR_PUSHOVER_TOKEN_FILE",
    "INTERNET_MONITOR_PUSHOVER_USER",
    "INTERNET_MONITOR_PUSHOVER_USER_FILE",
    "INTERNET_MONITOR_PUSHOVER_DEVICE",
    "INTERNET_MONITOR_PUSHOVER_PRIORITY",
    "INTERNET_MONITOR_PUSHOVER_TIMEOUT_SECONDS",
    "INTERNET_MONITOR_PUSHOVER_RETRY_INITIAL_SECONDS",
    "INTERNET_MONITOR_PUSHOVER_RETRY_MAX_SECONDS",
}


def _text(relative_path: str) -> str:
    """Read one project file as UTF-8 text."""
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def test_runtime_environment_contract_is_documented_in_both_deployments():
    """Every application setting should appear in the example, Compose, and Swarm."""
    environment_example = _text(".env.example")
    compose = _text("docker-compose.yml")
    stack = _text("docker-stack.yml")

    for variable in RUNTIME_ENVIRONMENT_VARIABLES:
        assert re.search(rf"^{variable}=", environment_example, re.MULTILINE), variable
        assert re.search(rf"^\s+{variable}:", compose, re.MULTILINE), variable
        assert re.search(rf"^\s+{variable}:", stack, re.MULTILINE), variable


def test_deployments_do_not_persist_application_state_or_logs():
    """Compose and Swarm should expose only ephemeral tmpfs runtime state."""
    deployment_text = _text("docker-compose.yml") + _text("docker-stack.yml")

    assert "type: tmpfs" in deployment_text
    assert "/tmp" in deployment_text
    assert "internet-monitor-data" not in deployment_text
    assert "connection.log" not in deployment_text
    assert "INTERNET_MONITOR_LOG_PATH" not in deployment_text


def test_version_surfaces_match_release_version():
    """Package, image defaults, metadata, and released changelog should align."""
    pyproject = tomllib.loads(_text("pyproject.toml"))

    assert __version__ == "0.1.0"
    assert pyproject["project"]["version"] == __version__
    assert f"ARG APP_VERSION={__version__}" in _text("Dockerfile")
    assert f"internet-monitor:{__version__}" in _text("docker-compose.yml")
    assert f"internet-monitor:{__version__}" in _text("docker-stack.yml")
    assert f"## {__version__} - 07.13.2026" in _text("CHANGELOG.md")


def test_release_workflow_is_release_only_and_publishes_ghcr_image():
    """Image publication must remain behind an explicit GitHub Release event."""
    workflow = _text(".github/workflows/publish-release-image.yml")

    assert "release:" in workflow
    assert "types: [published]" in workflow
    assert "pull_request:" not in workflow
    assert not re.search(r"^\s{2}push:", workflow, re.MULTILINE)
    assert "ghcr.io/cosmicc/internet-monitor" in workflow
    assert "push: true" in workflow
