"""Tests that keep version and Docker deployment contracts synchronized."""

from pathlib import Path
import re
import tomllib

from internet_monitor import __version__


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ENVIRONMENT_VARIABLES = {
    "LOG_LEVEL",
    "PING_HOST",
    "BACKUP_PING_HOST",
    "GATEWAY_1_IP",
    "GATEWAY_2_IP",
    "IMPORTANT_HOST_1",
    "IMPORTANT_HOST_2",
    "IMPORTANT_HOST_3",
    "DNS_HOST",
    "DNS_SERVERS",
    "DNS_RECORD_TYPE",
    "DNS_TIMEOUT_SECONDS",
    "DNS_SLOW_THRESHOLD_MS",
    "PINGS",
    "PING_PERIOD_MS",
    "PING_TIMEOUT_MS",
    "INTERVAL",
    "TRIGGER",
    "HIGH_LATENCY_MS",
    "DNS_FAILURE_TRIGGER",
    "MAX_ALERTS_PER_HOUR",
    "LOSS_ALERT_DELAY_SECONDS",
    "LATENCY_ALERT_DELAY_SECONDS",
    "OUTAGE_ALERT_DELAY_SECONDS",
    "STATUS_PATH",
    "HISTORY_PATH",
    "HISTORY_MAX_POINTS",
    "TIMEZONE",
    "WEB_TITLE",
    "WEB_WORKERS",
    "WEB_THREADS",
    "WEB_ALLOWED_HOSTS",
    "WEB_STATUS_MAX_AGE",
    "PUSHOVER_TOKEN",
    "PUSHOVER_TOKEN_FILE",
    "PUSHOVER_USER",
    "PUSHOVER_USER_FILE",
    "PUSHOVER_DEVICE",
    "PUSHOVER_PRIORITY",
    "PUSHOVER_TIMEOUT_SECONDS",
    "PUSHOVER_RETRY_INITIAL_SECONDS",
    "PUSHOVER_RETRY_MAX_SECONDS",
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
    entrypoint = _text("entrypoint.sh")

    assert "type: tmpfs" in deployment_text
    assert "/tmp" in deployment_text
    assert "internet-monitor-data" not in deployment_text
    assert "connection.log" not in deployment_text
    assert "LOG_PATH" not in deployment_text
    assert deployment_text.count("size: 16777216") == 2
    assert "--access-logfile" not in entrypoint
    assert "HISTORY_DETAILED_HOURS" not in deployment_text
    assert "HISTORY_MINUTE_DAYS" not in deployment_text


def test_one_variable_publishes_the_fixed_internal_web_port():
    """WEB_PORT should affect ingress only while container services use 5005."""
    environment_example = _text(".env.example")
    compose = _text("docker-compose.yml")
    stack = _text("docker-stack.yml")
    internal_contract = "".join(
        (
            _text("entrypoint.sh"),
            _text("internet_monitor/settings.py"),
            _text("internet_monitor/healthcheck.py"),
        )
    )

    assert environment_example.count("WEB_PORT=") == 1
    assert '"${WEB_PORT:-5005}:5005"' in compose
    assert "target: 5005" in stack
    assert "published: ${WEB_PORT:-5005}" in stack
    assert "WEB_HOST_PORT" not in environment_example + compose + stack
    assert not re.search(r"^\s+WEB_PORT:", compose, re.MULTILINE)
    assert not re.search(r"^\s+WEB_PORT:", stack, re.MULTILINE)
    assert '"WEB_PORT"' not in internal_contract
    assert '--bind "0.0.0.0:5005"' in _text("entrypoint.sh")


def test_runtime_contract_contains_no_legacy_prefixes():
    """The v0.2.0 clean break should expose only the short variable names."""
    active_contract = "".join(
        _text(path)
        for path in (
            ".env.example",
            "docker-compose.yml",
            "docker-stack.yml",
            "docker-stack.secrets.yml",
            "entrypoint.sh",
            "internet_monitor/settings.py",
            "internet_monitor/healthcheck.py",
        )
    )

    assert "INTERNET_MONITOR_" not in active_contract


def test_version_surfaces_match_release_version():
    """Package, image defaults, metadata, and released changelog should align."""
    pyproject = tomllib.loads(_text("pyproject.toml"))

    assert __version__ == "0.2.1"
    assert _text("VERSION").strip() == __version__
    assert pyproject["project"]["version"] == __version__
    assert pyproject["project"]["readme"] == "README.md"
    assert f"ARG APP_VERSION={__version__}" in _text("Dockerfile")
    assert f"internet-monitor:{__version__}" in _text("docker-compose.yml")
    assert f"internet-monitor:{__version__}" in _text("docker-stack.yml")
    assert f"## {__version__} - 07.15.2026" in _text("CHANGELOG.md")


def test_swarm_prefers_labeled_node_without_preventing_failover():
    """Swarm should prefer the monitor node but retain unlabeled fallbacks."""
    stack = _text("docker-stack.yml")

    assert "preferences:" in stack
    assert "spread: node.labels.internet-monitor" in stack
    assert "node.labels.internet-monitor ==" not in stack
    assert "node.labels.internet-monitor==" not in stack


def test_release_workflow_is_release_only_and_publishes_ghcr_image():
    """Image publication must remain behind an explicit GitHub Release event."""
    workflow = _text(".github/workflows/publish-release-image.yml")

    assert "release:" in workflow
    assert "types: [published]" in workflow
    assert "pull_request:" not in workflow
    assert not re.search(r"^\s{2}push:", workflow, re.MULTILINE)
    assert "python -m build" in workflow
    assert "ghcr.io/cosmicc/internet-monitor" in workflow
    assert "push: true" in workflow
