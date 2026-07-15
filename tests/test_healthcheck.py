"""Tests for the lightweight container health check."""

from __future__ import annotations

import http.server
import threading

import pytest

from internet_monitor import healthcheck


class _HealthHandler(http.server.BaseHTTPRequestHandler):
    """Return a successful response only for the health endpoint."""

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self.send_response(200 if self.path == "/health" else 404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        """Keep the test server quiet."""


def test_web_port_uses_default_and_validates_environment(monkeypatch: pytest.MonkeyPatch):
    """The health check accepts only a valid TCP port."""
    monkeypatch.delenv("WEB_PORT", raising=False)
    assert healthcheck._web_port() == 5005

    monkeypatch.setenv("WEB_PORT", "65536")
    with pytest.raises(ValueError, match="between 1 and 65535"):
        healthcheck._web_port()


def test_main_checks_the_local_health_endpoint(monkeypatch: pytest.MonkeyPatch):
    """A local HTTP 200 makes the command exit successfully."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("WEB_PORT", str(server.server_port))

    try:
        with pytest.raises(SystemExit) as exit_info:
            healthcheck.main()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert exit_info.value.code == 0
