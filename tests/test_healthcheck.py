"""Tests for the lightweight container health check."""

from __future__ import annotations

import pytest

from internet_monitor import healthcheck


class _HealthResponse:
    """Represent the successful response returned by the fake connection."""

    status = 200

    def close(self) -> None:
        """Match the standard-library HTTP response interface."""


class _HealthConnection:
    """Capture the fixed internal address used by the health check."""

    calls: list[tuple[object, ...]] = []

    def __init__(self, host: str, port: int, *, timeout: int) -> None:
        self.calls.append(("connect", host, port, timeout))

    def request(self, method: str, path: str) -> None:
        """Record the requested method and path."""
        self.calls.append(("request", method, path))

    def getresponse(self) -> _HealthResponse:
        """Return a successful health response."""
        return _HealthResponse()

    def close(self) -> None:
        """Record connection cleanup."""
        self.calls.append(("close",))


def test_main_checks_the_fixed_internal_health_endpoint(
    monkeypatch: pytest.MonkeyPatch,
):
    """Published WEB_PORT values must not change the container health target."""
    _HealthConnection.calls.clear()
    monkeypatch.setenv("WEB_PORT", "65000")
    monkeypatch.setattr(
        healthcheck.http.client,
        "HTTPConnection",
        _HealthConnection,
    )

    with pytest.raises(SystemExit) as exit_info:
        healthcheck.main()

    assert exit_info.value.code == 0
    assert _HealthConnection.calls == [
        ("connect", "127.0.0.1", 5005, 3),
        ("request", "GET", "/health"),
        ("close",),
    ]
