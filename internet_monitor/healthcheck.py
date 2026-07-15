"""Lightweight Docker healthcheck for the Internet Monitor web UI."""

from __future__ import annotations

import http.client
import os
import sys


DEFAULT_WEB_PORT = 5005
HEALTHCHECK_TIMEOUT_SECONDS = 3


def _web_port() -> int:
    """Read only the bounded port needed by this short-lived process."""
    raw_port = os.environ.get(
        "WEB_PORT",
        str(DEFAULT_WEB_PORT),
    ).strip()
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ValueError("WEB_PORT must be an integer.") from exc
    if not 1 <= port <= 65535:
        raise ValueError(
            "WEB_PORT must be between 1 and 65535."
        )
    return port


def main() -> None:
    """Exit 0 when the local Flask health endpoint returns HTTP 200."""
    try:
        port = _web_port()
    except ValueError as exc:
        print(f"Healthcheck configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    connection = http.client.HTTPConnection(
        "127.0.0.1",
        port,
        timeout=HEALTHCHECK_TIMEOUT_SECONDS,
    )
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        status_code = response.status
        response.close()
    except (OSError, http.client.HTTPException) as exc:
        print(
            f"Healthcheck failed for local port {port}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    finally:
        connection.close()

    if status_code != 200:
        print(
            f"Healthcheck bad status {status_code} from local port {port}",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
