"""Lightweight Docker healthcheck for the Internet Monitor web UI."""

from __future__ import annotations

import http.client
import sys


INTERNAL_WEB_PORT = 5005
HEALTHCHECK_TIMEOUT_SECONDS = 3


def main() -> None:
    """Exit 0 when the local Flask health endpoint returns HTTP 200."""
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        INTERNAL_WEB_PORT,
        timeout=HEALTHCHECK_TIMEOUT_SECONDS,
    )
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        status_code = response.status
        response.close()
    except (OSError, http.client.HTTPException) as exc:
        print(
            f"Healthcheck failed for local port {INTERNAL_WEB_PORT}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    finally:
        connection.close()

    if status_code != 200:
        print(
            "Healthcheck bad status "
            f"{status_code} from local port {INTERNAL_WEB_PORT}",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
