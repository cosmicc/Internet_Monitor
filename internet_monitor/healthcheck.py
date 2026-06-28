"""Docker healthcheck for the Internet Monitor web UI."""

from __future__ import annotations

import sys

import requests

from .settings import ConfigurationError, load_settings


def main() -> None:
    """Exit 0 when the local Flask health endpoint returns HTTP 200."""
    try:
        port = load_settings().web.port
    except ConfigurationError as exc:
        print(f"Healthcheck configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    url = f"http://127.0.0.1:{port}/health"

    try:
        response = requests.get(url, timeout=5)
    except requests.RequestException as exc:
        print(f"Healthcheck failed for {url}: {exc}", file=sys.stderr)
        sys.exit(1)

    if response.status_code != 200:
        print(
            f"Healthcheck bad status {response.status_code} from {url}",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
