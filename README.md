# Internet Monitor

Dockerized Python monitor for internet reachability, packet loss, latency, DNS
health, a small Flask log dashboard, and optional Pushover alerts.

## Configuration

All runtime configuration is set with Docker environment variables. Start from
`.env.example`, then adjust hosts, intervals, alert thresholds, web settings, and
optional Pushover values in your stack environment. `config.ini` is no longer
used.

The primary ping host defaults to `1.1.1.1`; the backup ping host defaults to
`8.8.8.8`. The backup host is checked when the primary result is failed,
degraded, or high latency so a single remote host does not create false outage
or packet-loss alerts.

Runtime log and status files are stored in the Docker volume mounted at `/data`.
The Docker stack serves the dashboard with Gunicorn.

For deployment steps, see [INSTALL.md](INSTALL.md).

## Web Interface

The web interface is available on the configured web port, `5005` by default. It
shows current Internet and DNS status, auto-refreshes with the monitor interval,
displays the most recent connection log lines, and includes a clear-log action.

Use `INTERNET_MONITOR_WEB_ALLOWED_HOSTS` to restrict direct client IPs. Leave it
blank to allow all clients that can reach the published Docker port.

## Pushover Alerts

Pushover notifications are optional and disabled until both
`INTERNET_MONITOR_PUSHOVER_TOKEN` and `INTERNET_MONITOR_PUSHOVER_USER` are set in
the stack environment. Optional settings include
`INTERNET_MONITOR_PUSHOVER_DEVICE` and `INTERNET_MONITOR_PUSHOVER_PRIORITY`.

Alerts cover outages, packet loss, high latency, DNS failures, and recovery
events. Notifications that cannot be sent while connectivity is down are queued
and retried after the monitor sees the connection recover.

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
docker compose config
```

The monitor requires `fping` and raw ICMP capability when run outside Docker.
