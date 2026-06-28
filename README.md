# Internet Monitor

Dockerized Python monitor for internet reachability, packet loss, latency, DNS
health, a small Flask log dashboard, and optional Pushover alerts.

## Deployment

Deploy this repository as a Docker stack, such as a Portainer stack, using
`docker-compose.yml`. Open `http://<docker-host>:5005` after deployment.

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

More deployment notes are in [INSTALL.md](INSTALL.md).

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
docker compose config
```

The monitor requires `fping` and raw ICMP capability when run outside Docker.
