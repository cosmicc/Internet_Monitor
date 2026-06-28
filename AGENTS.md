# Agent Instructions

## Project Shape

Internet Monitor is a Docker-first Python service. The application code lives in
`internet_monitor/`:

- `settings.py` loads all runtime configuration from environment variables.
- `monitor.py` runs the long-lived fping, DNS, status-file, log, and Pushover loop.
- `web.py` exposes the Flask dashboard and health endpoint.
- `healthcheck.py` is the Docker healthcheck entrypoint.
- `internet_monitor/templates/` contains Flask templates.

The project no longer uses `config.ini`. Keep configuration in Docker
environment variables and update `.env.example` whenever a runtime setting is
added, removed, or renamed.

## Development Workflow

Before code changes, read this file and the documentation touched by the change.
Keep changes focused and preserve the monitor's existing alert semantics unless
the request explicitly changes behavior.

Run targeted validation before finishing:

```bash
python -m pytest
docker compose config
```

## Docker And Portainer

`docker-compose.yml` must remain deployable as a Portainer stack from the Git
repository. Docker should run the web UI through Gunicorn, not the Flask
development server. Do not reintroduce bind-mounted config files. Persist
runtime files under `/data` through the `internet-monitor-data` volume unless a
requested change documents a different storage model.

Do not add install scripts for normal operation; this project is deployed as a
Docker stack.

The container needs `NET_RAW` for ICMP/fping. Avoid broader privileges.

## Security

Treat the dashboard and logs as sensitive operational data. Do not add secrets
to source files, examples, tests, logs, images, or documentation. Keep Pushover
tokens and user keys as environment variables only.

The Flask allow-list uses the direct remote address and intentionally does not
trust `X-Forwarded-For` by default. If reverse-proxy support is added later,
document the trusted proxy boundary and add tests.

## Documentation

For meaningful changes, update:

- `README.md` for user-facing setup and operation.
- `INSTALL.md` when deployment steps change.
- `CHANGELOG.md` for notable changes.
- This `AGENTS.md` when architecture, workflows, security posture, or agent
  instructions change.
