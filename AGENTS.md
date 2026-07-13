# Agent Instructions

## Project Shape

Internet Monitor is a Docker-first Python service. Application code lives in
`internet_monitor/`:

- `settings.py` validates all operator-controlled environment variables and
  Docker secret-file inputs.
- `monitor.py` runs the concurrent fping, gateway, system resolver, and
  per-server dig cycle, alert tracking, Pushover retry queue, console logging,
  path diagnosis, and ephemeral status updates.
- `web.py` exposes the Flask status dashboard, sanitized live status endpoint,
  and health endpoint.
- `healthcheck.py` is the Docker health-check entry point.
- `internet_monitor/templates/` contains Flask templates.
- `internet_monitor/static/` contains the CSP-compatible dashboard CSS and
  JavaScript.

The app has no configuration file and no persistent data store. Keep every
operator-tunable setting in Docker environment variables and update
`.env.example`, `docker-compose.yml`, and `docker-stack.yml` together whenever
the environment contract changes.

## Runtime State And Logging

Application logs must go only to stdout or stderr for Docker collection. Do not
add application log files or a web log viewer.

The web and monitor processes share only the latest status snapshot at
`/tmp/internet-monitor/status.json`. Compose and Swarm mount `/tmp` as tmpfs;
it is not history or durable storage. Alert counters and the ordered Pushover
retry queue are process-local and reset on restart. Browser-session charts are
also ephemeral and reset when the page reloads.

Internet Monitor currently requires no long-term storage. Stop and ask the user
before adding PostgreSQL or any other persistent store.

## DNS Monitoring

Preserve both DNS layers:

1. The system resolver checks `INTERNET_MONITOR_DNS_HOST`.
2. `dig` queries that host against every IP in
   `INTERNET_MONITOR_DNS_SERVERS` and records the latest response time.

Each explicit DNS server has an independent failure/slow-response alert and
recovery lifecycle. Keep the slow threshold environment-controlled and never
construct a shell command from DNS settings.

DNS health is intentionally measured from the monitor task's network namespace.
If a query succeeds on the Swarm node but `dig` exits with code 9 in the task,
treat it as a container network, firewall, or resolver access-control problem;
do not hide a consistently unreachable path by adding query retries.

For a UFW-protected Swarm node using an Unbound service published in host mode,
keep DNS rules limited to the monitor overlay source subnet, the secondary host
IP or Unbound overlay destination, port 53, and both UDP and TCP. Do not recommend
an unrestricted DNS rule or imply that port 53 must be opened between Swarm
nodes when traffic remains inside a shared overlay.

## Gateway And Internet Monitoring

`INTERNET_MONITOR_GATEWAY_1_IP` and `INTERNET_MONITOR_GATEWAY_2_IP` are optional
validated IP addresses. When present, they are ordered from the monitoring
server toward the Internet. Probe both gateways and both Internet targets every
cycle so dashboard values remain comparable.

Preserve the diagnosis order: Gateway 1 failure means a local network issue;
Gateway 2 failure while Gateway 1 responds means an upstream gateway issue; an
Internet failure while configured gateways respond means an ISP or Internet
issue; healthy Internet with unhealthy DNS means a DNS issue. Each configured
gateway has its own degradation, outage, and recovery alert lifecycle using the
existing trigger and delay settings.

Pushover failures and rate-limited messages must remain queued in order and
retry with the configured capped exponential backoff until delivered. Do not
persist the queue without asking the user first.

## Development Workflow

Before code changes, read this file and the documentation touched by the change.
Keep work focused and preserve existing alert-delay semantics unless explicitly
asked to change them.

Run targeted validation before finishing:

```bash
python -m pytest
python -m compileall internet_monitor tests
docker compose config
docker stack config --compose-file docker-stack.yml
docker stack config --compose-file docker-stack.yml --compose-file docker-stack.secrets.yml
```

## Docker, Swarm, And Releases

`docker-compose.yml` is the local build and Portainer Compose contract.
`docker-stack.yml` is the dedicated Swarm contract and must remain build-free,
single-replica, ingress-published, and registry-image based. Stop-first updates
prevent duplicate monitoring and notifications.

The container runs as UID/GID 10001, has a read-only root filesystem, drops all
default capabilities, and adds back only `NET_RAW` for fping. Do not add broader
privileges. Do not add `no-new-privileges` without retesting fping: the packaged
binary uses its file capability to open ICMP sockets as the unprivileged user.

Pushover token and user values may come from environment variables for Compose.
For Swarm, prefer the external-secret overlay in `docker-stack.secrets.yml`.
Never put secret values in code, examples, tests, logs, images, or documentation.

`.github/workflows/publish-release-image.yml` publishes the multi-architecture
GHCR image only when a GitHub Release is published. It must build the Python
wheel and source distribution before publishing the image. A version change
must keep `internet_monitor/__init__.py`, `pyproject.toml`, Docker image defaults,
and the changelog aligned. Do not create a tag or release unless explicitly
requested.

## Web And Security

The approved visual contract is the Operational Dark palette in
[`docs/color-palette.svg`](docs/color-palette.svg). Keep dashboard changes
consistent with those colors and maintain uniform spacing.

The dashboard must provide a complete server-rendered initial view and may poll
only the same-origin `/api/status` endpoint for live updates. Keep browser charts
session-local, render packet-loss intervals in the approved failure red, and do
not turn total loss into a zero-latency sample. Avoid third-party scripts and
preserve a restrictive Content Security Policy without inline JavaScript.

Treat dashboard data as sensitive operational information. The direct-address
allow-list intentionally ignores `X-Forwarded-For`. If nginx or another reverse
proxy is added, document and test the trusted proxy boundary before honoring
forwarded client addresses.

## Documentation

For meaningful changes, update:

- `README.md` for concise user-facing capabilities and configuration.
- `INSTALL.md` for Compose, Portainer, Swarm, secret, or upgrade procedures.
- `CHANGELOG.md` for every notable change or version update.
- This file when architecture, workflow, security, deployment, or agent guidance
  changes.

Create focused skill files only when a specialized procedure becomes too large
or detailed for this index; do not duplicate large instruction blocks.
