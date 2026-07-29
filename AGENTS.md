# Agent Instructions

## Project Shape

Internet Monitor is a Docker-first Python service. Application code lives in
`internet_monitor/`:

- `settings.py` validates all operator-controlled environment variables and
  Docker secret-file inputs.
- `monitor.py` runs the concurrent fping, gateway, system resolver, and
  per-server dig cycle, DNS-gated important-host pings, alert tracking,
  Pushover retry queue, console logging, path diagnosis, and ephemeral status
  updates.
- `history.py` keeps loss-preserving detailed, minute, and hourly monitoring
  history in a compact, permission-restricted tmpfs snapshot.
- `storage.py` measures the filesystem holding runtime snapshots and applies the
  fixed temporary-storage warning and critical thresholds.
- `resources.py` reads container-scoped CPU and memory usage from Linux cgroups
  without Docker socket access, host filesystem mounts, or added privileges.
- `web.py` exposes the Flask status dashboard, sanitized live status and history
  endpoints, and health endpoint.
- `healthcheck.py` is the Docker health-check entry point.
- `internet_monitor/templates/` contains Flask templates.
- `internet_monitor/static/` contains the CSP-compatible dashboard CSS and
  JavaScript.

The app has no configuration file and no persistent data store. Keep every
operator-tunable setting in Docker environment variables and update
`.env.example`, `docker-compose.yml`, and `docker-stack.yml` together whenever
the environment contract changes.

Version 0.2.0 is a clean configuration break. Active environment variable names
must not use the retired `INTERNET_MONITOR_` prefix, and no compatibility aliases
may restore prefixed names without explicit approval and migration documentation.

## Runtime State And Logging

Application logs must go only to stdout or stderr for Docker collection. Do not
add application log files or a web log viewer. Keep routine Gunicorn access
logging disabled so dashboard polling does not generate continuous log churn;
Gunicorn errors and monitor events remain console-visible. At normal log levels,
log a probe issue when it begins and when its alert/recovery state changes; keep
repeated per-cycle details at debug level.

The web and monitor processes share current status at
`/tmp/internet-monitor/status.json` and 30-day chart history at
`/tmp/internet-monitor/history.json`. Compose and Swarm mount `/tmp` as a 16 MiB
tmpfs, so neither file is durable storage. Keep exact probe samples for 6 hours,
minute summaries for 24 hours, and hourly summaries for 30 days. Nothing older
than 30 days may remain. Downsampling and aggregation must preserve maximum loss
or DNS failure values, weighted latency averages, and minimum/maximum latency.
Collect every probe and container CPU/memory observation in memory, but publish
the complete atomic history snapshot at most once per minute instead of after
every probe. Alert counters, the ordered Pushover retry queue, status, and
history all reset on container restart or redeploy; a browser reload must not
clear published history.

Container CPU is the percentage of the CPU allocation visible through the
container's cgroup. Container memory always reports current MiB when available
and reports a percentage only when Docker provides a finite cgroup memory
limit. Do not substitute host-wide `/proc` values, mount the host filesystem, or
add Docker socket access for these dashboard metrics.

Measure the filesystem holding `HISTORY_PATH` every monitor cycle and again when
serving dashboard status. A usage level of 80% is warning and 95% is critical.
The monitor must emit one Pushover notification per warning, critical, unknown,
or recovery transition. The web process must measure storage independently so a
full tmpfs remains visible even when the monitor cannot replace its JSON files.
At critical usage, retain observations in memory but pause atomic history
publication; when no bytes remain, skip status publication too. Both must resume
without restart after storage recovers.

Internet Monitor currently requires no long-term storage. Stop and ask the user
before adding PostgreSQL or any other persistent store.

## DNS Monitoring

Preserve both DNS layers:

1. The system resolver checks `DNS_HOST` through a bounded
   `getent ahosts` subprocess so NSS resolution cannot block a monitor cycle.
2. `dig` queries that host against every IP in
   `DNS_SERVERS` and records the latest response time.

Each explicit DNS server has an independent failure/slow-response alert and
recovery lifecycle. Keep the slow threshold environment-controlled and never
construct a shell command from DNS settings.

`IMPORTANT_HOST_1`, `IMPORTANT_HOST_2`, and `IMPORTANT_HOST_3` are optional,
de-duplicated fping targets. Run them only when the system resolver is healthy
and at least one direct DNS server is healthy or slow-but-responding. A DNS-gated
skip must be visible on the dashboard, must not add a failed history sample, and
must not advance or clear an important-host alert tracker. When checks run, each
host uses the existing ping degradation, outage, and recovery alert lifecycle.

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

`GATEWAY_1_IP` and `GATEWAY_2_IP` are optional
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

`WEB_PORT` controls only the Docker host or Swarm ingress port published to
operators. Gunicorn, the Docker target port, the Flask development entry point,
and the container health check must remain fixed on internal TCP port 5005. Do
not reintroduce `WEB_HOST_PORT` or pass the published port into the container.

The static Swarm stack intentionally has no placement preference or constraint.
Docker's only native preference strategy is `spread`, which treats labeled and
unlabeled nodes as separate groups instead of prioritizing the labeled group.
Do not restore that ineffective preference or add a permanent label constraint.

Preferred placement is an opt-in manager responsibility implemented by
`deploy/swarm-placement/internet-monitor-placement-reconciler` and its systemd
timer. When at least one node with the configured label is `ready` and `active`,
the utility adds its exact hard constraint. When none is healthy, it removes
only that constraint so Swarm can use another eligible node. When a preferred
node returns, it restores the constraint and Swarm moves the task back. The
utility must remain idempotent, must preserve unrelated constraints, and must
fail without changing placement when node state cannot be read reliably.

Install the utility on exactly one stable Swarm manager that does not carry the
preferred label; it must remain available when the preferred node fails. Keep
Docker socket access out of the application container; only the hardened
manager-side oneshot may access the local Docker socket. Preserve transition-only
journal logging, the 30-second default timer, the 10-to-3600-second installer
range, and both manager-role and local-label safety checks.

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

Beginning with version 0.3, active application, Python package, Docker image, Git
tag, and GitHub Release versions use two levels (`major.minor`). Preserve older
three-level version numbers in historical changelog entries, upgrade headings,
and other historical documentation. The release workflow must tag GHCR with the
validated two-level package version and `latest` for a stable release; do not
depend on three-level semantic-version metadata expansion.

## Web And Security

The approved visual contract uses the Operational Dark palette in
[`docs/color-palette.svg`](docs/color-palette.svg) and the matching Operational
Light palette in
[`docs/color-palette-light.svg`](docs/color-palette-light.svg). Keep dashboard
changes consistent with those colors and maintain uniform spacing. With no
saved browser preference, the dashboard must follow the device color-scheme
setting without an incorrect first paint. A manual Light or Dark choice may be
stored only in same-origin browser storage and must remain usable when storage
is disabled.

The desktop detail region uses a balanced two-column upper grid. Keep Internet
Performance on the left, keep compact Gateway Details above DNS Health on the
right, and place Important Hosts in one full-width row below with up to three
equal host cards. At 760 px and below, the cards must collapse into the
overflow-free order Internet, Gateway Details, DNS Health, then Important Hosts.

The Server topology card shows container CPU and memory values with retained
sparklines. Keep the small history graphs approximately 75% taller than the
original 30 px treatment. Every small history graph shows dark neutral low,
midpoint, and high guides with dynamic low/high y-axis values in the graph's
unit. The large Active-target latency graph shows four dynamic y-axis values:
its current upper scale, two-thirds, one-third, and 0 ms.

The dashboard must provide a complete server-rendered initial view and may poll
only the same-origin `/api/status` and `/api/history` endpoints. History ranges
are restricted to 1h, 6h, 24h, and 30d. Do not restore 7d or All without also
changing the fixed retention contract. Render ping loss and DNS failures in the
approved failure red, and do not turn a total failure into a zero-latency sample.
Avoid third-party scripts and preserve a restrictive Content Security Policy
without inline JavaScript.

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
