# Changelog

## 0.1.0 - 07.13.2026

### Added

- Added direct `dig` checks against every server in
  `INTERNET_MONITOR_DNS_SERVERS`, with response timing and configurable record
  type, timeout, slow-response threshold, and consecutive-failure trigger.
- Added independent Pushover failure, slow-response, and recovery alerts for each
  configured DNS server.
- Added a current-status dashboard for Internet metrics, the system resolver, and
  per-server DNS response times.
- Added two optional, ordered gateway IP checks with independent degradation,
  outage, and recovery alerts.
- Added path diagnosis for local network, upstream gateway, ISP/Internet, and DNS
  failures.
- Added a live Server → Gateway 1 → Gateway 2 → Internet topology, detailed
  min/average/max latency and packet statistics, and browser-session charts.
- Added a same-origin `/api/status` endpoint for live dashboard updates.
- Added `docker-stack.yml` for a single-replica Swarm deployment using ingress,
  stop-first updates, rollback settings, and a registry image.
- Added optional external Swarm secrets through `docker-stack.secrets.yml`.
- Added a GitHub Release workflow that validates the release tag and publishes
  multi-architecture GHCR images.
- Added the approved Operational Dark palette reference at
  `docs/color-palette.svg`.

### Changed

- Moved all operator-controlled behavior into validated Docker environment
  variables synchronized across `.env.example`, Compose, and Swarm.
- Changed application logging to human-readable stdout output for Docker and
  added the configurable `INTERNET_MONITOR_LOG_LEVEL` setting.
- Changed current dashboard state to an atomic, permission-restricted snapshot
  inside the container's `/tmp` tmpfs.
- Changed ping, gateway, system-resolver, and per-server DNS probes to run in one
  concurrent monitoring cycle.
- Changed Pushover rate-limit handling to queue messages instead of dropping
  them, with configurable capped exponential retry backoff until delivery.
- Changed the dashboard from full-page refreshes to same-origin JSON polling
  while preserving a complete server-rendered initial view.
- Hardened the container with an explicit unprivileged UID/GID, a read-only root
  filesystem, dropped capabilities, and only `NET_RAW` added back for fping.
- Added security headers and bounded status-file reads to the web dashboard.
- Aligned package, image, deployment, and documentation version surfaces for
  the 0.1.0 release.

### Fixed

- Removed persistent application log files, the Docker data volume, the web log
  viewer, and the clear-log endpoint.
- Fixed partial packet-loss handling so a reachable fping target is not treated as
  a complete outage solely because fping returned a non-zero exit status.
- Fixed health checks so a dashboard client allow-list cannot block the internal
  Docker liveness endpoint.
- Fixed DNS observability by distinguishing system-resolver failures, explicit
  server failures, and slow server responses.
- Fixed incomplete ping observability by capturing transmitted/received packets
  and minimum, average, and maximum latency for every target.
- Fixed cumulative DNS timeout delays by querying configured servers
  concurrently.
