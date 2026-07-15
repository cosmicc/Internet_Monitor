# Changelog

## 0.2.0 - 07.14.2026

### Added

- Added a soft Swarm placement preference for nodes carrying the
  `internet-monitor` label.
- Added operator instructions for labeling the preferred node and reconciling
  the service after that node returns.
- Added the root `VERSION` file as a simple version reference for operators and
  scripts.
- Added a compact Important Hosts dashboard card with up to three configurable
  fping targets, DNS-aware skipping, retained history, and independent alerts.
- Added live tmpfs capacity reporting with web and Pushover warning, critical,
  measurement-failure, and recovery transitions.
- Added an accessible Light/Dark dashboard control with labeled desktop choices
  and compact sun/moon icons on mobile.
- Added a dashboard screenshot to the README.

### Changed

- Changed all package, container, deployment, and documentation version surfaces
  to 0.2.0.
- Changed every active environment variable to its shorter unprefixed name. The
  former `INTERNET_MONITOR_` names are intentionally unsupported in this clean
  configuration break.
- Shortened the DNS Health card and placed Important Hosts in the newly available
  dashboard space while preserving responsive layouts.
- Documented that Swarm can reschedule the single monitor task onto an eligible
  unlabeled node when the preferred node is unavailable.
- Changed complete tmpfs history snapshot publication from every probe to an
  at-most-once-per-minute cadence while retaining every probe in memory and
  keeping live status updates at the configured interval.
- Changed history retention to resolution-matched tiers: exact samples for 6
  hours, minute summaries for 24 hours, and hourly summaries for 30 days.
- Changed the longest dashboard range from 7d to 30d and removed the unbounded
  All range.
- Reused one bounded probe executor across cycles instead of recreating worker
  threads every interval, and moved ordered Pushover delivery to one background
  worker so notification timeouts cannot delay monitoring.
- Reduced the ephemeral `/tmp` limit from 64 MiB to 16 MiB after bounding the
  history file and record count.
- Reduced recurring container work by using a minimal standard-library health
  check and disabling routine dashboard access logs while preserving errors.
- Changed repeated per-cycle issue details to debug logging after the initial
  warning; alert thresholds, state changes, and recoveries remain visible at
  normal log levels.
- Replaced configurable, unbounded-lifetime history tiers with the fixed 30-day
  contract; the retired `HISTORY_DETAILED_HOURS` and
  `HISTORY_MINUTE_DAYS` variables are no longer used.
- Bounded probe counts, timing, DNS-server count, web concurrency, and chart
  points, and reject configurations whose probe window cannot fit the monitor
  interval.
- Changed the dashboard's initial theme to follow the device color-scheme
  setting and remember a manual browser choice across reloads.

### Fixed

- Fixed Swarm placement so the single monitor task considers the
  operator-designated node before other eligible nodes without sacrificing
  automatic failover.
- Fixed steadily increasing background CPU usage caused by serializing the
  entire growing history dataset after every monitoring cycle.
- Fixed potentially unbounded system-resolver delays by using a timeout-controlled
  NSS lookup subprocess.
- Fixed avoidable history API work by validating only the tier needed for the
  requested range and reading the bounded snapshot without a duplicate encoding.
- Fixed chart rendering overhead by combining hundreds of SVG line elements into
  compact paths while retaining loss and outage styling.
- Fixed routine Pushover network delays blocking the next monitoring cycle.
- Fixed aggregate bucket timestamps drawing a startup chart segment outside its
  visible range.
- Fixed priority hostname checks creating avoidable delays or false failures
  during DNS outages by skipping them until the system resolver and one direct
  DNS server respond.
- Fixed priority hostname checks waiting for every configured DNS timeout by
  starting them as soon as the first usable direct DNS result arrives.
- Fixed a full tmpfs becoming invisible after JSON writes fail by measuring
  capacity independently in the web process.
- Fixed repeated writes under critical tmpfs pressure by retaining new history
  in memory, pausing history publication, and skipping status writes only when
  no space remains; publication resumes automatically after recovery.
- Fixed Python distribution metadata so wheel and source package pages include
  the project README as their long description.

## 0.1.2 - 07.13.2026

### Added

- Added container-lifetime ping and DNS response-time history with 1-hour,
  6-hour, 24-hour, 7-day, and All dashboard ranges.
- Added per-target and per-resolver history sparklines, including red markers for
  packet loss and failed DNS checks.
- Added configurable detailed, minute-summary, and dashboard-point retention
  limits through synchronized Docker environment variables.

### Changed

- Changed dashboard history from browser memory to a shared, atomic tmpfs
  snapshot that retains detailed samples for 24 hours, minute summaries for 30
  days, and hourly summaries for the remaining container lifetime.
- Increased the Compose and Swarm tmpfs allocation to 64 MiB for bounded
  container-scoped history.
- Changed long-range downsampling to retain the maximum packet loss or DNS
  failure observed in each displayed interval.

### Fixed

- Fixed monitoring charts losing all collected information when the dashboard
  was reloaded or opened in a new browser session.

## 0.1.1 - 07.13.2026

### Added

- Added a chart legend and screen-reader descriptions that summarize the latest
  latency, packet loss, and number of loss-affected samples.

### Changed

- Changed gateway and Internet browser-session charts to render partial-loss
  intervals and samples in red while keeping clean latency intervals green.
- Changed the GitHub Release workflow to build the Python wheel and source
  distribution before publishing the multi-architecture container image.
- Documented same-node Swarm DNS troubleshooting for secondary host IPs, task
  overlay source subnets, Unbound access control, and narrowly scoped UFW input
  and routed rules for both UDP/53 and TCP/53.

### Fixed

- Fixed complete packet-loss samples being omitted from charts by displaying a
  red vertical outage marker without inventing a zero-latency response.

## 0.1.0 - 07.13.2026

### Added

- Added direct `dig` checks against every server in
  `DNS_SERVERS`, with response timing and configurable record
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
  added the configurable `LOG_LEVEL` setting.
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
