# Changelog

## Unreleased

### Added

- Added a package-based Python structure under `internet_monitor/`.
- Added environment-backed settings for monitor, web, status, and Pushover
  configuration.
- Added a backup ping host and explicit fping period/timeout settings to reduce
  false outage and packet-loss alerts from a single remote host.
- Added `.env.example` with default Docker configuration values.
- Added pytest coverage for settings parsing, fping output parsing, status-file
  writes, and the Flask dashboard.
- Added `AGENTS.md`, `README.md`, `INSTALL.md`, and dependency metadata.

### Changed

- Updated Docker and Compose to run package modules, persist runtime data under
  `/data`, and deploy without a mounted config file.
- Switched the container web process from Flask's development server to Gunicorn.
- Optimized dashboard log tail reads to avoid loading the entire log file.
- Made monitor status writes atomic so the dashboard does not read partial JSON.

### Removed

- Removed `config.ini` and stale top-level script copies.
- Removed the tracked runtime `connection.log` file.
- Removed `install.sh`; deployment is handled by Docker stack tooling.
