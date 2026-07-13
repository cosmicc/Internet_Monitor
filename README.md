# Internet Monitor

Internet Monitor 0.1.0 is a Docker-first Python service for Internet and gateway
reachability, packet loss, latency, system DNS resolution, and direct DNS-server
health checks.

## Features

- Concurrently checks primary, backup, and two optional gateway targets with
  fping.
- Uses the container resolver and concurrently runs `dig` against every
  configured DNS server.
- Diagnoses local gateway, upstream gateway, ISP/Internet, and DNS problems.
- Displays a live Server → Gateway 1 → Gateway 2 → Internet topology, detailed
  ping statistics, and browser-session latency charts.
- Sends independent Pushover alerts for gateways and DNS servers, with queued
  delivery retries and capped exponential backoff.
- Writes human-readable application logs only to the Docker console.
- Supports Docker Compose, Portainer, and a dedicated single-replica Swarm stack.

## Configuration

All operator settings are Docker environment variables. Start with
`.env.example`; the default DNS servers are `1.1.1.1` and `8.8.8.8`, and both
query `INTERNET_MONITOR_DNS_HOST`.

`INTERNET_MONITOR_GATEWAY_1_IP` and `INTERNET_MONITOR_GATEWAY_2_IP` are optional.
When configured, each value must be a pingable IPv4 or IPv6 address representing
the next device in order toward the Internet.

No monitoring history or logs are persisted. The dashboard receives only the
latest status through an ephemeral tmpfs snapshot. Browser charts begin when the
page opens and reset with the page. Pushover credentials can be supplied through
environment variables or Docker secrets.

For deployment and secret setup, see [INSTALL.md](INSTALL.md).

## Web Interface

The dark dashboard is published on port `5005` by default. It polls the sanitized
same-origin status endpoint at the monitor interval without reloading the page.
`INTERNET_MONITOR_WEB_ALLOWED_HOSTS` can restrict direct client addresses;
forwarded addresses are not trusted unless reverse-proxy support is added later.

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
docker compose config
docker stack config --compose-file docker-stack.yml
```
