# Installation

Internet Monitor is deployed with Docker Compose, either through Portainer or
from the command line.

## Portainer Stack

1. Create a new Portainer stack from the Git repository.
2. Use `docker-compose.yml` as the compose path.
3. Set environment overrides in Portainer if the defaults in `.env.example` are
   not appropriate.
4. Deploy the stack.

The stack builds the image from this repository, grants only `NET_RAW` for
fping, publishes the web UI on port `5005` by default, and stores runtime data in
the `internet-monitor-data` Docker volume.

## Command-Line Docker Compose

1. Clone the repository on the Docker host.

```bash
git clone <repository-url> Internet_Monitor
cd Internet_Monitor
```

2. Create a local environment file and edit it for the deployment.

```bash
cp .env.example .env
```

Do not commit `.env`; it can contain Pushover tokens and deployment-specific
settings.

3. Build and start the stack.

```bash
docker compose up -d --build
```

4. Confirm the service is healthy.

```bash
docker compose ps
docker compose logs -f
```

Open `http://<docker-host>:5005`, or the port configured with
`INTERNET_MONITOR_WEB_HOST_PORT`.

## Useful Commands

```bash
docker compose logs -f
docker compose ps
docker compose down
```

To reset logs and status, remove the `internet-monitor-data` volume after the
stack is stopped.
