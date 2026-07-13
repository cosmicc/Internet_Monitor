# Installation

Internet Monitor supports local Docker Compose, Portainer, and Docker Swarm.
Configuration values come from `.env.example`; do not commit a populated `.env`
file because it may contain Pushover credentials.

The default Swarm deployment pulls the versioned 0.1.0 image from GHCR. For
testing source changes that have not been released, use Docker Compose or
override `INTERNET_MONITOR_IMAGE` with an image published under a test tag.

## Docker Compose

1. Clone the repository and create the local environment file.

```bash
git clone https://github.com/cosmicc/Internet_Monitor.git
cd Internet_Monitor
cp .env.example .env
```

2. Edit `.env`, then build and start the service.

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f
```

Open `http://<docker-host>:5005`, or the configured host port.

## Gateway Path Configuration

Set either or both optional gateway variables in `.env` or the stack environment:

```dotenv
INTERNET_MONITOR_GATEWAY_1_IP=192.0.2.1
INTERNET_MONITOR_GATEWAY_2_IP=198.51.100.1
```

Gateway 1 must be the closest pingable device to the monitoring server. Gateway
2 must be the next pingable device toward the Internet. The monitor treats a
Gateway 1 outage as a local network issue, a Gateway 2 outage while Gateway 1 is
up as an upstream gateway issue, and an Internet-target outage while both
gateways are up as an ISP or Internet issue. Leave a value blank to disable that
hop.

## Portainer With Docker Compose

1. Create a stack from the Git repository.
2. Select `docker-compose.yml` as the Compose path.
3. Add the required values from `.env.example` to the stack environment.
4. Deploy the stack and inspect its console logs.

Compose builds the image from the repository. It grants only `NET_RAW`, runs as
an unprivileged user, and stores the latest dashboard snapshot in tmpfs.

## Docker Swarm

Swarm cannot build the image in the stack definition. By default,
`docker-stack.yml` pulls `ghcr.io/cosmicc/internet-monitor:0.1.0`. Override
`INTERNET_MONITOR_IMAGE` when testing another registry tag.

Deploy without Pushover secrets:

```bash
docker stack config --compose-file docker-stack.yml
docker stack deploy --with-registry-auth --compose-file docker-stack.yml internet-monitor
docker service logs -f internet-monitor_internet-monitor
```

The service is intentionally fixed at one replica. Its published port uses the
Swarm ingress routing mesh. Do not scale it, because each replica would run the
same checks and send duplicate alerts.

## Pushover Docker Secrets For Swarm

Create the external secrets once on a Swarm manager. The commands read values
without putting them in source files:

```bash
read -rsp "Pushover application token: " PUSHOVER_TOKEN
printf '%s' "$PUSHOVER_TOKEN" | docker secret create internet_monitor_pushover_token -
unset PUSHOVER_TOKEN

read -rsp "Pushover user key: " PUSHOVER_USER
printf '%s' "$PUSHOVER_USER" | docker secret create internet_monitor_pushover_user -
unset PUSHOVER_USER
```

Portainer users may instead create secrets with the same names in its Swarm
secret interface. Deploy both stack files to attach them:

```bash
docker stack config \
  --compose-file docker-stack.yml \
  --compose-file docker-stack.secrets.yml

docker stack deploy --with-registry-auth \
  --compose-file docker-stack.yml \
  --compose-file docker-stack.secrets.yml \
  internet-monitor
```

The application reads the mounted files through
`INTERNET_MONITOR_PUSHOVER_TOKEN_FILE` and
`INTERNET_MONITOR_PUSHOVER_USER_FILE`. Secret files take precedence over direct
environment values.

Failed and rate-limited Pushover messages remain in an ordered in-memory queue.
`INTERNET_MONITOR_PUSHOVER_RETRY_INITIAL_SECONDS` controls the first retry delay;
subsequent failures back off to
`INTERNET_MONITOR_PUSHOVER_RETRY_MAX_SECONDS`. Delivery retries continue until
successful while the container is running, but the queue intentionally does not
survive a restart.

## Release Image Publishing

Publishing a GitHub Release triggers `.github/workflows/publish-release-image.yml`.
The workflow requires the release tag, such as `v0.1.0`, to match the package
version. It runs tests, validates Compose and Swarm definitions, and then
publishes `linux/amd64` and `linux/arm64` images to GHCR. Stable releases also
update the `latest` tag.

## Operations

Application events are available only through Docker console logging:

```bash
docker compose logs -f
docker service logs -f internet-monitor_internet-monitor
```

There is no log volume or database to back up. The current dashboard state,
browser-session charts, alert counters, and queued Pushover messages reset when
the page or container restarts, as applicable.

The dashboard does not trust `X-Forwarded-For`. When nginx is added later, keep
the direct allow-list empty until the trusted proxy boundary is implemented and
tested.
