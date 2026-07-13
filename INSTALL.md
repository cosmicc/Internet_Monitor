# Installation

Internet Monitor supports local Docker Compose, Portainer, and Docker Swarm.
Configuration values come from `.env.example`; do not commit a populated `.env`
file because it may contain Pushover credentials.

The default Swarm deployment pulls the versioned 0.1.2 image from GHCR. For
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
an unprivileged user, and stores current status and container-lifetime chart
history in a 64 MiB tmpfs.

## Docker Swarm

Swarm cannot build the image in the stack definition. By default,
`docker-stack.yml` pulls `ghcr.io/cosmicc/internet-monitor:0.1.2`. Override
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
The workflow requires the release tag, such as `v0.1.2`, to match the package
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
alert counters, chart history, and queued Pushover messages reset when the
container restarts or is redeployed. Reloading or reopening a browser restores
the same container-scoped history. The default retention is:

- Detailed probe-cycle samples for 24 hours.
- Minute summaries for 30 days.
- Hourly summaries for the remaining lifetime of the container.

The dashboard downsamples long ranges while preserving the highest packet loss
or DNS failure in each displayed interval. Retention and response point limits
are configured by `INTERNET_MONITOR_HISTORY_DETAILED_HOURS`,
`INTERNET_MONITOR_HISTORY_MINUTE_DAYS`, and
`INTERNET_MONITOR_HISTORY_MAX_POINTS`. Keep `INTERNET_MONITOR_HISTORY_PATH` on
the container tmpfs; pointing it at persistent storage changes the approved
storage model.

### DNS Works On The Host But Fails In The Swarm Task

`dig` exit code 9 means that no reply reached the querying process. A query from
the Swarm task is a different network path from a query run directly on the
node, even when the DNS destination is a secondary IP assigned to that node.
The task reaches that address from a Docker overlay or `docker_gwbridge` source
subnet, which may be silently dropped by the host firewall, Docker forwarding
rules, or an Unbound access-control rule.

Find the local task and compare UDP and TCP queries from its network namespace:

```bash
MONITOR_TASK=$(docker ps \
  --filter name=internet-monitor_internet-monitor \
  --format '{{.ID}}' | head -n 1)
DNS_SERVER_IP="replace-with-dns-server-ip"
QUERY_HOST="www.google.com"

docker inspect "$MONITOR_TASK" \
  --format '{{range $name, $network := .NetworkSettings.Networks}}{{$name}} {{$network.IPAddress}}{{println}}{{end}}'

docker exec "$MONITOR_TASK" \
  dig @"$DNS_SERVER_IP" "$QUERY_HOST" A +time=5 +tries=1
docker exec "$MONITOR_TASK" \
  dig @"$DNS_SERVER_IP" "$QUERY_HOST" A +tcp +time=5 +tries=1
```

Set `QUERY_HOST` to the configured `INTERNET_MONITOR_DNS_HOST` value before
testing.

If both task queries time out while the node query succeeds, inspect packet flow
on the node while repeating one task query:

```bash
sudo tcpdump -ni any "host $DNS_SERVER_IP and port 53"
```

#### UFW Rules For A Host-Published Unbound Service

When Unbound publishes both DNS protocols with Swarm `mode: host`, traffic from
Internet Monitor to a secondary IP on the same node may cross two UFW paths:

1. The incoming path to the secondary host IP.
2. Docker's post-DNAT routed path to the Unbound overlay network.

Do not add an unrestricted `Anywhere` rule for DNS. Discover the two overlay
subnets, set the secondary IP, and confirm the values before changing UFW:

```bash
MONITOR_SUBNET=$(docker network inspect internet-monitor_default \
  --format '{{(index .IPAM.Config 0).Subnet}}')
UNBOUND_SUBNET=$(docker network inspect unbound_default \
  --format '{{(index .IPAM.Config 0).Subnet}}')
SECONDARY_DNS_IP="replace-with-secondary-dns-ip"
QUERY_HOST="www.google.com"

printf 'Monitor subnet: %s\nUnbound subnet: %s\nDNS IP: %s\n' \
  "$MONITOR_SUBNET" "$UNBOUND_SUBNET" "$SECONDARY_DNS_IP"
```

For example, an Internet Monitor network inspection may report
`10.251.6.0/24`. Allow only that source subnet to use DNS on the configured
secondary IP:

```bash
sudo ufw allow in proto udp \
  from "$MONITOR_SUBNET" to "$SECONDARY_DNS_IP" port 53 \
  comment 'Internet Monitor DNS UDP'
sudo ufw allow in proto tcp \
  from "$MONITOR_SUBNET" to "$SECONDARY_DNS_IP" port 53 \
  comment 'Internet Monitor DNS TCP'
```

Because Docker may DNAT the secondary IP to the Unbound task before UFW applies
its routed policy, also allow the same two protocols only to the Unbound overlay
subnet:

```bash
sudo ufw route allow proto udp \
  from "$MONITOR_SUBNET" to "$UNBOUND_SUBNET" port 53 \
  comment 'Internet Monitor routed DNS UDP'
sudo ufw route allow proto tcp \
  from "$MONITOR_SUBNET" to "$UNBOUND_SUBNET" port 53 \
  comment 'Internet Monitor routed DNS TCP'
```

The rules take effect immediately. Review them and retest from the task:

```bash
sudo ufw status numbered

docker exec "$MONITOR_TASK" \
  dig @"$SECONDARY_DNS_IP" "$QUERY_HOST" A +time=5 +tries=1
docker exec "$MONITOR_TASK" \
  dig @"$SECONDARY_DNS_IP" "$QUERY_HOST" A +tcp +time=5 +tries=1
```

If UFW no longer logs a block but Unbound still does not reply, its configuration
must also allow `MONITOR_SUBNET`. Keep that access-control entry limited to the
monitor overlay rather than allowing all private networks. Use
`sudo ufw delete RULE_NUMBER`, replacing `RULE_NUMBER` with a number shown by
`ufw status numbered`, to remove an incorrect rule.

Port 53 does not need to be opened between Swarm nodes when both services share
an overlay; that application traffic is carried inside Swarm's existing VXLAN
transport. A dedicated shared overlay network between the monitor and Unbound
services is preferable when both stacks can be changed together. Avoid host
networking for the monitor because it unnecessarily broadens network access and
weakens isolation.

The dashboard does not trust `X-Forwarded-For`. When nginx is added later, keep
the direct allow-list empty until the trusted proxy boundary is implemented and
tested.
