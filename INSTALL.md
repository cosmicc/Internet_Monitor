# Installation

Internet Monitor supports local Docker Compose, Portainer, and Docker Swarm.
Configuration values come from `.env.example`; do not commit a populated `.env`
file because it may contain Pushover credentials.

The default Swarm deployment pulls the versioned 0.3 image from GHCR. For
testing source changes that have not been released, use Docker Compose or
override `IMAGE` with an image published under a test tag.

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

## Dashboard Port Configuration

`WEB_PORT` is the only dashboard port setting. It controls the port published
on the Docker host or through the Swarm ingress routing mesh. The application,
Docker target, and health check always use port `5005` inside the container.

For example, publish the dashboard on port `8080` without changing its internal
services:

```dotenv
WEB_PORT=8080
```

Deployments created from an earlier 0.2.0 configuration may contain both
`WEB_HOST_PORT` and `WEB_PORT`. Keep the former `WEB_HOST_PORT` value as the new
`WEB_PORT` value and remove `WEB_HOST_PORT`:

```dotenv
# Earlier configuration
WEB_HOST_PORT=8080
WEB_PORT=5005

# Current configuration
WEB_PORT=8080
```

## Gateway Path Configuration

Set either or both optional gateway variables in `.env` or the stack environment:

```dotenv
GATEWAY_1_IP=192.0.2.1
GATEWAY_2_IP=198.51.100.1
```

Gateway 1 must be the closest pingable device to the monitoring server. Gateway
2 must be the next pingable device toward the Internet. The monitor treats a
Gateway 1 outage as a local network issue, a Gateway 2 outage while Gateway 1 is
up as an upstream gateway issue, and an Internet-target outage while both
gateways are up as an ISP or Internet issue. Leave a value blank to disable that
hop.

## Important Host Configuration

Configure two or three priority hostnames to add them to the Important Hosts
dashboard card and the normal ping alert lifecycle:

```dotenv
IMPORTANT_HOST_1=status.example.com
IMPORTANT_HOST_2=api.example.com
IMPORTANT_HOST_3=
```

The monitor starts these fping checks only when the system resolver succeeds and
at least one server in `DNS_SERVERS` returns a usable response. When DNS is
unavailable, the checks are marked as skipped on the web page; they do not add
false packet-loss history or advance an outage alert. A slow but responding
direct DNS server is sufficient because it can still resolve the hostname.

## Portainer With Docker Compose

1. Create a stack from the Git repository.
2. Select `docker-compose.yml` as the Compose path.
3. Add the required values from `.env.example` to the stack environment.
4. Deploy the stack and inspect its console logs.

Compose builds the image from the repository. It grants only `NET_RAW`, runs as
an unprivileged user, and stores current status and bounded 30-day chart history
in a 16 MiB tmpfs.

## Docker Swarm

Swarm cannot build the image in the stack definition. By default,
`docker-stack.yml` pulls `ghcr.io/cosmicc/internet-monitor:0.3`. Override
`IMAGE` when testing another registry tag.

From a Swarm manager, label the node that should normally run Internet Monitor:

```bash
docker node update --label-add internet-monitor=true <preferred-node>
```

Deploy without Pushover secrets:

```bash
docker stack config --compose-file docker-stack.yml
docker stack deploy --with-registry-auth --compose-file docker-stack.yml internet-monitor
docker service logs -f internet-monitor_internet-monitor
```

Docker Swarm does not provide a native “prefer this label, but fall back” rule.
Its `spread` preference distributes tasks across label-value groups, so one
labeled node is not prioritized over unlabeled nodes. The 0.2.2 stack therefore
has no static placement rule and remains schedulable on any eligible node.

To enable deterministic preference with fallback, install the included
reconciler on exactly one stable Swarm manager after deploying the stack. That
manager must not carry the preferred label, because the utility has to remain
online when the preferred node fails:

```bash
sudo scripts/install-swarm-placement-reconciler.sh
systemctl status internet-monitor-placement.timer
```

Every 30 seconds, the utility applies this behavior:

- If a node labeled `internet-monitor=true` is ready and active, add the exact
  placement constraint and let Swarm move the monitor there.
- If no matching node is ready and active, remove only that constraint so Swarm
  can place the task on another eligible node.
- When the preferred node returns, restore the constraint so the task moves
  back without a manual service update.

The expected failover delay is up to one reconciliation interval plus Swarm's
normal scheduling and task startup time. Label exactly one node when one
specific host should be preferred; if several healthy nodes have the label,
Swarm may select any of them.

The default service name, label, and interval can be changed during installation:

```bash
sudo scripts/install-swarm-placement-reconciler.sh \
  --service internet-monitor_internet-monitor \
  --label internet-monitor=true \
  --interval-seconds 30
```

The installer writes non-secret settings to
`/etc/default/internet-monitor-placement` and a timer override under
`/etc/systemd/system`. Rerun the installer with new options to change them. The
utility logs only placement changes and errors to the system journal:

```bash
journalctl -u internet-monitor-placement.service
docker service ps internet-monitor_internet-monitor
docker service inspect internet-monitor_internet-monitor \
  --format '{{json .Spec.TaskTemplate.Placement.Constraints}}'
```

The installer rejects a manager that has the preferred label. The application
container remains unprivileged and never mounts the Docker socket. The host
utility is a root-owned, locked-down oneshot because changing a Swarm service
requires manager access to `/var/run/docker.sock`.

To remove the utility, run the uninstaller on the same active manager. It stops
the timer and removes the constraint it owns before deleting its files:

```bash
sudo scripts/uninstall-swarm-placement-reconciler.sh
```

Use `--keep-constraint` only when the current hard placement should remain after
the timer is removed. If the selected manager is unavailable, the current
constraint remains unchanged until the utility runs on an active manager; the
application container cannot alter cluster placement itself.

The service is intentionally fixed at one replica. Its published port uses the
Swarm ingress routing mesh, while its target port remains fixed at `5005`. Do
not scale it, because each replica would run the same checks and send duplicate
alerts.

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
`PUSHOVER_TOKEN_FILE` and
`PUSHOVER_USER_FILE`. Secret files take precedence over direct
environment values.

Failed and rate-limited Pushover messages remain in an ordered in-memory queue.
`PUSHOVER_RETRY_INITIAL_SECONDS` controls the first retry delay;
subsequent failures back off to
`PUSHOVER_RETRY_MAX_SECONDS`. Delivery retries continue until
successful while the container is running, but the queue intentionally does not
survive a restart.

## Release Image Publishing

Publishing a GitHub Release triggers `.github/workflows/publish-release-image.yml`.
The workflow requires the release tag, such as `v0.3`, to match the package
version. It runs tests, validates Compose and Swarm definitions, and then
publishes `linux/amd64` and `linux/arm64` images to GHCR. Stable releases also
update the `latest` tag.

## Operations

Application events are available only through Docker console logging:

```bash
docker compose logs -f
docker service logs -f internet-monitor_internet-monitor
```

Manager-side placement changes and reconciliation errors are separate from
application logs and are available through systemd:

```bash
journalctl -u internet-monitor-placement.service
systemctl list-timers internet-monitor-placement.timer
```

Routine dashboard polling is intentionally excluded from the Gunicorn access
log to avoid thousands of low-value log writes per day. Gunicorn errors and all
monitoring events continue to use the Docker console. At the default `INFO`
level, a sustained issue logs its first observation, alert transition, and
recovery without repeating the same warning every monitoring cycle. Temporarily
set `LOG_LEVEL=DEBUG` when per-cycle probe details are needed.

There is no log volume or database to back up. The current dashboard state,
alert counters, chart history, and queued Pushover messages reset when the
container restarts or is redeployed. Reloading or reopening a browser restores
the most recently published container-scoped history. Retention is fixed at:

- Detailed probe-cycle samples for 6 hours.
- Minute summaries for 24 hours.
- Hourly summaries for 30 days.
- No history older than 30 days.

The JSON snapshots are stored under `/tmp/internet-monitor` in the container's
16 MiB tmpfs. They are compact, permission-restricted, and atomically replaced;
history is published no more than once per minute. At 80% tmpfs usage the web
page and Pushover report a warning. At 95% they report a critical condition.
The web process checks the filesystem directly, so the alert remains visible
even if a full tmpfs prevents the monitor from updating its snapshot.
History publication pauses at the critical threshold while samples continue to
be retained in memory. At zero available bytes, status publication also pauses.
Both resume automatically after space is recovered.

The dashboard downsamples long ranges while preserving the highest packet loss
or DNS failure, weighted average latency, and minimum/maximum latency in each
displayed interval. `HISTORY_MAX_POINTS` limits response and
browser chart size. Keep `HISTORY_PATH` on the container tmpfs;
pointing it at persistent storage changes the approved storage model.

### Upgrading From 0.2.2 To 0.3

Redeploy the service with the `0.3` image. No environment-variable or persistent
data migration is required. The container restart intentionally begins a fresh
ephemeral history window, now including container CPU and memory observations.

Container memory always shows current MiB. It also shows a percentage when the
deployment applies a finite Docker memory limit.

### Upgrading From 0.2.1 To 0.2.2

Redeploy `docker-stack.yml` first. This removes the old `spread` preference,
which did not actually prioritize the labeled node. The service remains free to
run anywhere until the optional manager utility is installed.

Keep the existing node label, then install the reconciler on one manager:

```bash
docker node update --label-add internet-monitor=true <preferred-node>
sudo scripts/install-swarm-placement-reconciler.sh
```

No application environment variables or monitoring data need migration. The
reconciler is host-level deployment automation and does not change the
application container's privileges or mounts.

### Upgrading From 0.1.x To 0.2.0

Version 0.2.0 is a clean configuration break. Every active variable has dropped
the `INTERNET_MONITOR_` prefix, and the old names are intentionally ignored. Do
not reuse a 0.1.x environment block unchanged. Start from the new `.env.example`
or replace each name by removing the prefix, for example:

```text
INTERNET_MONITOR_PING_HOST -> PING_HOST
INTERNET_MONITOR_DNS_SERVERS -> DNS_SERVERS
INTERNET_MONITOR_WEB_PORT -> WEB_PORT
INTERNET_MONITOR_PUSHOVER_TOKEN -> PUSHOVER_TOKEN
```

The retired `HISTORY_DETAILED_HOURS` and `HISTORY_MINUTE_DAYS` settings have no
replacement because retention is fixed. The new `IMPORTANT_HOST_1` through
`IMPORTANT_HOST_3` settings are optional.

Version 0.2.0 also uses a new bounded history format. History is intentionally
ephemeral, so redeploying starts a fresh 30-day window; there is no database or
history migration to run.

The updated stack reduces `/tmp` from 64 MiB to 16 MiB. Operators who want
preferred Swarm placement should apply the `internet-monitor=true` node label
before redeploying. Runtime configuration validation will reject excessive
probe or web concurrency and an interval shorter than its configured probe
window instead of allowing a permanently busy loop.

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

Set `QUERY_HOST` to the configured `DNS_HOST` value before
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
