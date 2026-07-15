#!/usr/bin/env bash
# Install the Internet Monitor placement reconciler on one Swarm manager.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly PROJECT_ROOT
readonly ASSET_DIR="$PROJECT_ROOT/deploy/swarm-placement"
readonly RECONCILER_PATH="/usr/local/sbin/internet-monitor-placement-reconciler"
readonly SERVICE_PATH="/etc/systemd/system/internet-monitor-placement.service"
readonly TIMER_PATH="/etc/systemd/system/internet-monitor-placement.timer"
readonly CONFIG_PATH="/etc/default/internet-monitor-placement"
readonly TIMER_OVERRIDE_DIR="/etc/systemd/system/internet-monitor-placement.timer.d"
readonly TIMER_OVERRIDE_PATH="$TIMER_OVERRIDE_DIR/interval.conf"

service_name="internet-monitor_internet-monitor"
label_key="internet-monitor"
label_value="true"
interval_seconds=30

usage() {
    cat <<'EOF'
Usage: sudo scripts/install-swarm-placement-reconciler.sh [OPTIONS]

Options:
  --service NAME               Swarm service name.
  --label KEY=VALUE            Preferred node label and value.
  --interval-seconds SECONDS   Reconciliation interval (10-3600; default 30).
  -h, --help                   Show this help.
EOF
}

fail() {
    printf 'Install failed: %s\n' "$*" >&2
    exit 1
}

validate_identifier() {
    local name="$1"
    local value="$2"

    [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] ||
        fail "$name contains unsupported characters or exceeds 128 characters."
}

while (($# > 0)); do
    case "$1" in
        --service)
            (($# >= 2)) || fail "--service requires a value."
            service_name="$2"
            shift 2
            ;;
        --label)
            (($# >= 2)) || fail "--label requires KEY=VALUE."
            [[ "$2" == *=* ]] || fail "--label requires KEY=VALUE."
            label_key="${2%%=*}"
            label_value="${2#*=}"
            shift 2
            ;;
        --interval-seconds)
            (($# >= 2)) || fail "--interval-seconds requires a value."
            interval_seconds="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

((EUID == 0)) || fail "run this installer as root."
validate_identifier "service name" "$service_name"
validate_identifier "label key" "$label_key"
validate_identifier "label value" "$label_value"
[[ "$interval_seconds" =~ ^[0-9]+$ ]] || fail "interval must be an integer."
((interval_seconds >= 10 && interval_seconds <= 3600)) ||
    fail "interval must be between 10 and 3600 seconds."

for required_command in docker flock install systemctl; do
    command -v "$required_command" >/dev/null 2>&1 ||
        fail "$required_command was not found in PATH."
done

for required_asset in \
    "$ASSET_DIR/internet-monitor-placement-reconciler" \
    "$ASSET_DIR/internet-monitor-placement.service" \
    "$ASSET_DIR/internet-monitor-placement.timer"; do
    [[ -f "$required_asset" ]] || fail "required asset is missing: $required_asset"
done

if ! swarm_details="$(
    docker info --format \
        '{{.Swarm.LocalNodeState}}|{{.Swarm.ControlAvailable}}|{{.Swarm.NodeID}}' \
        2>/dev/null
)"; then
    fail "cannot query Docker; run this installer on a Swarm manager."
fi
IFS='|' read -r swarm_state control_available local_node_id <<<"$swarm_details"
[[ "$swarm_state" == "active" && "$control_available" == "true" &&
    -n "$local_node_id" ]] ||
    fail "this host is not an active Swarm manager."

local_label_template="{{index .Spec.Labels \"${label_key}\"}}"
if ! local_label_value="$(
    docker node inspect "$local_node_id" --format "$local_label_template" \
        2>/dev/null
)"; then
    fail "cannot inspect the local manager's node labels."
fi
[[ "$local_label_value" != "$label_value" ]] || fail \
    "install on a stable manager that does not carry ${label_key}=${label_value}; otherwise it cannot enable fallback when that node goes down."

docker service inspect "$service_name" >/dev/null 2>&1 ||
    fail "Swarm service $service_name does not exist. Deploy the stack first."

install -D -o root -g root -m 0755 \
    "$ASSET_DIR/internet-monitor-placement-reconciler" "$RECONCILER_PATH"
install -D -o root -g root -m 0644 \
    "$ASSET_DIR/internet-monitor-placement.service" "$SERVICE_PATH"
install -D -o root -g root -m 0644 \
    "$ASSET_DIR/internet-monitor-placement.timer" "$TIMER_PATH"
install -d -o root -g root -m 0755 "$(dirname -- "$CONFIG_PATH")"
install -d -o root -g root -m 0755 "$TIMER_OVERRIDE_DIR"

temporary_config="$(mktemp)"
temporary_override="$(mktemp)"
trap 'rm -f -- "$temporary_config" "$temporary_override"' EXIT
chmod 0600 "$temporary_config" "$temporary_override"

printf '%s\n' \
    "SERVICE_NAME=$service_name" \
    "PREFERRED_NODE_LABEL=$label_key" \
    "PREFERRED_NODE_LABEL_VALUE=$label_value" \
    >"$temporary_config"

printf '%s\n' \
    '[Timer]' \
    'OnUnitActiveSec=' \
    "OnUnitActiveSec=${interval_seconds}s" \
    >"$temporary_override"

install -o root -g root -m 0644 "$temporary_config" "$CONFIG_PATH"
install -o root -g root -m 0644 "$temporary_override" "$TIMER_OVERRIDE_PATH"

systemctl daemon-reload
systemctl enable --now internet-monitor-placement.timer
if ! systemctl start internet-monitor-placement.service; then
    systemctl disable --now internet-monitor-placement.timer >/dev/null 2>&1 || true
    fail "the first reconciliation failed; inspect journalctl -u internet-monitor-placement.service."
fi

printf '%s\n' \
    "Installed Internet Monitor placement reconciliation every ${interval_seconds} seconds." \
    "Service: $service_name" \
    "Preferred label: ${label_key}=${label_value}" \
    'Logs: journalctl -u internet-monitor-placement.service'
