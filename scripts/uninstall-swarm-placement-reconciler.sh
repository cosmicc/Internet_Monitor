#!/usr/bin/env bash
# Uninstall the Internet Monitor placement reconciler from a manager.

set -euo pipefail
IFS=$'\n\t'

readonly RECONCILER_PATH="/usr/local/sbin/internet-monitor-placement-reconciler"
readonly SERVICE_PATH="/etc/systemd/system/internet-monitor-placement.service"
readonly TIMER_PATH="/etc/systemd/system/internet-monitor-placement.timer"
readonly CONFIG_PATH="/etc/default/internet-monitor-placement"
readonly TIMER_OVERRIDE_DIR="/etc/systemd/system/internet-monitor-placement.timer.d"

service_name="internet-monitor_internet-monitor"
label_key="internet-monitor"
label_value="true"
keep_constraint=false
service_overridden=false
label_overridden=false

usage() {
    cat <<'EOF'
Usage: sudo scripts/uninstall-swarm-placement-reconciler.sh [OPTIONS]

By default, uninstalling first removes the constraint owned by the reconciler.

Options:
  --service NAME       Override the configured Swarm service name.
  --label KEY=VALUE    Override the configured preferred node label.
  --keep-constraint    Remove the systemd utility without changing placement.
  -h, --help           Show this help.
EOF
}

fail() {
    printf 'Uninstall failed: %s\n' "$*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --service)
            (($# >= 2)) || fail "--service requires a value."
            service_name="$2"
            service_overridden=true
            shift 2
            ;;
        --label)
            (($# >= 2)) || fail "--label requires KEY=VALUE."
            [[ "$2" == *=* ]] || fail "--label requires KEY=VALUE."
            label_key="${2%%=*}"
            label_value="${2#*=}"
            label_overridden=true
            shift 2
            ;;
        --keep-constraint)
            keep_constraint=true
            shift
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

((EUID == 0)) || fail "run this uninstaller as root."
command -v systemctl >/dev/null 2>&1 || fail "systemctl was not found in PATH."

# Parse only the three supported assignments; never execute configuration text.
if [[ -r "$CONFIG_PATH" ]]; then
    while IFS='=' read -r config_key config_value; do
        config_value="${config_value%$'\r'}"
        case "$config_key" in
            SERVICE_NAME)
                [[ "$service_overridden" == true ]] || service_name="$config_value"
                ;;
            PREFERRED_NODE_LABEL)
                [[ "$label_overridden" == true ]] || label_key="$config_value"
                ;;
            PREFERRED_NODE_LABEL_VALUE)
                [[ "$label_overridden" == true ]] || label_value="$config_value"
                ;;
        esac
    done <"$CONFIG_PATH"
fi

systemctl disable --now internet-monitor-placement.timer >/dev/null 2>&1 || true

if [[ "$keep_constraint" == false && -x "$RECONCILER_PATH" ]]; then
    if ! "$RECONCILER_PATH" \
        --service "$service_name" \
        --label "${label_key}=${label_value}" \
        --release-constraint; then
        systemctl enable --now internet-monitor-placement.timer >/dev/null 2>&1 || true
        fail "the owned constraint could not be removed. Retry on an active manager or use --keep-constraint."
    fi
fi

rm -f -- "$RECONCILER_PATH" "$SERVICE_PATH" "$TIMER_PATH" "$CONFIG_PATH"
rm -rf -- "$TIMER_OVERRIDE_DIR"
systemctl daemon-reload
systemctl reset-failed internet-monitor-placement.service >/dev/null 2>&1 || true

printf 'Internet Monitor placement reconciliation was uninstalled.\n'
