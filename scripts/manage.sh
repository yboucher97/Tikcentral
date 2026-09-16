#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-status}"
APP="/opt/tikcentral/current"
VENV="/opt/tikcentral/venv"

case "$ACTION" in
  update)
    [[ "$EUID" -eq 0 ]] || exec sudo "$0" "$@"
    git -C "$APP" fetch --prune origin
    git -C "$APP" reset --hard origin/main
    chmod +x "$APP/bootstrap.sh" "$APP/scripts/"*.sh "$APP/helpers/tikcentral-wg-peer"
    install -o root -g root -m 0755 "$APP/helpers/tikcentral-wg-peer" /usr/local/sbin/tikcentral-wg-peer
    "$VENV/bin/pip" install -r "$APP/app/requirements.txt"
    install -o root -g root -m 0644 "$APP/deploy/tikcentral.service" /etc/systemd/system/tikcentral.service
    install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.service" /etc/systemd/system/tikcentral-backup.service
    install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.timer" /etc/systemd/system/tikcentral-backup.timer
    systemctl daemon-reload
    systemctl restart tikcentral
    systemctl restart caddy
    "$APP/scripts/status.sh"
    ;;
  restart)
    [[ "$EUID" -eq 0 ]] || exec sudo "$0" "$@"
    systemctl restart wg-quick@wg0 tikcentral caddy
    "$APP/scripts/status.sh"
    ;;
  backup)
    [[ "$EUID" -eq 0 ]] || exec sudo "$0" "$@"
    "$APP/scripts/backup.sh"
    ;;
  status)
    [[ "$EUID" -eq 0 ]] || exec sudo "$0" "$@"
    "$APP/scripts/status.sh"
    ;;
  *)
    echo "usage: $0 {status|update|restart|backup}" >&2
    exit 2
    ;;
esac
