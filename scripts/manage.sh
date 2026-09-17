#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-status}"
CURRENT="/opt/tikcentral/current"

case "$ACTION" in
  update)
    [[ "$EUID" -eq 0 ]] || exec sudo "$0" "$@"
    exec /usr/local/sbin/tikcentral-update
    ;;
  restart)
    [[ "$EUID" -eq 0 ]] || exec sudo "$0" "$@"
    systemctl restart wg-quick@wg0 tikcentral tikcentral-winbox-proxy caddy
    systemctl restart tikcentral-fleet.timer
    "$CURRENT/scripts/status.sh"
    ;;
  backup)
    [[ "$EUID" -eq 0 ]] || exec sudo "$0" "$@"
    "$CURRENT/scripts/backup.sh"
    ;;
  status)
    [[ "$EUID" -eq 0 ]] || exec sudo "$0" "$@"
    "$CURRENT/scripts/status.sh"
    ;;
  *)
    echo "usage: $0 {status|update|restart|backup}" >&2
    exit 2
    ;;
esac
