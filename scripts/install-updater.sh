#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$EUID" -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
install -o root -g root -m 0755 "$ROOT/helpers/tikcentral-update" /usr/local/sbin/tikcentral-update
echo "Installed /usr/local/sbin/tikcentral-update"
echo "Future updates: sudo tikcentral-update"
