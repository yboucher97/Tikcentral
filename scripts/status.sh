#!/usr/bin/env bash
set -euo pipefail

echo '== Services =='
systemctl --no-pager --full status wg-quick@wg0 tikcentral tikcentral-winbox-proxy caddy tikcentral-backup.timer || true

echo
echo '== API =='
curl -fsS http://127.0.0.1:8080/healthz | jq . || true

echo
echo '== Public WinBox listeners =='
ss -ltnp | grep -E ':(2[0-9]{4}|3[0-9]{4}|4[0-9]{4}) ' || true

echo
echo '== WireGuard =='
wg show wg0 || true

echo
echo '== Disk =='
df -h / /var/lib/tikcentral /var/backups/tikcentral 2>/dev/null || true
