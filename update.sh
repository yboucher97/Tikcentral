#!/usr/bin/env bash
set -euo pipefail

ROOT="/opt/tikcentral"
APP="$ROOT/current"
ENV_FILE="/etc/tikcentral/tikcentral.env"

[[ "$EUID" -eq 0 ]] || { echo "Run as root (use sudo)." >&2; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "Tikcentral is not installed: $ENV_FILE is missing. Run bootstrap.sh once first." >&2; exit 1; }
[[ -d "$APP/.git" ]] || { echo "Tikcentral app repository is missing at $APP. Run bootstrap.sh once first." >&2; exit 1; }

STAMP="$(date -u +%Y%m%d-%H%M%S)"
mkdir -p /var/backups/tikcentral
if [[ -f /var/lib/tikcentral/tikcentral.db ]]; then
  sqlite3 /var/lib/tikcentral/tikcentral.db ".backup '/var/backups/tikcentral/pre-update-$STAMP.db'"
fi
cp -a "$ENV_FILE" "/var/backups/tikcentral/pre-update-$STAMP.env"

git -C "$APP" fetch --prune origin
git -C "$APP" reset --hard origin/main

chmod +x "$APP/helpers/tikcentral-wg-peer"
install -o root -g root -m 0755 "$APP/helpers/tikcentral-wg-peer" /usr/local/sbin/tikcentral-wg-peer
printf 'tikcentral ALL=(root) NOPASSWD: /usr/local/sbin/tikcentral-wg-peer *\n' > /etc/sudoers.d/tikcentral-wg
chmod 0440 /etc/sudoers.d/tikcentral-wg
visudo -cf /etc/sudoers.d/tikcentral-wg >/dev/null

python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/pip" install --upgrade pip wheel
"$ROOT/venv/bin/pip" install -r "$APP/app/requirements.txt"

chown -R root:root "$ROOT/venv"
find "$ROOT/venv" -type d -exec chmod 0755 {} +
find "$ROOT/venv" -type f -exec chmod a+r {} +
find "$ROOT/venv/bin" -maxdepth 1 -type f -exec chmod 0755 {} +
chmod 0755 "$ROOT" "$ROOT/venv" "$ROOT/venv/bin"

if ! sudo -u tikcentral "$ROOT/venv/bin/python3" --version >/dev/null 2>&1; then
  echo "Tikcentral service account cannot execute the Python virtual environment." >&2
  namei -l "$ROOT/venv/bin/python3" >&2 || true
  exit 1
fi

"$ROOT/venv/bin/python3" -m py_compile \
  "$APP/app/main.py" \
  "$APP/app/portal.py" \
  "$APP/app/winbox_proxy.py"

install -o root -g root -m 0644 "$APP/deploy/tikcentral.service" /etc/systemd/system/tikcentral.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-winbox-proxy.service" /etc/systemd/system/tikcentral-winbox-proxy.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.service" /etc/systemd/system/tikcentral-backup.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.timer" /etc/systemd/system/tikcentral-backup.timer

set -a
source "$ENV_FILE"
set +a
DOMAIN="${PUBLIC_HOSTNAME:-${WG_ENDPOINT%:*}}"
[[ -n "$DOMAIN" ]] || { echo "Could not determine Tikcentral hostname from $ENV_FILE" >&2; exit 1; }

cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
EOF
caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null
caddy validate --config /etc/caddy/Caddyfile

systemctl daemon-reload
systemctl enable tikcentral tikcentral-winbox-proxy tikcentral-backup.timer >/dev/null
systemctl disable --now tikcentral-enroll-ui >/dev/null 2>&1 || true
systemctl restart tikcentral
systemctl restart tikcentral-winbox-proxy
systemctl restart caddy
systemctl start tikcentral-backup.timer

API_OK=0
for _ in {1..10}; do
  if curl -fsS http://127.0.0.1:8080/healthz >/tmp/tikcentral-update-health.json 2>/dev/null; then
    API_OK=1
    break
  fi
  sleep 1
done

if [[ "$API_OK" -ne 1 ]]; then
  echo "Tikcentral API failed after update. Existing DB/config were preserved and a pre-update backup was created." >&2
  systemctl --no-pager --full status tikcentral || true
  journalctl -u tikcentral -n 80 --no-pager || true
  exit 1
fi

if ! curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/enroll | grep -Eq '^(200|303)$'; then
  echo "Tikcentral enrollment route did not respond correctly after update." >&2
  journalctl -u tikcentral -n 80 --no-pager || true
  exit 1
fi

jq . /tmp/tikcentral-update-health.json
rm -f /tmp/tikcentral-update-health.json

echo
echo "Tikcentral updated successfully."
echo "Persistent state preserved:"
echo "  - users and password hashes"
echo "  - sessions"
echo "  - routers and assigned VPN/public WinBox ports"
echo "  - authorized IPs"
echo "  - enrollment history/tokens"
echo "  - WireGuard server keys and peers"
echo "  - /etc/tikcentral/tikcentral.env"
echo "Pre-update backup: /var/backups/tikcentral/pre-update-$STAMP.db"
echo "Dashboard: https://$DOMAIN/"
echo "Routers: https://$DOMAIN/routers"
echo "Enrollment: https://$DOMAIN/enroll"
echo "Settings: https://$DOMAIN/settings"
