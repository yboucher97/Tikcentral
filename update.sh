#!/usr/bin/env bash
set -euo pipefail

ROOT="/opt/tikcentral"
APP="$ROOT/current"
ENV_FILE="/etc/tikcentral/tikcentral.env"

[[ "$EUID" -eq 0 ]] || { echo "Run as root (use sudo)." >&2; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "Tikcentral is not installed: $ENV_FILE is missing. Run bootstrap.sh once first." >&2; exit 1; }
[[ -d "$APP/.git" ]] || { echo "Tikcentral app repository is missing at $APP. Run bootstrap.sh once first." >&2; exit 1; }

# Preserve persistent state before touching code.
STAMP="$(date -u +%Y%m%d-%H%M%S)"
mkdir -p /var/backups/tikcentral
if [[ -f /var/lib/tikcentral/tikcentral.db ]]; then
  sqlite3 /var/lib/tikcentral/tikcentral.db ".backup '/var/backups/tikcentral/pre-update-$STAMP.db'"
fi
cp -a "$ENV_FILE" "/var/backups/tikcentral/pre-update-$STAMP.env"

# Update application source only. Persistent data/config are outside the repository.
git -C "$APP" fetch --prune origin
git -C "$APP" reset --hard origin/main

# Update the narrowly-scoped root helper if its implementation changed.
chmod +x "$APP/helpers/tikcentral-wg-peer"
install -o root -g root -m 0755 "$APP/helpers/tikcentral-wg-peer" /usr/local/sbin/tikcentral-wg-peer
printf 'tikcentral ALL=(root) NOPASSWD: /usr/local/sbin/tikcentral-wg-peer *\n' > /etc/sudoers.d/tikcentral-wg
chmod 0440 /etc/sudoers.d/tikcentral-wg
visudo -cf /etc/sudoers.d/tikcentral-wg >/dev/null

# Reconcile Tikcentral's Python environment only.
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

# Update service definitions only; do not recreate runtime data.
install -o root -g root -m 0644 "$APP/deploy/tikcentral.service" /etc/systemd/system/tikcentral.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-winbox-proxy.service" /etc/systemd/system/tikcentral-winbox-proxy.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-enroll-ui.service" /etc/systemd/system/tikcentral-enroll-ui.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.service" /etc/systemd/system/tikcentral-backup.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.timer" /etc/systemd/system/tikcentral-backup.timer

# Read existing configuration. Never rewrite credentials during update.
set -a
source "$ENV_FILE"
set +a
DOMAIN="${PUBLIC_HOSTNAME:-${WG_ENDPOINT%:*}}"
[[ -n "$DOMAIN" ]] || { echo "Could not determine Tikcentral hostname from $ENV_FILE" >&2; exit 1; }

# Refresh reverse-proxy routing for application services only.
cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    encode zstd gzip

    handle_path /enroll* {
        reverse_proxy 127.0.0.1:8081
    }

    handle {
        reverse_proxy 127.0.0.1:8080
    }
}
EOF
caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null
caddy validate --config /etc/caddy/Caddyfile

systemctl daemon-reload
systemctl enable tikcentral tikcentral-winbox-proxy tikcentral-enroll-ui tikcentral-backup.timer >/dev/null
systemctl restart tikcentral
systemctl restart tikcentral-winbox-proxy
systemctl restart tikcentral-enroll-ui
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
echo "Enrollment UI: https://$DOMAIN/enroll"
