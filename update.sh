#!/usr/bin/env bash
set -euo pipefail

ROOT="/opt/tikcentral"
APP="$ROOT/current"
ENV_FILE="/etc/tikcentral/tikcentral.env"
SSH_DIR="/etc/tikcentral/ssh"
ROUTER_BACKUP_DIR="/var/backups/tikcentral/routers"

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
DEPLOYED_COMMIT="$(git -C "$APP" rev-parse --short HEAD)"

apt-get update
apt-get install -y --no-install-recommends openssh-client

chmod +x "$APP/helpers/tikcentral-wg-peer"
install -o root -g root -m 0755 "$APP/helpers/tikcentral-wg-peer" /usr/local/sbin/tikcentral-wg-peer
printf 'tikcentral ALL=(root) NOPASSWD: /usr/local/sbin/tikcentral-wg-peer *\n' > /etc/sudoers.d/tikcentral-wg
chmod 0440 /etc/sudoers.d/tikcentral-wg
visudo -cf /etc/sudoers.d/tikcentral-wg >/dev/null

install -d -o root -g tikcentral -m 0750 "$SSH_DIR"
if [[ ! -f "$SSH_DIR/tikcentral_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C 'tikcentral-vps' -f "$SSH_DIR/tikcentral_ed25519"
fi
chown root:tikcentral "$SSH_DIR/tikcentral_ed25519"
chmod 0640 "$SSH_DIR/tikcentral_ed25519"
chown root:tikcentral "$SSH_DIR/tikcentral_ed25519.pub"
chmod 0644 "$SSH_DIR/tikcentral_ed25519.pub"

install -d -o tikcentral -g tikcentral -m 0750 "$ROUTER_BACKUP_DIR"
if [[ ! -f /var/lib/tikcentral/known_hosts ]]; then
  install -o tikcentral -g tikcentral -m 0600 /dev/null /var/lib/tikcentral/known_hosts
else
  chown tikcentral:tikcentral /var/lib/tikcentral/known_hosts
  chmod 0600 /var/lib/tikcentral/known_hosts
fi

grep -q '^TIKCENTRAL_ROUTER_USER=' "$ENV_FILE" || echo 'TIKCENTRAL_ROUTER_USER=tikcentral' >> "$ENV_FILE"
grep -q '^TIKCENTRAL_SSH_KEY=' "$ENV_FILE" || echo 'TIKCENTRAL_SSH_KEY=/etc/tikcentral/ssh/tikcentral_ed25519' >> "$ENV_FILE"
grep -q '^TIKCENTRAL_KNOWN_HOSTS=' "$ENV_FILE" || echo 'TIKCENTRAL_KNOWN_HOSTS=/var/lib/tikcentral/known_hosts' >> "$ENV_FILE"
grep -q '^ROUTER_BACKUP_DIR=' "$ENV_FILE" || echo 'ROUTER_BACKUP_DIR=/var/backups/tikcentral/routers' >> "$ENV_FILE"
grep -q '^TIKCENTRAL_SSH_TIMEOUT=' "$ENV_FILE" || echo 'TIKCENTRAL_SSH_TIMEOUT=20' >> "$ENV_FILE"
grep -q '^TIKCENTRAL_FLEET_WORKERS=' "$ENV_FILE" || echo 'TIKCENTRAL_FLEET_WORKERS=8' >> "$ENV_FILE"
if ! grep -q '^ROUTER_BACKUP_PASSWORD=' "$ENV_FILE"; then
  echo "ROUTER_BACKUP_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"
fi
if ! grep -q '^TIKCENTRAL_ROUTER_API_PASSWORD=' "$ENV_FILE"; then
  echo "TIKCENTRAL_ROUTER_API_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"
fi
if ! grep -q '^TIKCENTRAL_PROVISIONING_KEY=' "$ENV_FILE"; then
  echo "TIKCENTRAL_PROVISIONING_KEY=$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')" >> "$ENV_FILE"
fi
chmod 0640 "$ENV_FILE"
chown root:tikcentral "$ENV_FILE"

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
  "$APP/app/entrypoint.py" \
  "$APP/app/fleet.py" \
  "$APP/app/fleet_runner.py" \
  "$APP/app/fleet_web.py" \
  "$APP/app/guardian.py" \
  "$APP/app/changes.py" \
  "$APP/app/provisioning.py" \
  "$APP/app/production.py" \
  "$APP/app/final.py" \
  "$APP/app/winbox_proxy.py"

set -a
source "$ENV_FILE"
set +a

ROUTES="$(cd "$APP" && "$ROOT/venv/bin/python3" -c 'from app.final import app; print("\n".join(sorted({r.path for r in app.routes})))')"
for REQUIRED_ROUTE in /enroll /enroll/generate /enroll/admin-credentials /routers /settings /automation /automation/command /automation/backup /automation/update/check /automation/update/install /ssh '/ssh/{router_id}' /guardian '/guardian/{router_id}/repair' /changes '/changes/{router_id}' /audit '/audit/{router_id}' '/audit/{router_id}/normalize'; do
  if ! grep -Fxq "$REQUIRED_ROUTE" <<<"$ROUTES"; then
    echo "Required route $REQUIRED_ROUTE is missing from app.final." >&2
    echo "$ROUTES" >&2
    exit 1
  fi
done

MANAGED_SCRIPT="$(cd "$APP" && "$ROOT/venv/bin/python3" -c 'from app.production import managed_router_script_with_api_password; print(managed_router_script_with_api_password("scope-check", "scope-check-token"))')"
if ! grep -Fq 'Tikcentral managed service identity' <<<"$MANAGED_SCRIPT"; then
  echo "Enrollment script is missing the managed Tikcentral identity." >&2
  exit 1
fi
if ! grep -Fq 'password=' <<<"$MANAGED_SCRIPT" || ! grep -Fq 'name="tikcentral"' <<<"$MANAGED_SCRIPT"; then
  echo "Enrollment script is missing the VM-held RouterOS API credential." >&2
  exit 1
fi
if grep -Fq 'key-owner=' <<<"$MANAGED_SCRIPT"; then
  echo "Enrollment script contains invalid direct SSH key syntax (key-owner=)." >&2
  exit 1
fi
if ! grep -Fq 'dst-port=22,8291,8728' <<<"$MANAGED_SCRIPT"; then
  echo "Enrollment script is missing the canonical Tikcentral management firewall rule." >&2
  exit 1
fi
if ! grep -Fxq '{' <<<"$MANAGED_SCRIPT" || ! grep -Fxq '}' <<<"$MANAGED_SCRIPT"; then
  echo "RouterOS enrollment script is not wrapped in a single local scope." >&2
  exit 1
fi

DEFAULT_SCRIPT="$(cd "$APP" && "$ROOT/venv/bin/python3" -c 'from app.provisioning import default_config_script; print(default_config_script("scope-check",12,4,500,500,80,40,"ether2"))')"
if ! grep -Fq 'Default WAN DHCP' <<<"$DEFAULT_SCRIPT" || ! grep -Fq 'Bell PPPoE - enter credentials onsite' <<<"$DEFAULT_SCRIPT" || ! grep -Fq 'Opticable FastTrack' <<<"$DEFAULT_SCRIPT"; then
  echo "Opticable default provisioning profile failed validation." >&2
  exit 1
fi

cd "$APP"
"$ROOT/venv/bin/python3" -c 'from app.fleet import ensure_schema; ensure_schema()'
"$ROOT/venv/bin/python3" -c 'from app.guardian import ensure_schema; ensure_schema()'
"$ROOT/venv/bin/python3" -c 'from app.provisioning import ensure_schema; ensure_schema()'

install -o root -g root -m 0644 "$APP/deploy/tikcentral.service" /etc/systemd/system/tikcentral.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-winbox-proxy.service" /etc/systemd/system/tikcentral-winbox-proxy.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.service" /etc/systemd/system/tikcentral-backup.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.timer" /etc/systemd/system/tikcentral-backup.timer
install -o root -g root -m 0644 "$APP/deploy/tikcentral-fleet.service" /etc/systemd/system/tikcentral-fleet.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-fleet.timer" /etc/systemd/system/tikcentral-fleet.timer

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
systemctl enable tikcentral tikcentral-winbox-proxy tikcentral-backup.timer tikcentral-fleet.timer >/dev/null
systemctl disable --now tikcentral-enroll-ui >/dev/null 2>&1 || true
systemctl restart tikcentral
systemctl restart tikcentral-winbox-proxy
systemctl restart caddy
systemctl start tikcentral-backup.timer
systemctl restart tikcentral-fleet.timer

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
  journalctl -u tikcentral -n 100 --no-pager || true
  exit 1
fi

for PATH_TO_CHECK in /enroll /routers /automation /ssh /guardian /changes /audit; do
  CODE="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$PATH_TO_CHECK" || true)"
  if [[ "$CODE" != "200" && "$CODE" != "303" ]]; then
    echo "Tikcentral $PATH_TO_CHECK failed directly on the application (HTTP $CODE)." >&2
    systemctl show tikcentral -p ExecStart --no-pager >&2 || true
    journalctl -u tikcentral -n 100 --no-pager >&2 || true
    exit 1
  fi
done

CADDY_CODE="$(curl -ksS --resolve "$DOMAIN:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$DOMAIN/guardian" || true)"
if [[ "$CADDY_CODE" != "200" && "$CADDY_CODE" != "303" ]]; then
  echo "Tikcentral /guardian failed through Caddy (HTTP $CADDY_CODE)." >&2
  cat /etc/caddy/Caddyfile >&2 || true
  exit 1
fi

jq . /tmp/tikcentral-update-health.json
rm -f /tmp/tikcentral-update-health.json

echo
echo "Tikcentral updated successfully."
echo "Deployed commit: $DEPLOYED_COMMIT"
echo "Fleet SSH identity: ready"
echo "Router API credential: ready (secret retained on VPS)"
echo "Encrypted personal-router credential store: ready"
echo "Enrollment modes: Tikcentral-only + Opticable default config"
echo "Access Guardian: enabled (1-minute checks)"
echo "Configuration change history: ready"
echo "Router backup scheduler: enabled"
echo "Live router audit/normalization: ready"
echo "Guardian Caddy check: HTTP $CADDY_CODE"
echo "Persistent state preserved: users, routers, WireGuard assignments, authorized IPs and existing configuration."
echo "Pre-update backup: /var/backups/tikcentral/pre-update-$STAMP.db"
echo "Dashboard: https://$DOMAIN/"
echo "Routers: https://$DOMAIN/routers"
echo "Guardian: https://$DOMAIN/guardian"
echo "Changes: https://$DOMAIN/changes"
echo "Enrollment: https://$DOMAIN/enroll"
echo "Automation: https://$DOMAIN/automation"
echo "Web SSH: https://$DOMAIN/ssh"
echo "Audit: https://$DOMAIN/audit"
echo "Settings: https://$DOMAIN/settings"
