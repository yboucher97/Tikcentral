#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/yboucher97/Tikcentral.git"
DOMAIN=""
EMAIL=""
SSH_PORT="22"
ROOT="/opt/tikcentral"
APP="$ROOT/current"
ENV_DIR="/etc/tikcentral"
ENV_FILE="$ENV_DIR/tikcentral.env"
DATA_DIR="/var/lib/tikcentral"
BACKUP_DIR="/var/backups/tikcentral"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$DOMAIN" ]] || { echo "--domain is required" >&2; exit 2; }
[[ -n "$EMAIL" ]] || { echo "--email is required" >&2; exit 2; }
[[ "$EUID" -eq 0 ]] || { echo "Run this bootstrap as root (use: curl ... | sudo bash -s -- ...)" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive

# Refresh package metadata, but do not perform a machine-wide upgrade.
# apt-get install below only installs/upgrades packages Tikcentral actually requires.
apt-get update
apt-get install -y --no-install-recommends \
  apt-transport-https ca-certificates curl debian-archive-keyring debian-keyring git gnupg jq python3 python3-venv sqlite3 sudo ufw wireguard-tools

# Ensure Caddy comes from its official stable repository. Running apt-get install for
# this named package is idempotent: if the installed version already matches the
# repository candidate, apt makes no change; if Tikcentral needs the newer package,
# only Caddy and its required dependencies are upgraded.
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y --no-install-recommends caddy

id tikcentral >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin tikcentral
install -d -o root -g root -m 0755 "$ROOT" "$ENV_DIR" /etc/wireguard
install -d -o tikcentral -g tikcentral -m 0750 "$DATA_DIR"
install -d -o root -g root -m 0750 "$BACKUP_DIR"

if [[ -d "$APP/.git" ]]; then
  git -C "$APP" fetch --prune origin
  git -C "$APP" reset --hard origin/main
else
  rm -rf "$APP"
  git clone --depth 1 "$REPO" "$APP"
fi

chmod +x "$APP/bootstrap.sh" "$APP/scripts/"*.sh "$APP/helpers/tikcentral-wg-peer"
install -o root -g root -m 0755 "$APP/helpers/tikcentral-wg-peer" /usr/local/sbin/tikcentral-wg-peer
printf 'tikcentral ALL=(root) NOPASSWD: /usr/local/sbin/tikcentral-wg-peer *\n' > /etc/sudoers.d/tikcentral-wg
chmod 0440 /etc/sudoers.d/tikcentral-wg
visudo -cf /etc/sudoers.d/tikcentral-wg >/dev/null

if [[ ! -f /etc/wireguard/server.key ]]; then
  # Keep restrictive permissions only while creating WireGuard private material.
  # Restore the caller's umask immediately afterwards so later app files/venvs
  # remain readable/executable by the dedicated tikcentral service account.
  OLD_UMASK="$(umask)"
  umask 077
  wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
  umask "$OLD_UMASK"
fi
WG_PRIVATE="$(cat /etc/wireguard/server.key)"
WG_PUBLIC="$(cat /etc/wireguard/server.pub)"

if [[ ! -f /etc/wireguard/wg0.conf ]]; then
  cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.250.0.1/16
ListenPort = 51820
PrivateKey = $WG_PRIVATE
SaveConfig = true
EOF
  chmod 0600 /etc/wireguard/wg0.conf
fi

cat > /etc/sysctl.d/99-tikcentral.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null

if [[ ! -f "$ENV_FILE" ]]; then
  ADMIN_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(40))')"
  DASHBOARD_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  cat > "$ENV_FILE" <<EOF
ADMIN_API_KEY=$ADMIN_API_KEY
DASHBOARD_PASSWORD=$DASHBOARD_PASSWORD
DB_PATH=$DATA_DIR/tikcentral.db
WG_HELPER=/usr/local/sbin/tikcentral-wg-peer
WG_SERVER_PUBLIC_KEY=$WG_PUBLIC
WG_ENDPOINT=$DOMAIN:51820
PUBLIC_HOSTNAME=$DOMAIN
WG_ROUTER_POOL=10.250.1.0/24
WG_ALLOWED_NETWORK=10.250.0.0/16
TOKEN_TTL_HOURS=24
ONLINE_SECONDS=180
TEMP_ACCESS_DAYS=5
WINBOX_PUBLIC_PORT_MIN=20000
WINBOX_PUBLIC_PORT_MAX=49999
WINBOX_TARGET_PORT=8291
WINBOX_RESCAN_SECONDS=10
EOF
  chmod 0640 "$ENV_FILE"
  chown root:tikcentral "$ENV_FILE"
else
  sed -i "s|^WG_SERVER_PUBLIC_KEY=.*|WG_SERVER_PUBLIC_KEY=$WG_PUBLIC|" "$ENV_FILE"
  sed -i "s|^WG_ENDPOINT=.*|WG_ENDPOINT=$DOMAIN:51820|" "$ENV_FILE"
  if grep -q '^PUBLIC_HOSTNAME=' "$ENV_FILE"; then sed -i "s|^PUBLIC_HOSTNAME=.*|PUBLIC_HOSTNAME=$DOMAIN|" "$ENV_FILE"; else echo "PUBLIC_HOSTNAME=$DOMAIN" >> "$ENV_FILE"; fi
  grep -q '^DASHBOARD_PASSWORD=' "$ENV_FILE" || echo "DASHBOARD_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')" >> "$ENV_FILE"
  grep -q '^ONLINE_SECONDS=' "$ENV_FILE" || echo 'ONLINE_SECONDS=180' >> "$ENV_FILE"
  grep -q '^TEMP_ACCESS_DAYS=' "$ENV_FILE" || echo 'TEMP_ACCESS_DAYS=5' >> "$ENV_FILE"
  grep -q '^WINBOX_PUBLIC_PORT_MIN=' "$ENV_FILE" || echo 'WINBOX_PUBLIC_PORT_MIN=20000' >> "$ENV_FILE"
  grep -q '^WINBOX_PUBLIC_PORT_MAX=' "$ENV_FILE" || echo 'WINBOX_PUBLIC_PORT_MAX=49999' >> "$ENV_FILE"
  grep -q '^WINBOX_TARGET_PORT=' "$ENV_FILE" || echo 'WINBOX_TARGET_PORT=8291' >> "$ENV_FILE"
  grep -q '^WINBOX_RESCAN_SECONDS=' "$ENV_FILE" || echo 'WINBOX_RESCAN_SECONDS=10' >> "$ENV_FILE"
fi

set -a
source "$ENV_FILE"
set +a
DASHBOARD_HASH="$(caddy hash-password --plaintext "$DASHBOARD_PASSWORD")"

python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/pip" install --upgrade pip wheel
# Reconcile only Tikcentral's Python dependencies to the versions declared by the repo.
"$ROOT/venv/bin/pip" install -r "$APP/app/requirements.txt"

# Repair permissions from older bootstrap runs that leaked umask 077 into venv creation.
# Root owns the environment. Every venv directory must be traversable by the service;
# regular files are read-only to non-root, while existing executable files remain executable.
chown -R root:root "$ROOT/venv"
find "$ROOT/venv" -type d -exec chmod 0755 {} +
find "$ROOT/venv" -type f -exec chmod a+r {} +
find "$ROOT/venv/bin" -maxdepth 1 -type f -exec chmod 0755 {} +
chmod 0755 "$ROOT" "$ROOT/venv" "$ROOT/venv/bin"

# Verify the dedicated service account can actually execute the venv interpreter before
# touching systemd. Fail here with a clear path dump rather than entering a restart loop.
if ! sudo -u tikcentral "$ROOT/venv/bin/python3" --version >/dev/null 2>&1; then
  echo "Tikcentral service account cannot execute the Python virtual environment." >&2
  namei -l "$ROOT/venv/bin/python3" >&2 || true
  findmnt -T "$ROOT/venv/bin/python3" >&2 || true
  exit 1
fi

install -o root -g root -m 0644 "$APP/deploy/tikcentral.service" /etc/systemd/system/tikcentral.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-winbox-proxy.service" /etc/systemd/system/tikcentral-winbox-proxy.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.service" /etc/systemd/system/tikcentral-backup.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.timer" /etc/systemd/system/tikcentral-backup.timer

cat > /etc/caddy/Caddyfile <<EOF
{
    email $EMAIL
}

$DOMAIN {
    encode zstd gzip

    @router_api path /api/enroll /healthz
    handle @router_api {
        reverse_proxy 127.0.0.1:8080
    }

    handle {
        basic_auth {
            admin $DASHBOARD_HASH
        }
        reverse_proxy 127.0.0.1:8080
    }
}
EOF
caddy fmt --overwrite /etc/caddy/Caddyfile >/dev/null
caddy validate --config /etc/caddy/Caddyfile

ufw allow "$SSH_PORT/tcp"
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 51820/udp
ufw allow 20000:49999/tcp
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw route allow in on wg0 out on wg0 from 10.250.254.0/24 to 10.250.1.0/24
ufw --force enable

systemctl daemon-reload
systemctl enable --now wg-quick@wg0
systemctl enable --now caddy
systemctl enable --now tikcentral
systemctl restart tikcentral
systemctl enable --now tikcentral-winbox-proxy
systemctl restart tikcentral-winbox-proxy
systemctl enable --now tikcentral-backup.timer

# Give the API a few seconds to initialize, then fail with useful diagnostics if it
# still is not listening. This makes first-install failures self-diagnosing.
API_OK=0
for _ in {1..10}; do
  if curl -fsS http://127.0.0.1:8080/healthz >/tmp/tikcentral-health.json 2>/dev/null; then
    API_OK=1
    break
  fi
  sleep 1
done

if [[ "$API_OK" -ne 1 ]]; then
  echo >&2
  echo "Tikcentral API failed to start. Service diagnostics:" >&2
  systemctl --no-pager --full status tikcentral || true
  echo >&2
  journalctl -u tikcentral -n 80 --no-pager || true
  exit 1
fi

jq . /tmp/tikcentral-health.json
rm -f /tmp/tikcentral-health.json

echo
echo "Tikcentral installed."
echo "Dashboard: https://$DOMAIN/"
echo "Dashboard username: admin"
echo "Dashboard password: $DASHBOARD_PASSWORD"
echo "Public WinBox relay ports: 20000-49999/tcp (source IP authorization enforced by Tikcentral)"
echo "WireGuard public key: $WG_PUBLIC"
echo "Run: cd $APP && sudo ./scripts/status.sh"
