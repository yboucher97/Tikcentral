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
apt-get update
apt-get upgrade -y
apt-get install -y --no-install-recommends \
  ca-certificates caddy curl git jq python3 python3-venv sqlite3 sudo ufw wireguard-tools

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
  umask 077
  wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
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
  cat > "$ENV_FILE" <<EOF
ADMIN_API_KEY=$ADMIN_API_KEY
DB_PATH=$DATA_DIR/tikcentral.db
WG_HELPER=/usr/local/sbin/tikcentral-wg-peer
WG_SERVER_PUBLIC_KEY=$WG_PUBLIC
WG_ENDPOINT=$DOMAIN:51820
WG_ROUTER_POOL=10.250.1.0/24
WG_ALLOWED_NETWORK=10.250.0.0/16
TOKEN_TTL_HOURS=24
EOF
  chmod 0640 "$ENV_FILE"
  chown root:tikcentral "$ENV_FILE"
else
  sed -i "s|^WG_SERVER_PUBLIC_KEY=.*|WG_SERVER_PUBLIC_KEY=$WG_PUBLIC|" "$ENV_FILE"
  sed -i "s|^WG_ENDPOINT=.*|WG_ENDPOINT=$DOMAIN:51820|" "$ENV_FILE"
fi

python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/pip" install --upgrade pip wheel
"$ROOT/venv/bin/pip" install -r "$APP/app/requirements.txt"

install -o root -g root -m 0644 "$APP/deploy/tikcentral.service" /etc/systemd/system/tikcentral.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.service" /etc/systemd/system/tikcentral-backup.service
install -o root -g root -m 0644 "$APP/deploy/tikcentral-backup.timer" /etc/systemd/system/tikcentral-backup.timer

cat > /etc/caddy/Caddyfile <<EOF
{
    email $EMAIL
}

$DOMAIN {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
EOF
caddy validate --config /etc/caddy/Caddyfile

ufw allow "$SSH_PORT/tcp"
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 51820/udp
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw route allow in on wg0 out on wg0 from 10.250.254.0/24 to 10.250.1.0/24
ufw --force enable

systemctl daemon-reload
systemctl enable --now wg-quick@wg0
systemctl enable --now caddy
systemctl enable --now tikcentral
systemctl enable --now tikcentral-backup.timer

sleep 2
curl -fsS http://127.0.0.1:8080/healthz | jq .

echo
echo "Tikcentral installed."
echo "Domain: https://$DOMAIN"
echo "WireGuard public key: $WG_PUBLIC"
echo "Run: cd $APP && sudo ./scripts/status.sh"
