#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL=""
DOMAIN=""
EMAIL=""
ADMIN_EMAIL=""
SSH_PORT="22"
ROOT="/opt/tikcentral"
REPO="$ROOT/repository.git"
ENV_DIR="/etc/tikcentral"
ENV_FILE="$ENV_DIR/tikcentral.env"
DATA_DIR="/var/lib/tikcentral"
BACKUP_DIR="/var/backups/tikcentral"

if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  REPO_URL="$(git -C "$SCRIPT_DIR" remote get-url origin 2>/dev/null || true)"
fi
[[ -n "$REPO_URL" ]] || REPO_URL="https://github.com/yboucher97/Tikcentral.git"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO_URL="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --admin-email) ADMIN_EMAIL="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$DOMAIN" ]] || { echo "--domain is required" >&2; exit 2; }
[[ -n "$EMAIL" ]] || { echo "--email is required" >&2; exit 2; }
[[ -n "$ADMIN_EMAIL" ]] || ADMIN_EMAIL="$EMAIL"
[[ "$EUID" -eq 0 ]] || { echo "Run bootstrap with sudo/root." >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  apt-transport-https ca-certificates curl debian-archive-keyring debian-keyring \
  git gnupg jq python3 python3-venv sqlite3 sudo ufw wireguard-tools

if ! command -v caddy >/dev/null 2>&1; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
  apt-get update
  apt-get install -y --no-install-recommends caddy
fi

id tikcentral >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin tikcentral
install -d -o root -g root -m 0755 "$ROOT" "$ROOT/releases" "$ENV_DIR" /etc/wireguard
install -d -o tikcentral -g tikcentral -m 0750 "$DATA_DIR" "$DATA_DIR/router-backups"
install -d -o root -g root -m 0750 "$BACKUP_DIR"

# The bare mirror is the only Git checkout used by production. For a private
# repository, --repo must be an origin the root updater can authenticate to
# later as well (for example an SSH deploy-key URL).
if [[ ! -d "$REPO" ]]; then
  if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git clone --mirror "$SCRIPT_DIR" "$REPO"
    git --git-dir="$REPO" remote set-url origin "$REPO_URL"
  else
    git clone --mirror "$REPO_URL" "$REPO"
  fi
fi
git --git-dir="$REPO" remote set-url origin "$REPO_URL"
git --git-dir="$REPO" fetch --prune origin '+refs/heads/main:refs/heads/main'
chmod -R go-rwx "$REPO"

if [[ ! -f /etc/wireguard/server.key ]]; then
  old_umask="$(umask)"
  umask 077
  wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
  umask "$old_umask"
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

set_env() {
  local key="$1" value="$2"
  if [[ -f "$ENV_FILE" ]] && grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

INITIAL_PASSWORD=""
if [[ ! -f "$ENV_FILE" ]]; then
  touch "$ENV_FILE"
  INITIAL_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  set_env ADMIN_API_KEY "$(python3 -c 'import secrets; print(secrets.token_urlsafe(40))')"
  set_env DASHBOARD_PASSWORD "$INITIAL_PASSWORD"
  set_env DB_PATH "$DATA_DIR/tikcentral.db"
  set_env WG_HELPER /usr/local/sbin/tikcentral-wg-peer
  set_env WG_ROUTER_POOL 10.250.1.0/24
  set_env WG_ALLOWED_NETWORK 10.250.0.0/16
  set_env TOKEN_TTL_HOURS 24
  set_env ONLINE_SECONDS 180
  set_env TEMP_ACCESS_DAYS 5
  set_env SESSION_DAYS 7
  set_env WINBOX_PUBLIC_PORT_MIN 20000
  set_env WINBOX_PUBLIC_PORT_MAX 49999
  set_env WINBOX_TARGET_PORT 8291
  set_env WINBOX_RESCAN_SECONDS 10
  set_env TIKCENTRAL_TIMEZONE America/Toronto
  set_env TIKCENTRAL_PROVISIONING_KEY "$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')"
  set_env TIKCENTRAL_ROUTER_API_PASSWORD "$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  set_env ROUTER_BACKUP_PASSWORD "$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
fi
set_env ADMIN_EMAIL "$ADMIN_EMAIL"
set_env WG_SERVER_PUBLIC_KEY "$WG_PUBLIC"
set_env WG_ENDPOINT "$DOMAIN:51820"
set_env PUBLIC_HOSTNAME "$DOMAIN"
set_env ACME_EMAIL "$EMAIL"
chmod 0640 "$ENV_FILE"
chown root:tikcentral "$ENV_FILE"

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

systemctl enable --now wg-quick@wg0

# Hand off service files, per-release Python environment, migrations, validation,
# Caddy and health checks to the same atomic updater used for every later release.
tmp_updater="$(mktemp /tmp/tikcentral-bootstrap-update.XXXXXX.sh)"
git --git-dir="$REPO" show refs/heads/main:update.sh > "$tmp_updater"
chmod 0700 "$tmp_updater"
bash "$tmp_updater"
rm -f "$tmp_updater"

echo
echo "Tikcentral installed."
echo "Dashboard: https://$DOMAIN/"
echo "Enrollment: https://$DOMAIN/enroll"
echo "Admin email: $ADMIN_EMAIL"
if [[ -n "$INITIAL_PASSWORD" ]]; then
  echo "Initial password: $INITIAL_PASSWORD"
  echo "Change it after login at: https://$DOMAIN/account/password"
fi
echo "Updates: sudo tikcentral-update"
echo "Status: sudo /opt/tikcentral/current/scripts/manage.sh status"
