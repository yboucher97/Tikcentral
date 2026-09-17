#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="/opt/tikcentral"
CURRENT="$ROOT/current"
RELEASES="$ROOT/releases"
REPO="$ROOT/repository.git"
ENV_FILE="/etc/tikcentral/tikcentral.env"
SSH_DIR="/etc/tikcentral/ssh"
ROUTER_BACKUP_DIR="/var/backups/tikcentral/routers"
KEEP_RELEASES="${TIKCENTRAL_KEEP_RELEASES:-5}"

[[ "$EUID" -eq 0 ]] || { echo "Run as root (use sudo)." >&2; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "Tikcentral is not installed: $ENV_FILE is missing. Run bootstrap.sh once first." >&2; exit 1; }
for cmd in git tar python3 sqlite3 curl jq caddy sudo visudo ssh-keygen systemctl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Required command is missing: $cmd" >&2; exit 1; }
done

mkdir -p "$RELEASES" /var/backups/tikcentral
chmod 0755 "$ROOT" "$RELEASES"

bootstrap_repository() {
  if [[ -d "$REPO" ]]; then
    return
  fi
  if [[ ! -d "$CURRENT/.git" ]]; then
    echo "Cannot initialize atomic updater: neither $REPO nor a git checkout at $CURRENT exists." >&2
    exit 1
  fi
  local remote tmp
  remote="$(git -C "$CURRENT" remote get-url origin)"
  tmp="$ROOT/.repository.git.$$"
  rm -rf "$tmp"
  git clone --mirror "$CURRENT" "$tmp" >/dev/null
  git --git-dir="$tmp" remote set-url origin "$remote"
  chmod -R go-rwx "$tmp"
  mv "$tmp" "$REPO"
}

bootstrap_repository

git --git-dir="$REPO" fetch --prune origin '+refs/heads/main:refs/heads/main'
TARGET_SHA="$(git --git-dir="$REPO" rev-parse refs/heads/main)"
SHORT_SHA="${TARGET_SHA:0:12}"

if [[ "${TIKCENTRAL_UPDATE_TARGET:-}" != "$TARGET_SHA" ]]; then
  tmp_updater="$(mktemp /tmp/tikcentral-update.XXXXXX.sh)"
  git --git-dir="$REPO" show "$TARGET_SHA:update.sh" > "$tmp_updater"
  chmod 0700 "$tmp_updater"
  export TIKCENTRAL_UPDATE_TARGET="$TARGET_SHA"
  exec bash "$tmp_updater"
fi

STAMP="$(date -u +%Y%m%d-%H%M%S)"
RELEASE="$RELEASES/$SHORT_SHA"
BUILD="$RELEASES/.build-$SHORT_SHA-$$"
DB_BACKUP="/var/backups/tikcentral/pre-update-$STAMP.db"
ENV_BACKUP="/var/backups/tikcentral/pre-update-$STAMP.env"

if [[ -f /var/lib/tikcentral/tikcentral.db ]]; then
  sqlite3 /var/lib/tikcentral/tikcentral.db ".backup '$DB_BACKUP'"
fi
cp -a "$ENV_FILE" "$ENV_BACKUP"

install -d -o root -g tikcentral -m 0750 "$SSH_DIR"
if [[ ! -f "$SSH_DIR/tikcentral_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C 'tikcentral-vps' -f "$SSH_DIR/tikcentral_ed25519"
fi
chown root:tikcentral "$SSH_DIR/tikcentral_ed25519" "$SSH_DIR/tikcentral_ed25519.pub"
chmod 0640 "$SSH_DIR/tikcentral_ed25519"
chmod 0644 "$SSH_DIR/tikcentral_ed25519.pub"

install -d -o tikcentral -g tikcentral -m 0750 "$ROUTER_BACKUP_DIR"
chown -R tikcentral:tikcentral "$ROUTER_BACKUP_DIR" || true
install -d -o tikcentral -g tikcentral -m 0750 /var/lib/tikcentral /var/lib/tikcentral/router-backups
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
grep -q '^TIKCENTRAL_TIMEZONE=' "$ENV_FILE" || echo 'TIKCENTRAL_TIMEZONE=America/Toronto' >> "$ENV_FILE"
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

if [[ ! -f "$RELEASE/.tikcentral-validated" ]] || [[ "$(cat "$RELEASE/.tikcentral-validated" 2>/dev/null || true)" != "$TARGET_SHA" ]]; then
  rm -rf "$BUILD" "$RELEASE"
  mkdir -p "$BUILD"
  git --git-dir="$REPO" archive "$TARGET_SHA" | tar -x -C "$BUILD"
  mv "$BUILD" "$RELEASE"

  python3 -m venv "$RELEASE/.venv"
  "$RELEASE/.venv/bin/pip" install --upgrade pip wheel >/dev/null
  "$RELEASE/.venv/bin/pip" install -r "$RELEASE/app/requirements.txt"

  chown -R root:root "$RELEASE"
  find "$RELEASE" -type d -exec chmod a+rx {} +
  find "$RELEASE" -type f -exec chmod a+r {} +
  find "$RELEASE/.venv/bin" -maxdepth 1 -type f -exec chmod a+rx {} +

  sudo -u tikcentral bash -c "set -a; source '$ENV_FILE'; set +a; cd '$RELEASE'; '$RELEASE/.venv/bin/python3' scripts/validate_release.py"
  printf '%s\n' "$TARGET_SHA" > "$RELEASE/.tikcentral-validated"
fi

sudo -u tikcentral bash -c "set -a; source '$ENV_FILE'; set +a; cd '$RELEASE'; '$RELEASE/.venv/bin/python3' -c 'from app import migrations; migrations.migrate()'"

install_runtime_files() {
  local release="$1"
  chmod +x "$release/helpers/tikcentral-wg-peer" "$release/helpers/tikcentral-update"
  install -o root -g root -m 0755 "$release/helpers/tikcentral-wg-peer" /usr/local/sbin/tikcentral-wg-peer
  install -o root -g root -m 0755 "$release/helpers/tikcentral-update" /usr/local/sbin/tikcentral-update
  printf 'tikcentral ALL=(root) NOPASSWD: /usr/local/sbin/tikcentral-wg-peer *\n' > /etc/sudoers.d/tikcentral-wg
  chmod 0440 /etc/sudoers.d/tikcentral-wg
  visudo -cf /etc/sudoers.d/tikcentral-wg >/dev/null

  install -o root -g root -m 0644 "$release/deploy/tikcentral.service" /etc/systemd/system/tikcentral.service
  install -o root -g root -m 0644 "$release/deploy/tikcentral-winbox-proxy.service" /etc/systemd/system/tikcentral-winbox-proxy.service
  install -o root -g root -m 0644 "$release/deploy/tikcentral-backup.service" /etc/systemd/system/tikcentral-backup.service
  install -o root -g root -m 0644 "$release/deploy/tikcentral-backup.timer" /etc/systemd/system/tikcentral-backup.timer
  install -o root -g root -m 0644 "$release/deploy/tikcentral-fleet.service" /etc/systemd/system/tikcentral-fleet.service
  install -o root -g root -m 0644 "$release/deploy/tikcentral-fleet.timer" /etc/systemd/system/tikcentral-fleet.timer
}

switch_current() {
  local target="$1" link="$ROOT/.current-next-$$"
  rm -f "$link"
  ln -s "$target" "$link"
  if [[ -L "$CURRENT" ]]; then
    mv -Tf "$link" "$CURRENT"
  elif [[ ! -e "$CURRENT" ]]; then
    mv "$link" "$CURRENT"
  else
    rm -f "$link"
    return 1
  fi
}

wait_health() {
  local tries="${1:-20}"
  for ((i=1; i<=tries; i++)); do
    if curl -fsS http://127.0.0.1:8080/healthz >/tmp/tikcentral-update-health.json 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

PREVIOUS=""
if [[ -L "$CURRENT" ]]; then
  PREVIOUS="$(readlink -f "$CURRENT")"
elif [[ -d "$CURRENT" ]]; then
  PREVIOUS="$RELEASES/legacy-$STAMP"
fi

rollback() {
  local reason="$1"
  trap - ERR
  echo "New release failed activation: $reason" >&2
  if [[ -z "$PREVIOUS" || ! -d "$PREVIOUS" ]]; then
    echo "No previous release is available for automatic rollback." >&2
    return 1
  fi
  systemctl stop tikcentral-fleet.timer >/dev/null 2>&1 || true
  systemctl stop tikcentral-fleet.service >/dev/null 2>&1 || true
  switch_current "$PREVIOUS" || true
  [[ -f "$PREVIOUS/deploy/tikcentral.service" ]] && install_runtime_files "$PREVIOUS"
  systemctl daemon-reload || true
  systemctl restart tikcentral || true
  systemctl restart tikcentral-winbox-proxy || true
  systemctl restart caddy || true
  systemctl start tikcentral-backup.timer >/dev/null 2>&1 || true
  systemctl restart tikcentral-fleet.timer >/dev/null 2>&1 || true
  if wait_health 15; then
    echo "Automatic rollback succeeded: $PREVIOUS" >&2
  else
    echo "Automatic rollback attempted but previous release health check also failed." >&2
  fi
  return 1
}

ACTIVATION_STARTED=0
activation_error() {
  local rc=$?
  if [[ "$ACTIVATION_STARTED" == "1" ]]; then
    rollback "unexpected activation command failure (exit $rc)" || true
  fi
  exit "$rc"
}
trap activation_error ERR

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

systemctl stop tikcentral-fleet.timer >/dev/null 2>&1 || true
systemctl stop tikcentral-fleet.service >/dev/null 2>&1 || true
ACTIVATION_STARTED=1

if [[ -d "$CURRENT" && ! -L "$CURRENT" ]]; then
  mv "$CURRENT" "$PREVIOUS"
fi
switch_current "$RELEASE"
install_runtime_files "$RELEASE"
systemctl daemon-reload
systemctl enable tikcentral tikcentral-winbox-proxy tikcentral-backup.timer tikcentral-fleet.timer >/dev/null
systemctl disable --now tikcentral-enroll-ui >/dev/null 2>&1 || true
systemctl restart tikcentral
systemctl restart tikcentral-winbox-proxy
systemctl restart caddy
systemctl start tikcentral-backup.timer
systemctl restart tikcentral-fleet.timer

if ! wait_health 20; then
  journalctl -u tikcentral -n 120 --no-pager >&2 || true
  rollback "application /healthz did not recover" || true
  exit 1
fi

for PATH_TO_CHECK in /enroll /routers /guardian /operations /rescue /changes /audit; do
  CODE="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$PATH_TO_CHECK" || true)"
  if [[ "$CODE" != "200" && "$CODE" != "303" ]]; then
    rollback "$PATH_TO_CHECK returned HTTP $CODE" || true
    exit 1
  fi
done
for ASSET_PATH in /static/opticable-icon.png /static/opticable-logo-light.svg /static/opticable-logo-dark.svg; do
  CODE="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$ASSET_PATH" || true)"
  if [[ "$CODE" != "200" ]]; then
    rollback "$ASSET_PATH returned HTTP $CODE" || true
    exit 1
  fi
done
CADDY_CODE="$(curl -ksS --resolve "$DOMAIN:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$DOMAIN/operations" || true)"
if [[ "$CADDY_CODE" != "200" && "$CADDY_CODE" != "303" ]]; then
  rollback "Caddy /operations returned HTTP $CADDY_CODE" || true
  exit 1
fi

ACTIVATION_STARTED=0
trap - ERR

current_real="$(readlink -f "$CURRENT")"
kept=0
while IFS= read -r dir; do
  [[ -d "$dir" ]] || continue
  [[ "$(basename "$dir")" =~ ^[0-9a-f]{12}$ ]] || continue
  if [[ "$dir" == "$current_real" || "$dir" == "$PREVIOUS" ]]; then
    continue
  fi
  kept=$((kept + 1))
  if (( kept >= KEEP_RELEASES - 1 )); then
    rm -rf "$dir"
  fi
done < <(find "$RELEASES" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | cut -d' ' -f2-)

jq . /tmp/tikcentral-update-health.json
rm -f /tmp/tikcentral-update-health.json

echo
echo "Tikcentral updated successfully."
echo "Active release: $SHORT_SHA"
echo "Release path: $RELEASE"
echo "Previous release: ${PREVIOUS:-none}"
echo "Atomic rollback: enabled for all activation failures"
echo "Runtime: consolidated Operations + Rescue + UI"
echo "Read/change scheduler isolation: enabled"
echo "Structured operational errors: enabled"
echo "Central runtime settings: enabled"
echo "Stable updater command: sudo tikcentral-update"
echo "Per-release Python environment: ready"
echo "Access Guardian: enabled"
echo "Montréal UI time: enabled"
echo "Operations Caddy check: HTTP $CADDY_CODE"
echo "Persistent state preserved: users, routers, WireGuard assignments, authorized IPs and router configuration."
echo "Pre-update database backup: $DB_BACKUP"
echo "Dashboard: https://$DOMAIN/"
