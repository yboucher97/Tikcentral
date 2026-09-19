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
[[ "$KEEP_RELEASES" =~ ^[0-9]+$ ]] || KEEP_RELEASES=5
(( KEEP_RELEASES >= 2 && KEEP_RELEASES <= 50 )) || KEEP_RELEASES=5

[[ "$EUID" -eq 0 ]] || { echo "Run as root (use sudo)." >&2; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "Tikcentral is not installed: $ENV_FILE is missing. Run bootstrap.sh once first." >&2; exit 1; }
set -a
source "$ENV_FILE"
set +a
DB_FILE="${DB_PATH:-/var/lib/tikcentral/tikcentral.db}"
for cmd in git tar python3 sqlite3 curl jq caddy sudo visudo ssh-keygen systemctl runuser useradd ufw; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Required command is missing: $cmd" >&2; exit 1; }
done

mkdir -p "$RELEASES"
chmod 0755 "$ROOT" "$RELEASES"
install -d -o root -g tikcentral -m 0750 /var/backups/tikcentral
find /var/backups/tikcentral -maxdepth 1 -type f \( -name 'tikcentral-*.db' -o -name 'pre-update-*.db' \) -exec chown root:tikcentral {} + -exec chmod 0640 {} + 2>/dev/null || true

bootstrap_repository() {
  if [[ -d "$REPO" ]]; then return; fi
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
ACTIVATION_DB_BACKUP="/var/backups/tikcentral/pre-activation-$STAMP.db"
ENV_BACKUP="/var/backups/tikcentral/pre-update-$STAMP.env"

if [[ -f "$DB_FILE" ]]; then
  sqlite3 "$DB_FILE" ".backup '$DB_BACKUP'"
  chown root:tikcentral "$DB_BACKUP"
  chmod 0640 "$DB_BACKUP"
fi
cp -a "$ENV_FILE" "$ENV_BACKUP"

install -d -o root -g tikcentral -m 0750 "$SSH_DIR"
if [[ ! -f "$SSH_DIR/tikcentral_ed25519" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C 'tikcentral-vps' -f "$SSH_DIR/tikcentral_ed25519"
fi
chown root:tikcentral "$SSH_DIR/tikcentral_ed25519" "$SSH_DIR/tikcentral_ed25519.pub"
chmod 0640 "$SSH_DIR/tikcentral_ed25519"
chmod 0644 "$SSH_DIR/tikcentral_ed25519.pub"

install -d -o root -g tikcentral -m 0750 /var/backups/tikcentral
install -d -o tikcentral -g tikcentral -m 0750 "$ROUTER_BACKUP_DIR"
chown -R tikcentral:tikcentral "$ROUTER_BACKUP_DIR" || true
find "$ROUTER_BACKUP_DIR" -type d -exec chmod 0750 {} + 2>/dev/null || true
find "$ROUTER_BACKUP_DIR" -type f -exec chmod 0640 {} + 2>/dev/null || true
install -d -o tikcentral -g tikcentral -m 0750 /var/lib/tikcentral /var/lib/tikcentral/router-backups
if [[ ! -f /var/lib/tikcentral/known_hosts ]]; then
  install -o tikcentral -g tikcentral -m 0600 /dev/null /var/lib/tikcentral/known_hosts
else
  chown tikcentral:tikcentral /var/lib/tikcentral/known_hosts
  chmod 0600 /var/lib/tikcentral/known_hosts
fi

# Codex analysis runs as an unprivileged identity that is deliberately not a
# member of the tikcentral group, so it cannot read Tikcentral env/SSH secrets.
if ! id tikcentral-ai >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/tikcentral-ai --create-home --shell /usr/sbin/nologin tikcentral-ai
fi
install -d -o tikcentral-ai -g tikcentral-ai -m 0700 /var/lib/tikcentral-ai

ensure_env() {
  local key="$1" value="$2"
  grep -q "^${key}=" "$ENV_FILE" || printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
}
ensure_env TIKCENTRAL_ROUTER_USER tikcentral
ensure_env TIKCENTRAL_SSH_KEY /etc/tikcentral/ssh/tikcentral_ed25519
ensure_env TIKCENTRAL_KNOWN_HOSTS /var/lib/tikcentral/known_hosts
ensure_env ROUTER_BACKUP_DIR /var/backups/tikcentral/routers
ensure_env TIKCENTRAL_SSH_TIMEOUT 20
ensure_env TIKCENTRAL_FLEET_WORKERS 8
ensure_env TIKCENTRAL_TIMEZONE America/Toronto
ensure_env TIKCENTRAL_CODEX_HELPER /usr/local/sbin/tikcentral-codex-analyze
if ! grep -q '^ROUTER_BACKUP_PASSWORD=' "$ENV_FILE"; then printf 'ROUTER_BACKUP_PASSWORD=%s\n' "$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"; fi
if ! grep -q '^TIKCENTRAL_ROUTER_API_PASSWORD=' "$ENV_FILE"; then printf 'TIKCENTRAL_ROUTER_API_PASSWORD=%s\n' "$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> "$ENV_FILE"; fi
if ! grep -q '^TIKCENTRAL_PROVISIONING_KEY=' "$ENV_FILE"; then printf 'TIKCENTRAL_PROVISIONING_KEY=%s\n' "$(python3 -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())')" >> "$ENV_FILE"; fi
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

  "$RELEASE/.venv/bin/python3" -m compileall -q "$RELEASE/app" "$RELEASE/scripts"
  bash -n "$RELEASE/bootstrap.sh"
  bash -n "$RELEASE/update.sh"
  for file in "$RELEASE"/helpers/* "$RELEASE"/scripts/*.sh; do [[ -f "$file" ]] || continue; bash -n "$file"; done

  "$RELEASE/.venv/bin/python3" "$RELEASE/scripts/validate_packaging.py"
  sudo -u tikcentral bash -c "set -a; source '$ENV_FILE'; set +a; cd '$RELEASE'; '$RELEASE/.venv/bin/python3' scripts/validate_release.py"
  printf '%s\n' "$TARGET_SHA" > "$RELEASE/.tikcentral-validated"
fi

install_runtime_files() {
  local release="$1"
  chmod +x "$release/helpers/tikcentral-wg-peer" "$release/helpers/tikcentral-update" "$release/helpers/tikcentral-codex-analyze"
  install -o root -g root -m 0755 "$release/helpers/tikcentral-wg-peer" /usr/local/sbin/tikcentral-wg-peer
  install -o root -g root -m 0755 "$release/helpers/tikcentral-update" /usr/local/sbin/tikcentral-update
  install -o root -g root -m 0755 "$release/helpers/tikcentral-codex-analyze" /usr/local/sbin/tikcentral-codex-analyze
  printf 'tikcentral ALL=(root) NOPASSWD: /usr/local/sbin/tikcentral-wg-peer *\n' > /etc/sudoers.d/tikcentral-wg
  printf 'tikcentral ALL=(root) NOPASSWD: /usr/local/sbin/tikcentral-codex-analyze\n' > /etc/sudoers.d/tikcentral-ai
  chmod 0440 /etc/sudoers.d/tikcentral-wg /etc/sudoers.d/tikcentral-ai
  visudo -cf /etc/sudoers.d/tikcentral-wg >/dev/null
  visudo -cf /etc/sudoers.d/tikcentral-ai >/dev/null

  for unit in tikcentral.service tikcentral-winbox-proxy.service tikcentral-backup.service tikcentral-backup.timer tikcentral-fleet.service tikcentral-fleet.timer tikcentral-ai.service tikcentral-ai.timer; do
    [[ -f "$release/deploy/$unit" ]] || continue
    install -o root -g root -m 0644 "$release/deploy/$unit" "/etc/systemd/system/$unit"
  done
}

switch_current() {
  local target="$1" link="$ROOT/.current-next-$$"
  rm -f "$link"; ln -s "$target" "$link"
  if [[ -L "$CURRENT" ]]; then mv -Tf "$link" "$CURRENT"; elif [[ ! -e "$CURRENT" ]]; then mv "$link" "$CURRENT"; else rm -f "$link"; return 1; fi
}

wait_health() {
  local tries="${1:-20}" health_file="/tmp/tikcentral-update-health.json"
  for ((i=1; i<=tries; i++)); do
    if curl -fsS http://127.0.0.1:8080/healthz >"$health_file" 2>/dev/null && jq -e '.ok == true and .database == "ok" and .wireguard == "ok"' "$health_file" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

PREVIOUS=""
if [[ -L "$CURRENT" ]]; then PREVIOUS="$(readlink -f "$CURRENT")"; elif [[ -d "$CURRENT" ]]; then PREVIOUS="$RELEASES/legacy-$STAMP"; fi

rollback() {
  local reason="$1"
  trap - ERR
  echo "New release failed activation: $reason" >&2
  if [[ -z "$PREVIOUS" || ! -d "$PREVIOUS" ]]; then echo "No previous release is available for automatic rollback." >&2; return 1; fi
  systemctl stop tikcentral-ai.timer tikcentral-ai.service >/dev/null 2>&1 || true
  systemctl stop tikcentral-fleet.timer tikcentral-fleet.service >/dev/null 2>&1 || true
  systemctl stop tikcentral-backup.timer tikcentral-backup.service >/dev/null 2>&1 || true
  systemctl stop tikcentral-winbox-proxy tikcentral >/dev/null 2>&1 || true
  systemctl stop caddy >/dev/null 2>&1 || true
  if [[ -f "$ACTIVATION_DB_BACKUP" ]]; then
    rm -f "${DB_FILE}-wal" "${DB_FILE}-shm"
    install -o tikcentral -g tikcentral -m 0640 "$ACTIVATION_DB_BACKUP" "$DB_FILE"
  fi
  switch_current "$PREVIOUS" || true
  [[ -f "$PREVIOUS/deploy/tikcentral.service" ]] && install_runtime_files "$PREVIOUS"
  systemctl daemon-reload || true
  systemctl restart tikcentral || true
  systemctl restart tikcentral-winbox-proxy || true
  systemctl restart caddy || true
  systemctl start tikcentral-backup.timer >/dev/null 2>&1 || true
  systemctl restart tikcentral-fleet.timer >/dev/null 2>&1 || true
  if [[ -f "$PREVIOUS/deploy/tikcentral-ai.timer" ]]; then
    systemctl enable tikcentral-ai.timer >/dev/null 2>&1 || true
    systemctl restart tikcentral-ai.timer >/dev/null 2>&1 || true
  else
    systemctl disable --now tikcentral-ai.timer >/dev/null 2>&1 || true
  fi
  if wait_health 15; then echo "Automatic rollback succeeded: $PREVIOUS" >&2; else echo "Automatic rollback attempted but previous release health check also failed." >&2; fi
  return 1
}

ACTIVATION_STARTED=0
activation_error() {
  local rc=$?
  if [[ "$ACTIVATION_STARTED" == "1" ]]; then rollback "unexpected activation command failure (exit $rc)" || true; fi
  exit "$rc"
}
trap activation_error ERR

set -a
source "$ENV_FILE"
set +a
DOMAIN="${PUBLIC_HOSTNAME:-${WG_ENDPOINT%:*}}"
[[ -n "$DOMAIN" ]] || { echo "Could not determine Tikcentral hostname from $ENV_FILE" >&2; exit 1; }
# Keep host firewall rules aligned with runtime-configurable management ranges.
UFW_STATE="/var/lib/tikcentral/ufw-runtime.env"
CURRENT_ROUTER_POOL="${WG_ROUTER_POOL:-10.250.1.0/24}"
CURRENT_WINBOX_RANGE="${WINBOX_PUBLIC_PORT_MIN:-20000}:${WINBOX_PUBLIC_PORT_MAX:-49999}"
PREVIOUS_ROUTER_POOL=""
PREVIOUS_WINBOX_RANGE=""
if [[ -r "$UFW_STATE" ]]; then
  # shellcheck disable=SC1090
  source "$UFW_STATE"
  PREVIOUS_ROUTER_POOL="${TIKCENTRAL_UFW_ROUTER_POOL:-}"
  PREVIOUS_WINBOX_RANGE="${TIKCENTRAL_UFW_WINBOX_RANGE:-}"
fi
# Add the desired rules before deleting obsolete ones. If an add fails, the
# currently working access rules remain in place and this pre-activation update
# can stop safely.
ufw allow "$CURRENT_WINBOX_RANGE/tcp" >/dev/null
ufw route allow in on wg0 out on wg0 from 10.250.254.0/24 to "$CURRENT_ROUTER_POOL" >/dev/null
if [[ -n "$PREVIOUS_WINBOX_RANGE" && "$PREVIOUS_WINBOX_RANGE" != "$CURRENT_WINBOX_RANGE" ]]; then
  ufw delete allow "$PREVIOUS_WINBOX_RANGE/tcp" >/dev/null 2>&1 || true
elif [[ -z "$PREVIOUS_WINBOX_RANGE" && "$CURRENT_WINBOX_RANGE" != "20000:49999" ]]; then
  ufw delete allow "20000:49999/tcp" >/dev/null 2>&1 || true
fi
if [[ -n "$PREVIOUS_ROUTER_POOL" && "$PREVIOUS_ROUTER_POOL" != "$CURRENT_ROUTER_POOL" ]]; then
  ufw route delete allow in on wg0 out on wg0 from 10.250.254.0/24 to "$PREVIOUS_ROUTER_POOL" >/dev/null 2>&1 || true
elif [[ -z "$PREVIOUS_ROUTER_POOL" && "$CURRENT_ROUTER_POOL" != "10.250.1.0/24" ]]; then
  ufw route delete allow in on wg0 out on wg0 from 10.250.254.0/24 to 10.250.1.0/24 >/dev/null 2>&1 || true
fi
cat > "$UFW_STATE" <<EOF
TIKCENTRAL_UFW_ROUTER_POOL=$CURRENT_ROUTER_POOL
TIKCENTRAL_UFW_WINBOX_RANGE=$CURRENT_WINBOX_RANGE
EOF
chown root:tikcentral "$UFW_STATE"
chmod 0640 "$UFW_STATE"
CADDY_TMP="$(mktemp /tmp/tikcentral-caddy.XXXXXX)"
if [[ -n "${ACME_EMAIL:-}" ]]; then
  cat > "$CADDY_TMP" <<EOF
{
    email $ACME_EMAIL
}

$DOMAIN {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-For {remote_host}
    }
}
EOF
else
  cat > "$CADDY_TMP" <<EOF
$DOMAIN {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-For {remote_host}
    }
}
EOF
fi
caddy fmt --overwrite "$CADDY_TMP" >/dev/null
caddy validate --adapter caddyfile --config "$CADDY_TMP"
install -o root -g root -m 0644 "$CADDY_TMP" /etc/caddy/Caddyfile
rm -f "$CADDY_TMP"

ACTIVATION_STARTED=1
# Quiesce every Tikcentral process that can touch SQLite before schema evolution.
systemctl stop tikcentral-ai.timer tikcentral-ai.service >/dev/null 2>&1 || true
systemctl stop tikcentral-fleet.timer tikcentral-fleet.service >/dev/null 2>&1 || true
systemctl stop tikcentral-backup.timer tikcentral-backup.service >/dev/null 2>&1 || true
systemctl stop tikcentral-winbox-proxy tikcentral >/dev/null 2>&1 || true
systemctl stop caddy >/dev/null 2>&1 || true

# Preserve a legacy non-symlink installation before any operation that may need
# rollback. Modern installations already have PREVIOUS pointing at a release.
if [[ -d "$CURRENT" && ! -L "$CURRENT" ]]; then mv "$CURRENT" "$PREVIOUS"; fi

if [[ -f "$DB_FILE" ]]; then
  sqlite3 "$DB_FILE" ".backup '$ACTIVATION_DB_BACKUP'"
  chown root:tikcentral "$ACTIVATION_DB_BACKUP"
  chmod 0640 "$ACTIVATION_DB_BACKUP"
fi

# Apply the new schema only while the old runtime is stopped. Any activation
# failure restores the exact pre-migration activation snapshot in rollback().
sudo -u tikcentral bash -c "set -a; source '$ENV_FILE'; set +a; cd '$RELEASE'; '$RELEASE/.venv/bin/python3' -c 'from app import migrations; migrations.migrate()'"

switch_current "$RELEASE"
install_runtime_files "$RELEASE"

systemctl disable --now tikcentral-enroll-ui >/dev/null 2>&1 || true
rm -f /etc/systemd/system/tikcentral-enroll-ui.service

systemctl daemon-reload
systemctl enable tikcentral tikcentral-winbox-proxy tikcentral-backup.timer tikcentral-fleet.timer tikcentral-ai.timer >/dev/null
systemctl restart tikcentral
systemctl restart tikcentral-winbox-proxy
# Keep Caddy offline until local activation validation has passed. This prevents
# user writes from landing in the new database and then being lost if rollback
# restores the pre-activation snapshot.
# Seed a real scheduled-format database backup immediately after activation.
# The daily timer remains the ongoing schedule; this avoids a false "no scheduled
# backup" state until the next 03:15 timer window.
if ! systemctl start tikcentral-backup.service; then
  systemctl status tikcentral-backup.service --no-pager -l >&2 || true
  journalctl -u tikcentral-backup.service -n 80 --no-pager >&2 || true
  rollback "database backup seed service failed" || true
  exit 1
fi
systemctl start tikcentral-backup.timer
systemctl restart tikcentral-fleet.timer
systemctl restart tikcentral-ai.timer

if ! wait_health 20; then
  journalctl -u tikcentral -n 120 --no-pager >&2 || true
  rollback "application health check did not recover with database and WireGuard healthy" || true
  exit 1
fi

# Refresh backup verification while public HTTPS remains offline. Record full
# self-health only after Caddy is successfully back online.
sudo -u tikcentral bash -c "set -a; source '$ENV_FILE'; set +a; cd '$CURRENT'; '$CURRENT/.venv/bin/python3' -c 'from app import system_health; system_health.verify_backups()'"

for path in /enroll /routers /guardian /operations /rescue /changes /audit /automation /ssh; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$path" || true)"
  if [[ "$code" != "200" && "$code" != "303" ]]; then rollback "$path returned HTTP $code" || true; exit 1; fi
done

mapfile -t ASSET_PATHS < <(sudo -u tikcentral bash -c "set -a; source '$ENV_FILE'; set +a; cd '$CURRENT'; '$CURRENT/.venv/bin/python3' -c 'from app import settings; [print(v) for v in settings.ASSETS.values()]'")
for asset_path in "${ASSET_PATHS[@]}"; do
  code="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$asset_path" || true)"
  if [[ "$code" != "200" ]]; then rollback "$asset_path returned HTTP $code" || true; exit 1; fi
done

systemctl restart caddy
CADDY_CODE="$(curl -ksS --resolve "$DOMAIN:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$DOMAIN/operations" || true)"
if [[ "$CADDY_CODE" != "200" && "$CADDY_CODE" != "303" ]]; then rollback "Caddy /operations returned HTTP $CADDY_CODE" || true; exit 1; fi

# Now that public HTTPS is healthy, persist a complete self-health sample.
sudo -u tikcentral bash -c "set -a; source '$ENV_FILE'; set +a; cd '$CURRENT'; '$CURRENT/.venv/bin/python3' -c 'from app import system_health; system_health.record_health()'"

ACTIVATION_STARTED=0
trap - ERR

current_real="$(readlink -f "$CURRENT")"
kept=0
while IFS= read -r dir; do
  [[ -d "$dir" ]] || continue
  [[ "$(basename "$dir")" =~ ^[0-9a-f]{12}$ ]] || continue
  if [[ "$dir" == "$current_real" || "$dir" == "$PREVIOUS" ]]; then continue; fi
  kept=$((kept + 1))
  if (( kept >= KEEP_RELEASES - 1 )); then rm -rf "$dir"; fi
done < <(find "$RELEASES" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | cut -d' ' -f2-)

if [[ "$PREVIOUS" != "$RELEASES"/legacy-* ]]; then
  rm -rf "$ROOT/venv"
  find "$RELEASES" -mindepth 1 -maxdepth 1 -type d -name 'legacy-*' -exec rm -rf {} + 2>/dev/null || true
fi

UPDATE_BACKUP_KEEP="${TIKCENTRAL_UPDATE_BACKUP_KEEP:-20}"
[[ "$UPDATE_BACKUP_KEEP" =~ ^[0-9]+$ ]] || UPDATE_BACKUP_KEEP=20
(( UPDATE_BACKUP_KEEP >= 2 )) || UPDATE_BACKUP_KEEP=2
for pattern in 'pre-update-*.db' 'pre-activation-*.db' 'pre-update-*.env'; do
  mapfile -t files < <(find /var/backups/tikcentral -maxdepth 1 -type f -name "$pattern" -printf '%T@ %p\n' | sort -nr | cut -d' ' -f2-)
  if (( ${#files[@]} > UPDATE_BACKUP_KEEP )); then printf '%s\0' "${files[@]:UPDATE_BACKUP_KEEP}" | xargs -0r rm -f; fi
done

jq . /tmp/tikcentral-update-health.json
rm -f /tmp/tikcentral-update-health.json

echo
echo "Tikcentral updated successfully."
echo "Active release: $SHORT_SHA"
echo "Release path: $RELEASE"
echo "Previous release: ${PREVIOUS:-none}"
echo "Atomic rollback: enabled for activation failures"
echo "Release validation: passed"
echo "Central settings/schema/UI/RouterOS execution: enforced"
echo "Stable updater: sudo tikcentral-update"
echo "Access Guardian: enabled"
echo "Codex AI worker: enabled (authenticate the isolated tikcentral-ai account once before use)"
echo "Caddy /operations: HTTP $CADDY_CODE"
echo "Persistent state preserved: users, routers, WireGuard assignments, authorized IPs and router configuration."
echo "Pre-update database backup: $DB_BACKUP"
echo "Dashboard: https://$DOMAIN/"