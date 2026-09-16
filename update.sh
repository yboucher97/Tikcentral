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
# Older installs may contain router subdirectories created by root. This is a
# dedicated Tikcentral backup tree, so normalize ownership during deployment.
chown -R tikcentral:tikcentral "$ROUTER_BACKUP_DIR" 2>/dev/null || true
install -d -o tikcentral -g tikcentral -m 0750 /var/lib/tikcentral/router-backups
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

for BRAND_ASSET in \
  "$APP/app/static/opticable-logo-light.png" \
  "$APP/app/static/opticable-logo-dark.png" \
  "$APP/app/static/opticable-icon.png"; do
  [[ -s "$BRAND_ASSET" ]] || { echo "Missing Opticable UI asset: $BRAND_ASSET" >&2; exit 1; }
done

"$ROOT/venv/bin/python3" -m py_compile \
  "$APP/app/main.py" \
  "$APP/app/portal.py" \
  "$APP/app/entrypoint.py" \
  "$APP/app/fleet.py" \
  "$APP/app/fleet_runner.py" \
  "$APP/app/fleet_web.py" \
  "$APP/app/guardian.py" \
  "$APP/app/guardian_events.py" \
  "$APP/app/changes.py" \
  "$APP/app/events.py" \
  "$APP/app/backup_tiers.py" \
  "$APP/app/provisioning.py" \
  "$APP/app/performance_profile.py" \
  "$APP/app/interface_choices.py" \
  "$APP/app/enrollment_v2.py" \
  "$APP/app/enrollment_v3.py" \
  "$APP/app/operations.py" \
  "$APP/app/operations_safety.py" \
  "$APP/app/operations_stability.py" \
  "$APP/app/operations_compat.py" \
  "$APP/app/operations_safe_routes.py" \
  "$APP/app/operations_robust.py" \
  "$APP/app/rescue.py" \
  "$APP/app/rescue_v2.py" \
  "$APP/app/rescue_safe_routes.py" \
  "$APP/app/ui_time.py" \
  "$APP/app/ui_enhancements.py" \
  "$APP/app/branding.py" \
  "$APP/app/production.py" \
  "$APP/app/final.py" \
  "$APP/app/winbox_proxy.py"

set -a
source "$ENV_FILE"
set +a

ROUTES="$(cd "$APP" && "$ROOT/venv/bin/python3" -c 'from app.final import app; print("\n".join(sorted({r.path for r in app.routes})))')"
for REQUIRED_ROUTE in /enroll /enroll/generate /enroll/admin-credentials /routers /settings /automation /automation/command /automation/backup /automation/update/check /automation/update/install /ssh '/ssh/{router_id}' /guardian '/guardian/{router_id}/repair' /operations '/operations/{router_id}' '/operations/{router_id}/commission' '/operations/{router_id}/telemetry' '/operations/{router_id}/profile/{profile}' '/operations/{router_id}/backup/{tier}' '/operations/{router_id}/drift/check' '/operations/{router_id}/baseline' '/operations/{router_id}/update/check' '/operations/{router_id}/upgrade/{mode}' '/operations/{router_id}/routerboot' '/operations/{router_id}/approve-version' /rescue '/rescue/{router_id}/enable' '/rescue/{router_id}/disable' /changes '/changes/{router_id}' /audit '/audit/{router_id}' '/audit/{router_id}/normalize'; do
  if ! grep -Fxq "$REQUIRED_ROUTE" <<<"$ROUTES"; then
    echo "Required route $REQUIRED_ROUTE is missing from app.final." >&2
    echo "$ROUTES" >&2
    exit 1
  fi
done

# Verify every Operations POST action is the safe wrapper and appears exactly once.
cd "$APP"
"$ROOT/venv/bin/python3" - <<'PY'
from app.final import app
required = {
    "/operations/{router_id}/telemetry",
    "/operations/{router_id}/commission",
    "/operations/{router_id}/profile/{profile}",
    "/operations/{router_id}/backup/{tier}",
    "/operations/{router_id}/drift/check",
    "/operations/{router_id}/baseline",
    "/operations/{router_id}/update/check",
    "/operations/{router_id}/upgrade/{mode}",
    "/operations/{router_id}/routerboot",
    "/operations/{router_id}/approve-version",
}
for path in required:
    matches = [r for r in app.routes if getattr(r, "path", None) == path and "POST" in (getattr(r, "methods", set()) or set())]
    if len(matches) != 1:
        raise SystemExit(f"Operations route {path} has {len(matches)} POST handlers; expected exactly 1")
    if matches[0].endpoint.__module__ != "app.operations_safe_routes":
        raise SystemExit(f"Operations route {path} is not using app.operations_safe_routes")
PY

# The fleet timer is a separate Python process; verify it installs the same
# hardened telemetry implementation as the web process.
RUNNER_PROBE="$("$ROOT/venv/bin/python3" -c 'from app import fleet_runner, operations; print(operations.collect_telemetry.__module__)')"
if [[ "$RUNNER_PROBE" != "app.operations_stability" ]]; then
  echo "Fleet runner is not using hardened telemetry: $RUNNER_PROBE" >&2
  exit 1
fi

UI_CHECK="$("$ROOT/venv/bin/python3" -c 'from fastapi.responses import HTMLResponse; from app.ui_enhancements import enhance_response; print(enhance_response(HTMLResponse("<html><head></head><body><table><thead><tr><th>A</th></tr></thead><tbody><tr><td>1</td></tr></tbody></table></body></html>")).body.decode())')"
for UI_TEXT in 'tcGlobalSearch' 'tcTheme' 'tc-table-search' 'tikcentral:columns:' 'Light mode'; do
  if ! grep -Fq "$UI_TEXT" <<<"$UI_CHECK"; then
    echo "Tikcentral shared UI enhancement validation failed: missing $UI_TEXT" >&2
    exit 1
  fi
done

BRAND_CHECK="$("$ROOT/venv/bin/python3" -c 'from fastapi.responses import HTMLResponse; from app.branding import enhance_response; print(enhance_response(HTMLResponse("<html><head></head><body><div class=\"brand\"><h1>Tikcentral</h1><div class=\"sub\">MikroTik remote management</div></div></body></html>")).body.decode())')"
for BRAND_TEXT in '/static/opticable-logo-light.png' '/static/opticable-logo-dark.png' '/static/opticable-icon.png' 'opticable-brand-theme' 'tc-status-ok'; do
  if ! grep -Fq "$BRAND_TEXT" <<<"$BRAND_CHECK"; then
    echo "Opticable branding validation failed: missing $BRAND_TEXT" >&2
    exit 1
  fi
done

MANAGED_SCRIPT="$("$ROOT/venv/bin/python3" -c 'from app.production import managed_router_script_with_api_password; print(managed_router_script_with_api_password("scope-check", "scope-check-token"))')"
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

DEFAULT_SCRIPT="$("$ROOT/venv/bin/python3" -c 'from app.performance_profile import performance_ready_default_config_script; from app.enrollment_v2 import _apply_profile; print(_apply_profile(performance_ready_default_config_script("scope-check",12,4,500,500,80,40,"ether2"),"throughput"))')"
for REQUIRED_TEXT in 'Default WAN DHCP' 'Bell PPPoE - enter credentials onsite' 'Opticable FastTrack' 'Opticable RAW bad source' 'Opticable MSS clamp' 'OPT-QOS-UPLOAD' 'Performance profile active: Maximum throughput'; do
  if ! grep -Fq "$REQUIRED_TEXT" <<<"$DEFAULT_SCRIPT"; then
    echo "Opticable default provisioning profile failed validation: missing $REQUIRED_TEXT" >&2
    exit 1
  fi
done

"$ROOT/venv/bin/python3" -c 'from app.fleet import ensure_schema; ensure_schema()'
"$ROOT/venv/bin/python3" -c 'from app.guardian import ensure_schema; ensure_schema()'
"$ROOT/venv/bin/python3" -c 'from app.provisioning import ensure_schema; ensure_schema()'
"$ROOT/venv/bin/python3" -c 'from app.operations import ensure_schema; ensure_schema()'
"$ROOT/venv/bin/python3" -c 'from app.rescue import ensure_schema; ensure_schema()'

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
# Kill any one-shot fleet job that may still be running legacy code loaded before
# this deployment, then restart the timer so the next run imports the new code.
systemctl stop tikcentral-fleet.service >/dev/null 2>&1 || true
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

for PATH_TO_CHECK in /enroll /routers /automation /ssh /guardian /operations /rescue /changes /audit; do
  CODE="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$PATH_TO_CHECK" || true)"
  if [[ "$CODE" != "200" && "$CODE" != "303" ]]; then
    echo "Tikcentral $PATH_TO_CHECK failed directly on the application (HTTP $CODE)." >&2
    systemctl show tikcentral -p ExecStart --no-pager >&2 || true
    journalctl -u tikcentral -n 100 --no-pager >&2 || true
    exit 1
  fi
done

for STATIC_ASSET in /static/opticable-logo-light.png /static/opticable-logo-dark.png /static/opticable-icon.png; do
  STATIC_CODE="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080$STATIC_ASSET" || true)"
  if [[ "$STATIC_CODE" != "200" ]]; then
    echo "Tikcentral branding asset $STATIC_ASSET failed directly on the application (HTTP $STATIC_CODE)." >&2
    journalctl -u tikcentral -n 100 --no-pager >&2 || true
    exit 1
  fi
done

CADDY_CODE="$(curl -ksS --resolve "$DOMAIN:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$DOMAIN/operations" || true)"
if [[ "$CADDY_CODE" != "200" && "$CADDY_CODE" != "303" ]]; then
  echo "Tikcentral /operations failed through Caddy (HTTP $CADDY_CODE)." >&2
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
echo "Operations telemetry: hardened isolated probes (web + fleet runner)"
echo "Operations actions: router failures handled without HTTP 500 pages"
echo "Configuration drift: enabled (30-minute checks after baseline)"
echo "Serialized RouterOS upgrades: ready"
echo "Approved-version tracking: ready"
echo "Backup tiers: daily rotating + retained pre-change/commissioning"
echo "Router event timeline: ready"
echo "Static local rescue-port management: ready"
echo "Configuration change history: ready"
echo "Live router audit/normalization: ready"
echo "Searchable/sortable tables + saved column visibility: ready"
echo "Persistent light/dark UI mode: ready"
echo "Opticable branded light/dark logos, colors and status visuals: ready"
echo "Operations Caddy check: HTTP $CADDY_CODE"
echo "Persistent state preserved: users, routers, WireGuard assignments, authorized IPs and existing configuration."
echo "Pre-update backup: /var/backups/tikcentral/pre-update-$STAMP.db"
echo "Dashboard: https://$DOMAIN/"
echo "Routers: https://$DOMAIN/routers"
echo "Guardian: https://$DOMAIN/guardian"
echo "Operations: https://$DOMAIN/operations"
echo "Rescue: https://$DOMAIN/rescue"
echo "Changes: https://$DOMAIN/changes"
echo "Enrollment: https://$DOMAIN/enroll"
echo "Automation: https://$DOMAIN/automation"
echo "Web SSH: https://$DOMAIN/ssh"
echo "Audit: https://$DOMAIN/audit"
echo "Settings: https://$DOMAIN/settings"
