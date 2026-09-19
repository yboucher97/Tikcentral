#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/tikcentral/tikcentral.env"
DEST="/var/backups/tikcentral"
[[ -r "$ENV_FILE" ]] || { echo "Tikcentral environment file is missing: $ENV_FILE" >&2; exit 1; }

set -a
# Root-owned configuration used by Tikcentral services.
source "$ENV_FILE"
set +a

DB="${DB_PATH:-/var/lib/tikcentral/tikcentral.db}"
RETENTION_DAYS="${TIKCENTRAL_DB_BACKUP_RETENTION_DAYS:-14}"
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || { echo "Invalid TIKCENTRAL_DB_BACKUP_RETENTION_DAYS" >&2; exit 1; }
(( RETENTION_DAYS >= 1 && RETENTION_DAYS <= 3650 )) || { echo "Database backup retention must be 1-3650 days" >&2; exit 1; }
[[ -f "$DB" ]] || { echo "Tikcentral database is missing: $DB" >&2; exit 1; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -o root -g tikcentral -m 0750 "$DEST"
OUT="$DEST/tikcentral-$STAMP.db"
sqlite3 "$DB" ".backup '$OUT'"
chown root:tikcentral "$OUT"
chmod 0640 "$OUT"
find "$DEST" -maxdepth 1 -type f -name 'tikcentral-*.db' -mtime "+$RETENTION_DAYS" -delete
