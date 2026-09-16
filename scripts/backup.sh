#!/usr/bin/env bash
set -euo pipefail

DB="/var/lib/tikcentral/tikcentral.db"
DEST="/var/backups/tikcentral"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DEST"
sqlite3 "$DB" ".backup '$DEST/tikcentral-$STAMP.db'"
find "$DEST" -type f -name 'tikcentral-*.db' -mtime +14 -delete
