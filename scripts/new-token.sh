#!/usr/bin/env bash
set -euo pipefail
SITE="${1:-}"
[[ -n "$SITE" ]] || { echo "usage: $0 'Site Name'" >&2; exit 2; }
source /etc/tikcentral/tikcentral.env
curl -fsS -X POST http://127.0.0.1:8080/admin/tokens \
  -H "X-API-Key: $ADMIN_API_KEY" \
  -H 'Content-Type: application/json' \
  --data "$(jq -nc --arg site "$SITE" '{site_name:$site}')"
