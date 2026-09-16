#!/usr/bin/env bash
set -euo pipefail
source /etc/tikcentral/tikcentral.env
curl -fsS http://127.0.0.1:8080/admin/routers -H "X-API-Key: $ADMIN_API_KEY" | jq -r '
  (["ID","SITE","VPN IP","IDENTITY","SERIAL"] | @tsv),
  (.[] | [.id,.site_name,.vpn_ip,.identity,.serial] | @tsv)'
