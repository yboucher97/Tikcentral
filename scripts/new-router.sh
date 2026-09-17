#!/usr/bin/env bash
set -euo pipefail

SITE="${1:-}"
[[ -n "$SITE" ]] || { echo "usage: $0 'Site Name'" >&2; exit 2; }
CURRENT="/opt/tikcentral/current"
ENV_FILE="/etc/tikcentral/tikcentral.env"
[[ -f "$ENV_FILE" ]] || { echo "Missing $ENV_FILE" >&2; exit 1; }
[[ -x "$CURRENT/.venv/bin/python3" ]] || { echo "Tikcentral release environment is unavailable." >&2; exit 1; }

set -a
source "$ENV_FILE"
set +a
TOKEN_JSON="$("$(dirname "$0")/new-token.sh" "$SITE")"
TOKEN="$(jq -r .token <<<"$TOKEN_JSON")"
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || { echo "Could not create enrollment token." >&2; exit 1; }

export TIKCENTRAL_CLI_SITE="$SITE"
export TIKCENTRAL_CLI_TOKEN="$TOKEN"
cd "$CURRENT"
exec "$CURRENT/.venv/bin/python3" - <<'PY'
import os
from app import management_script, provisioning

site = os.environ["TIKCENTRAL_CLI_SITE"]
token = os.environ["TIKCENTRAL_CLI_TOKEN"]
parts = [management_script.build_routeros_script(site, token)]
user, password = provisioning.get_admin_credentials()
if user and password:
    parts.append(provisioning.personal_admin_block(user, password))
print("\n\n".join(parts))
PY
