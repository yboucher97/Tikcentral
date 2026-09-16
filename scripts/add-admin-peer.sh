#!/usr/bin/env bash
set -euo pipefail

NAME="${1:-}"
PUB="${2:-}"
IP="${3:-}"
[[ -n "$NAME" && -n "$PUB" && -n "$IP" ]] || { echo "usage: sudo $0 'Name' '<public-key>' 10.250.254.2" >&2; exit 2; }
[[ "$EUID" -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

python3 - "$IP" <<'PY'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
net = ipaddress.ip_network('10.250.254.0/24')
assert ip in net and ip not in (net.network_address, net.broadcast_address)
PY
[[ "$PUB" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "invalid WireGuard public key" >&2; exit 2; }

wg set wg0 peer "$PUB" allowed-ips "$IP/32"
wg-quick save wg0
SERVER_PUB="$(cat /etc/wireguard/server.pub)"
source /etc/tikcentral/tikcentral.env

echo "Added admin peer: $NAME ($IP)"
cat <<EOF

[Interface]
PrivateKey = <PRIVATE KEY THAT STAYS ON THIS DEVICE>
Address = $IP/32

[Peer]
PublicKey = $SERVER_PUB
Endpoint = $WG_ENDPOINT
AllowedIPs = 10.250.0.0/16
PersistentKeepalive = 25
EOF
