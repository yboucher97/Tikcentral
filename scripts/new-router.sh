#!/usr/bin/env bash
set -euo pipefail
SITE="${1:-}"
[[ -n "$SITE" ]] || { echo "usage: $0 'Site Name'" >&2; exit 2; }
source /etc/tikcentral/tikcentral.env
TOKEN_JSON="$("$(dirname "$0")/new-token.sh" "$SITE")"
TOKEN="$(jq -r .token <<<"$TOKEN_JSON")"
DOMAIN="${WG_ENDPOINT%:*}"

cat <<EOF
# Tikcentral enrollment for: $SITE
# Paste into a RouterOS 7 terminal.
:local token "$TOKEN"
:local apiUrl "https://$DOMAIN/api/enroll"
:local wgName "opticable-wg"

:if ([:len [/interface/wireguard find where name=\$wgName]] = 0) do={
    /interface/wireguard add name=\$wgName comment="Tikcentral management"
}

:local wgId [/interface/wireguard find where name=\$wgName]
:local pub [/interface/wireguard get \$wgId public-key]
:local serial [/system/routerboard get serial-number]
:local identity [/system/identity get name]
:local body ("{\\\"token\\\":\\\"" . \$token . "\\\",\\\"public_key\\\":\\\"" . \$pub . "\\\",\\\"serial\\\":\\\"" . \$serial . "\\\",\\\"identity\\\":\\\"" . \$identity . "\\\"}")
:local r [/tool/fetch url=\$apiUrl http-method=post http-header-field="Content-Type: application/json" http-data=\$body output=user as-value]
:local cfg [:deserialize from=json value=(\$r->"data")]
:local vpnIP (\$cfg->"vpn_ip")
:local serverKey (\$cfg->"server_public_key")
:local endpoint (\$cfg->"endpoint")
:local allowedNet (\$cfg->"allowed_network")
:local endpointHost [:pick \$endpoint 0 [:find \$endpoint ":"]]
:local endpointPort [:pick \$endpoint ([:find \$endpoint ":"] + 1) [:len \$endpoint]]

:if ([:len [/ip/address find where interface=\$wgName]] = 0) do={
    /ip/address add address=(\$vpnIP . "/32") interface=\$wgName comment="Tikcentral management"
}
:if ([:len [/interface/wireguard/peers find where interface=\$wgName and public-key=\$serverKey]] = 0) do={
    /interface/wireguard/peers add interface=\$wgName public-key=\$serverKey endpoint-address=\$endpointHost endpoint-port=\$endpointPort allowed-address=\$allowedNet persistent-keepalive=25 comment="Tikcentral hub"
}
:if ([:len [/ip/route find where dst-address=\$allowedNet and gateway=\$wgName]] = 0) do={
    /ip/route add dst-address=\$allowedNet gateway=\$wgName comment="Tikcentral management"
}
:if ([:len [/ip/firewall/filter find where comment="Tikcentral relay WinBox"]] = 0) do={
    /ip/firewall/filter add chain=input action=accept in-interface=\$wgName src-address=10.250.0.1 protocol=tcp dst-port=8291 place-before=0 comment="Tikcentral relay WinBox"
}
:if ([:len [/ip/firewall/filter find where comment="Tikcentral admin TCP"]] = 0) do={
    /ip/firewall/filter add chain=input action=accept in-interface=\$wgName src-address=10.250.254.0/24 protocol=tcp dst-port=22,8291 place-before=0 comment="Tikcentral admin TCP"
}
:if ([:len [/ip/firewall/filter find where comment="Tikcentral admin ICMP"]] = 0) do={
    /ip/firewall/filter add chain=input action=accept in-interface=\$wgName src-address=10.250.254.0/24 protocol=icmp place-before=0 comment="Tikcentral admin ICMP"
}
:put ("Tikcentral enrolled: " . \$vpnIP)
:put ("Remote WinBox: " . (\$cfg->"remote_winbox"))
EOF
