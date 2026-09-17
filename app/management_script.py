"""Canonical RouterOS management enrollment script generator.

This is the only place that builds Tikcentral's router-side management objects.
It is intentionally access-first and only reconciles Tikcentral-owned objects.
"""

from pathlib import Path

from app import settings


def _ros(value: str) -> str:
    return (value or "").replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")


def _ssh_public_key() -> str:
    path = Path(str(settings.SSH_KEY) + ".pub")
    if not path.is_file():
        return ""
    parts = path.read_text(encoding="utf-8").strip().split()
    return " ".join(parts[:2]) if len(parts) >= 2 else ""


def build_routeros_script(site_name: str, token: str) -> str:
    """Build one paste-safe, idempotent RouterOS 7 enrollment block."""
    domain = settings.WG_ENDPOINT.rsplit(":", 1)[0]
    site = _ros(site_name)
    enrollment_token = _ros(token)
    api_password = _ros(settings.ROUTER_API_PASSWORD)
    ssh_key = _ros(_ssh_public_key())

    ssh_key_block = ""
    if ssh_key:
        ssh_key_block = f'''
:if ([:len [/user ssh-keys find where user="tikcentral"]] > 0) do={{ /user ssh-keys remove [find where user="tikcentral"] }}
/user ssh-keys add user="tikcentral" key="{ssh_key}"
'''.strip()

    password_set = ""
    if api_password:
        password_set = f' password="{api_password}"'

    return f'''# Tikcentral enrollment for: {site_name}
# Paste this entire block into a RouterOS 7 terminal.
{{
:local token "{enrollment_token}"
:local apiUrl "https://{_ros(domain)}/api/enroll"
:local wgName "opticable-wg"

# Reuse the management interface if this script is run again.
:if ([:len [/interface/wireguard find where name=$wgName]] = 0) do={{
    /interface/wireguard add name=$wgName comment="Tikcentral management"
}}
:local wgId [/interface/wireguard find where name=$wgName]
:local pub [/interface/wireguard get $wgId public-key]
:local serial [/system/routerboard get serial-number]
:local identity [/system/identity get name]
:local model [/system/routerboard get model]
:local routerosVersion [/system/resource get version]
:local routerbootVersion [/system/routerboard get current-firmware]
:local body ("{{\\\"token\\\":\\\"" . $token . "\\\",\\\"public_key\\\":\\\"" . $pub . "\\\",\\\"serial\\\":\\\"" . $serial . "\\\",\\\"identity\\\":\\\"" . $identity . "\\\",\\\"model\\\":\\\"" . $model . "\\\",\\\"routeros_version\\\":\\\"" . $routerosVersion . "\\\",\\\"routerboot_version\\\":\\\"" . $routerbootVersion . "\\\"}}")
:local r [/tool/fetch url=$apiUrl http-method=post http-header-field="Content-Type: application/json" http-data=$body output=user as-value]
:local cfg [:deserialize from=json value=($r->"data")]
:local vpnIP ($cfg->"vpn_ip")
:local serverKey ($cfg->"server_public_key")
:local endpoint ($cfg->"endpoint")
:local allowedNet ($cfg->"allowed_network")
:local endpointHost [:pick $endpoint 0 [:find $endpoint ":"]]
:local endpointPort [:pick $endpoint ([:find $endpoint ":"] + 1) [:len $endpoint]]

# Reconcile Tikcentral address, peer and route without touching customer objects.
:if ([:len [/ip/address find where interface=$wgName and comment="Tikcentral management"]] > 0) do={{
    /ip/address set [find where interface=$wgName and comment="Tikcentral management"] address=($vpnIP . "/32")
}} else={{
    /ip/address add address=($vpnIP . "/32") interface=$wgName comment="Tikcentral management"
}}
:if ([:len [/interface/wireguard/peers find where interface=$wgName and comment="Tikcentral hub"]] > 0) do={{
    /interface/wireguard/peers set [find where interface=$wgName and comment="Tikcentral hub"] public-key=$serverKey endpoint-address=$endpointHost endpoint-port=$endpointPort allowed-address=$allowedNet persistent-keepalive=25
}} else={{
    /interface/wireguard/peers add interface=$wgName public-key=$serverKey endpoint-address=$endpointHost endpoint-port=$endpointPort allowed-address=$allowedNet persistent-keepalive=25 comment="Tikcentral hub"
}}
:if ([:len [/ip/route find where comment="Tikcentral management"]] > 0) do={{
    /ip/route set [find where comment="Tikcentral management"] dst-address=$allowedNet gateway=$wgName
}} else={{
    /ip/route add dst-address=$allowedNet gateway=$wgName comment="Tikcentral management"
}}

# Managed service identity. Its source is restricted to the Tikcentral hub.
:if ([:len [/user find where name="tikcentral"]] = 0) do={{
    /user add name="tikcentral" group=full address=10.250.0.1/32 disabled=no comment="Tikcentral managed service"{password_set}
}} else={{
    /user set [find where name="tikcentral"] group=full address=10.250.0.1/32 disabled=no comment="Tikcentral managed service"{password_set}
}}
{ssh_key_block}
:do {{ /ip/service set [find where name="api"] disabled=no address=10.250.0.1/32 }} on-error={{ :put "Tikcentral warning: could not enable/restrict API service" }}
:do {{ /ip/service set [find where name="winbox"] disabled=no }} on-error={{ :put "Tikcentral warning: could not enable WinBox" }}
:do {{ /ip/service set [find where name="ssh"] disabled=no }} on-error={{ :put "Tikcentral warning: could not enable SSH" }}

# Remove only historical/canonical Tikcentral-owned firewall rules, then recreate
# exactly one management rule set. Existing customer LAN access is preserved.
:foreach c in={{"Tikcentral relay WinBox";"Tikcentral management SSH API";"Tikcentral management TCP";"Tikcentral admin TCP";"Tikcentral admin ICMP"}} do={{
    :if ([:len [/ip/firewall/filter find where comment=$c]] > 0) do={{ /ip/firewall/filter remove [find where comment=$c] }}
}}
/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.0.1/32 protocol=tcp dst-port=22,8291,8728 place-before=0 comment="Tikcentral management TCP"
/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.254.0/24 protocol=tcp dst-port=22,8291 place-before=0 comment="Tikcentral admin TCP"
/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.254.0/24 protocol=icmp place-before=0 comment="Tikcentral admin ICMP"

:put ("Tikcentral enrolled: " . $vpnIP)
:put ("Remote WinBox: " . ($cfg->"remote_winbox"))
:put "Tikcentral reconciliation complete"
}}
'''
