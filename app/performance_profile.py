"""Opticable E50 performance-ready provisioning profiles.

Fresh-router provisioning always stages conservative RAW, MSS clamp, CAKE/FQ-CoDel,
QoS classification and tenant queues. Throughput is the default active profile;
Fairness/QoS can be selected at provisioning or switched later by Operations.
"""

from app import provisioning

PROFILE_LABELS = {
    "throughput": "Maximum throughput — FastTrack ON, QoS staged OFF",
    "fairness": "Fairness / QoS — FastTrack OFF, CAKE + tenant shaping ON",
}


def _performance_block(wan_down: int, wan_up: int) -> str:
    qos_down = max(10, int(wan_down * 0.95))
    qos_up = max(10, int(wan_up * 0.95))
    return f'''
# ----------------------------------------------------------
# E50 performance-ready profile
# Default: RAW prefilter ON, FastTrack ON, QoS OFF
# ----------------------------------------------------------
:if ([:len [/ip/firewall/address-list find where list="Opticable_BAD_SRC" and address="127.0.0.0/8"]] = 0) do={{ /ip/firewall/address-list add list=Opticable_BAD_SRC address=127.0.0.0/8 comment="Loopback cannot arrive from wire" }}
:if ([:len [/ip/firewall/address-list find where list="Opticable_BAD_SRC" and address="224.0.0.0/4"]] = 0) do={{ /ip/firewall/address-list add list=Opticable_BAD_SRC address=224.0.0.0/4 comment="Multicast cannot be a source" }}
:if ([:len [/ip/firewall/address-list find where list="Opticable_BAD_SRC" and address="240.0.0.0/4"]] = 0) do={{ /ip/firewall/address-list add list=Opticable_BAD_SRC address=240.0.0.0/4 comment="Reserved source range" }}
:if ([:len [/ip/firewall/address-list find where list="Opticable_BAD_SRC" and address="255.255.255.255"]] = 0) do={{ /ip/firewall/address-list add list=Opticable_BAD_SRC address=255.255.255.255 comment="Invalid source broadcast" }}

:if ([:len [/ip/firewall/raw find where comment="Opticable RAW DHCP"]] = 0) do={{ /ip/firewall/raw add chain=prerouting action=accept protocol=udp src-port=68 dst-port=67 comment="Opticable RAW DHCP" }}
:if ([:len [/ip/firewall/raw find where comment="Opticable RAW LAN fast accept"]] = 0) do={{ /ip/firewall/raw add chain=prerouting action=accept in-interface-list=LAN comment="Opticable RAW LAN fast accept" }}
:if ([:len [/ip/firewall/raw find where comment="Opticable RAW bad source"]] = 0) do={{ /ip/firewall/raw add chain=prerouting action=drop in-interface-list=WAN src-address-list=Opticable_BAD_SRC comment="Opticable RAW bad source" }}
:if ([:len [/ip/firewall/raw find where comment="Opticable RAW UDP port zero"]] = 0) do={{ /ip/firewall/raw add chain=prerouting action=drop in-interface-list=WAN protocol=udp port=0 comment="Opticable RAW UDP port zero" }}
:if ([:len [/ip/firewall/raw find where comment="Opticable RAW TCP port zero"]] = 0) do={{ /ip/firewall/raw add chain=prerouting action=drop in-interface-list=WAN protocol=tcp port=0 comment="Opticable RAW TCP port zero" }}
:if ([:len [/ip/firewall/raw find where comment="Opticable RAW WAN DNS to router"]] = 0) do={{ /ip/firewall/raw add chain=prerouting action=drop in-interface-list=WAN protocol=udp dst-port=53 comment="Opticable RAW WAN DNS to router" }}

:if ([:len [/ip/firewall/mangle find where comment="Opticable MSS clamp"]] = 0) do={{ /ip/firewall/mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu protocol=tcp tcp-flags=syn passthrough=yes comment="Opticable MSS clamp" }}

:if ([:len [/queue/type find where name="OPT-CAKE-UP"]] = 0) do={{ /queue/type add name=OPT-CAKE-UP kind=cake cake-ack-filter=filter cake-diffserv=diffserv4 cake-flowmode=dual-srchost cake-nat=yes cake-overhead=50 cake-rtt-scheme=internet }}
:if ([:len [/queue/type find where name="OPT-CAKE-DOWN"]] = 0) do={{ /queue/type add name=OPT-CAKE-DOWN kind=cake cake-diffserv=diffserv4 cake-flowmode=dual-dsthost cake-nat=yes cake-overhead=50 cake-rtt-scheme=internet }}
:if ([:len [/queue/type find where name="OPT-FQ-CODEL"]] = 0) do={{ /queue/type add name=OPT-FQ-CODEL kind=fq-codel fq-codel-ecn=no fq-codel-limit=1000 }}

:if ([:len [/ip/firewall/mangle find where comment="Opticable QoS mark upload"]] = 0) do={{ /ip/firewall/mangle add chain=prerouting in-interface-list=LAN packet-mark=no-mark action=mark-packet new-packet-mark=OPT-QOS-UP passthrough=no disabled=yes comment="Opticable QoS mark upload" }}
:if ([:len [/ip/firewall/mangle find where comment="Opticable QoS mark download"]] = 0) do={{ /ip/firewall/mangle add chain=prerouting in-interface-list=WAN packet-mark=no-mark action=mark-packet new-packet-mark=OPT-QOS-DOWN passthrough=no disabled=yes comment="Opticable QoS mark download" }}
:if ([:len [/ip/firewall/mangle find where comment="Opticable QoS Teams WebRTC"]] = 0) do={{ /ip/firewall/mangle add chain=prerouting in-interface-list=TENANT_VLAN protocol=udp dst-port=3478-3481 action=change-dscp new-dscp=34 passthrough=yes disabled=yes comment="Opticable QoS Teams WebRTC" }}
:if ([:len [/ip/firewall/mangle find where comment="Opticable QoS small QUIC"]] = 0) do={{ /ip/firewall/mangle add chain=prerouting protocol=udp dst-port=443 connection-bytes=0-2000000 action=change-dscp new-dscp=40 passthrough=yes disabled=yes comment="Opticable QoS small QUIC" }}
:if ([:len [/ip/firewall/mangle find where comment="Opticable QoS small HTTPS"]] = 0) do={{ /ip/firewall/mangle add chain=prerouting protocol=tcp dst-port=443 connection-bytes=0-2000000 action=change-dscp new-dscp=40 passthrough=yes disabled=yes comment="Opticable QoS small HTTPS" }}
:if ([:len [/ip/firewall/mangle find where comment="Opticable QoS bulk TCP"]] = 0) do={{ /ip/firewall/mangle add chain=prerouting protocol=tcp connection-bytes=20000000-0 action=change-dscp new-dscp=8 passthrough=yes disabled=yes comment="Opticable QoS bulk TCP" }}
:if ([:len [/ip/firewall/mangle find where comment="Opticable QoS bulk UDP"]] = 0) do={{ /ip/firewall/mangle add chain=prerouting protocol=udp connection-bytes=20000000-0 action=change-dscp new-dscp=8 passthrough=yes disabled=yes comment="Opticable QoS bulk UDP" }}
:if ([:len [/ip/firewall/mangle find where comment="Opticable QoS gaming"]] = 0) do={{ /ip/firewall/mangle add chain=prerouting protocol=udp port=30000-45000 action=change-dscp new-dscp=32 passthrough=yes disabled=yes comment="Opticable QoS gaming" }}

:if ([:len [/queue/tree find where name="OPT-QOS-UPLOAD"]] = 0) do={{ /queue/tree add name=OPT-QOS-UPLOAD parent=global packet-mark=OPT-QOS-UP max-limit={qos_up}M queue=OPT-CAKE-UP disabled=yes comment="Opticable QoS upload - {qos_up}M" }}
:if ([:len [/queue/tree find where name="OPT-QOS-DOWNLOAD"]] = 0) do={{ /queue/tree add name=OPT-QOS-DOWNLOAD parent=global packet-mark=OPT-QOS-DOWN max-limit={qos_down}M queue=OPT-CAKE-DOWN disabled=yes comment="Opticable QoS download - {qos_down}M" }}

:put "Performance profile ready: FastTrack active; RAW active; QoS/mangle staged disabled"
'''.strip()


def performance_ready_default_config_script(site_name: str, vlan_count: int, lan_count: int,
                                            wan_down: int, wan_up: int, tenant_down: int,
                                            tenant_up: int, vlan_parent: str) -> str:
    script = provisioning.default_config_script(
        site_name, vlan_count, lan_count, wan_down, wan_up,
        tenant_down, tenant_up, vlan_parent,
    )
    script = script.replace(
        'comment="Opticable tenant cap"',
        'disabled=yes comment="Opticable tenant cap - QoS profile disabled"',
    )
    block = _performance_block(wan_down, wan_up)
    head, sep, tail = script.rpartition("\n}")
    if not sep:
        return script + "\n" + block + "\n"
    return head + "\n\n" + block + sep + tail


def apply_profile(script: str, profile: str) -> str:
    if profile not in PROFILE_LABELS:
        raise ValueError("invalid performance profile")
    if profile == "fairness":
        commands = r'''
# Selected performance profile: FAIRNESS / QOS
/ip/firewall/filter set [find where comment="Opticable FastTrack"] disabled=yes
/ip/firewall/mangle set [find where comment="Opticable QoS mark upload"] disabled=no
/ip/firewall/mangle set [find where comment="Opticable QoS mark download"] disabled=no
/ip/firewall/mangle set [find where comment="Opticable QoS Teams WebRTC"] disabled=no
/ip/firewall/mangle set [find where comment="Opticable QoS small QUIC"] disabled=no
/ip/firewall/mangle set [find where comment="Opticable QoS small HTTPS"] disabled=no
/ip/firewall/mangle set [find where comment="Opticable QoS bulk TCP"] disabled=no
/ip/firewall/mangle set [find where comment="Opticable QoS bulk UDP"] disabled=no
/ip/firewall/mangle set [find where comment="Opticable QoS gaming"] disabled=no
/queue/tree set [find where name="OPT-QOS-UPLOAD"] disabled=no
/queue/tree set [find where name="OPT-QOS-DOWNLOAD"] disabled=no
/queue/simple set [find where comment~"Opticable tenant cap"] disabled=no
:put "Performance profile active: Fairness/QoS; RAW and MSS remain active"
'''.strip()
    else:
        commands = r'''
# Selected performance profile: MAXIMUM THROUGHPUT
/ip/firewall/filter set [find where comment="Opticable FastTrack"] disabled=no
/ip/firewall/mangle set [find where comment~"^Opticable QoS "] disabled=yes
/queue/tree set [find where name~"^OPT-QOS-"] disabled=yes
/queue/simple set [find where comment~"Opticable tenant cap"] disabled=yes
:put "Performance profile active: Maximum throughput; RAW and MSS remain active"
'''.strip()
    head, sep, tail = script.rpartition("\n}")
    if sep:
        return head + "\n\n" + commands + sep + tail
    return script + "\n\n" + commands + "\n"
