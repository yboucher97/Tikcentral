"""Expanded rescue-port UI supporting ether1-10 and sfp-sfpplus1-24."""

import html

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import interface_choices
from app import main as core
from app import rescue


def enable_rescue(router_id: int, interface: str, created_by: str):
    if interface not in interface_choices.INTERFACE_SET:
        raise ValueError("invalid rescue interface")
    router = rescue._router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    from app import fleet, guardian, operations, events
    if not guardian.probe_router(router)["management_ok"]:
        raise RuntimeError("Guardian access preflight failed")

    check = fleet.ssh_exec(
        router["vpn_ip"],
        f':put ("TC|addresses|" . [/ip/address print count-only where interface={interface} comment!="Tikcentral rescue address"]); '
        f':put ("TC|dhcp_server|" . [/ip/dhcp-server print count-only where interface={interface} name!="Tikcentral-Rescue-DHCP"]); '
        f':put ("TC|dhcp_client|" . [/ip/dhcp-client print count-only where interface={interface}]); '
        f':put ("TC|pppoe|" . [/interface/pppoe-client print count-only where interface={interface}]); '
        f':put ("TC|vlans|" . [/interface/vlan print count-only where interface={interface}]); '
        f':put ("TC|bridge_ports|" . [/interface/bridge/port print count-only where interface={interface}]); '
        f':put ("TC|wan_member|" . [/interface/list/member print count-only where interface={interface} list=WAN])',
        timeout=45,
    )
    m = rescue._markers(check)
    blockers = {
        "IP address": int(m.get("addresses", "0") or 0),
        "DHCP server": int(m.get("dhcp_server", "0") or 0),
        "DHCP client": int(m.get("dhcp_client", "0") or 0),
        "PPPoE client": int(m.get("pppoe", "0") or 0),
        "VLAN parent": int(m.get("vlans", "0") or 0),
        "bridge membership": int(m.get("bridge_ports", "0") or 0),
        "WAN membership": int(m.get("wan_member", "0") or 0),
    }
    active = [name for name, count in blockers.items() if count > 0]
    if active:
        raise RuntimeError(f"{interface} is already in use ({', '.join(active)}); Tikcentral will not repurpose it as a rescue port")

    operations.backup_router(router_id, "pre-change", created_by)
    command = f'''
/ip/dhcp-server remove [find where name="Tikcentral-Rescue-DHCP"];
/ip/dhcp-server/network remove [find where comment="Tikcentral rescue network"];
/ip/pool remove [find where name="Tikcentral-Rescue-Pool"];
/ip/address remove [find where comment="Tikcentral rescue address"];
/interface/list/member remove [find where comment="Tikcentral rescue LAN membership"];
:if ([:len [/interface/list/member find where interface={interface} list=LAN]] = 0) do={{ /interface/list/member add interface={interface} list=LAN comment="Tikcentral rescue LAN membership" }};
/ip/address add address=10.255.255.1/24 interface={interface} comment="Tikcentral rescue address";
/ip/pool add name="Tikcentral-Rescue-Pool" ranges=10.255.255.100-10.255.255.200;
/ip/dhcp-server/network add address=10.255.255.0/24 gateway=10.255.255.1 dns-server=1.1.1.1 comment="Tikcentral rescue network";
/ip/dhcp-server add name="Tikcentral-Rescue-DHCP" interface={interface} address-pool="Tikcentral-Rescue-Pool" disabled=no;
:put "Tikcentral local rescue port enabled on {interface}"
'''.strip()
    output = fleet.ssh_exec(router["vpn_ip"], command, timeout=60)
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_rescue_ports(router_id,enabled,interface,address,updated_at)
               VALUES(?,1,?,'10.255.255.1/24',?)
               ON CONFLICT(router_id) DO UPDATE SET enabled=1,interface=excluded.interface,address=excluded.address,updated_at=excluded.updated_at""",
            (router_id, interface, operations.now_iso()),
        )
    events.record(router_id, "rescue", f"Static local rescue port enabled on {interface}", "10.255.255.1/24 with DHCP 10.255.255.100-200")
    return output


def register(app, page_func):
    rescue.ensure_schema()
    app.router.routes[:] = [r for r in app.router.routes if getattr(r, "path", None) not in {"/rescue", "/rescue/{router_id}/enable", "/rescue/{router_id}/disable"}]

    @app.get("/rescue", response_class=HTMLResponse)
    def rescue_page(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        csrf = core.csrf_token(request)
        with core.db() as conn:
            rows = conn.execute(
                """SELECT r.id,r.site_name,r.model,r.vpn_ip,a.management_ok,
                          p.enabled rescue_enabled,p.interface rescue_interface,p.address rescue_address
                   FROM routers r
                   LEFT JOIN router_access_state a ON a.router_id=r.id
                   LEFT JOIN router_rescue_ports p ON p.router_id=r.id
                   WHERE r.enabled=1 ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()
        body_rows = []
        for r in rows:
            options = interface_choices.options_html(r["rescue_interface"] or "ether5")
            enable = f'''<form method="post" action="/rescue/{r['id']}/enable" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><select name="interface">{options}</select><button>Enable / move rescue</button></form>'''
            disable = f'''<form method="post" action="/rescue/{r['id']}/disable" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><button class="danger" onclick="return confirm('Disable the static rescue port?')">Disable</button></form>'''
            status = f"Enabled · {r['rescue_interface']} · {r['rescue_address'] or '10.255.255.1/24'}" if r["rescue_enabled"] else "Disabled"
            body_rows.append(f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')} · {html.escape(r['vpn_ip'])}</div></td><td>{'Healthy' if r['management_ok'] else 'Degraded'}</td><td>{html.escape(status)}</td><td>{enable} {disable if r['rescue_enabled'] else ''}</td></tr>''')
        body = f'''<div class="panel pad"><h2>Local Rescue Ports</h2><div class="muted">Available choices: ether1–ether10 and sfp-sfpplus1–sfp-sfpplus24. Tikcentral refuses to repurpose interfaces already used by IP, DHCP, PPPoE, VLANs, a bridge, or the WAN list. Rescue uses 10.255.255.1/24 with DHCP 10.255.255.100-200.</div></div><div class="panel"><table><thead><tr><th>Router</th><th>Access</th><th>Rescue</th><th>Action</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="4">No routers.</td></tr>'}</tbody></table></div>'''
        return page_func("Rescue Ports", body, user, "rescue")

    @app.post("/rescue/{router_id}/enable")
    async def rescue_enable(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        enable_rescue(router_id, data.get("interface", "ether5"), user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse("/rescue", status_code=303)

    @app.post("/rescue/{router_id}/disable")
    async def rescue_disable(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        rescue.disable_rescue(router_id, user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse("/rescue", status_code=303)
