"""Static local rescue-port management.

No Netwatch, scheduler, or persistent RouterOS scripts are installed. Tikcentral
only configures a known local IP/DHCP service on an otherwise unused Ethernet
port, with a pre-change backup and access preflight.
"""

import html

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import fleet
from app import guardian
from app import main as core
from app import operations
from app import events

SCHEMA = """
CREATE TABLE IF NOT EXISTS router_rescue_ports (
    router_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    interface TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '10.255.255.1/24',
    updated_at TEXT NOT NULL DEFAULT ''
);
"""


def ensure_schema():
    with core.db() as conn:
        conn.executescript(SCHEMA)


def _router(router_id):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,model,vpn_ip,public_key,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _markers(output):
    data = {}
    for line in (output or "").splitlines():
        if line.startswith("TC|"):
            p = line.split("|", 2)
            if len(p) == 3:
                data[p[1]] = p[2].strip()
    return data


def enable_rescue(router_id: int, interface: str, created_by: str):
    if interface not in {"ether2", "ether3", "ether4", "ether5"}:
        raise ValueError("invalid rescue interface")
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    if not guardian.probe_router(router)["management_ok"]:
        raise RuntimeError("Guardian access preflight failed")
    check = fleet.ssh_exec(
        router["vpn_ip"],
        f':put ("TC|addresses|" . [/ip/address print count-only where interface={interface} comment!="Tikcentral rescue address"]); '
        f':put ("TC|dhcp|" . [/ip/dhcp-server print count-only where interface={interface} name!="Tikcentral-Rescue-DHCP"])',
        timeout=45,
    )
    m = _markers(check)
    if int(m.get("addresses", "0") or 0) > 0 or int(m.get("dhcp", "0") or 0) > 0:
        raise RuntimeError(f"{interface} already has non-rescue IP/DHCP configuration; Tikcentral will not overwrite it")
    operations.backup_router(router_id, "pre-change", created_by)
    command = f'''
/ip/dhcp-server remove [find where name="Tikcentral-Rescue-DHCP"];
/ip/dhcp-server/network remove [find where comment="Tikcentral rescue network"];
/ip/pool remove [find where name="Tikcentral-Rescue-Pool"];
/ip/address remove [find where comment="Tikcentral rescue address"];
/interface/list/member remove [find where comment="Tikcentral rescue LAN membership"];
/interface/list/member add interface={interface} list=LAN comment="Tikcentral rescue LAN membership";
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


def disable_rescue(router_id: int, created_by: str):
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    if not guardian.probe_router(router)["management_ok"]:
        raise RuntimeError("Guardian access preflight failed")
    operations.backup_router(router_id, "pre-change", created_by)
    command = r'''
/ip/dhcp-server remove [find where name="Tikcentral-Rescue-DHCP"];
/ip/dhcp-server/network remove [find where comment="Tikcentral rescue network"];
/ip/pool remove [find where name="Tikcentral-Rescue-Pool"];
/ip/address remove [find where comment="Tikcentral rescue address"];
/interface/list/member remove [find where comment="Tikcentral rescue LAN membership"];
:put "Tikcentral local rescue port disabled"
'''.strip()
    output = fleet.ssh_exec(router["vpn_ip"], command, timeout=60)
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_rescue_ports(router_id,enabled,interface,address,updated_at)
               VALUES(?,0,'','10.255.255.1/24',?)
               ON CONFLICT(router_id) DO UPDATE SET enabled=0,interface='',updated_at=excluded.updated_at""",
            (router_id, operations.now_iso()),
        )
    events.record(router_id, "rescue", "Static local rescue port disabled")
    return output


def register(app, page_func):
    ensure_schema()

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
            options = ''.join(f'<option value="ether{i}" {"selected" if r["rescue_interface"]==f"ether{i}" else ""}>ether{i}</option>' for i in range(2,6))
            enable = f'''<form method="post" action="/rescue/{r['id']}/enable" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><select name="interface">{options}</select><button>Enable / move rescue</button></form>'''
            disable = f'''<form method="post" action="/rescue/{r['id']}/disable" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><button class="danger" onclick="return confirm('Disable the static rescue port?')">Disable</button></form>'''
            status = f"Enabled · {r['rescue_interface']} · {r['rescue_address'] or '10.255.255.1/24'}" if r["rescue_enabled"] else "Disabled"
            body_rows.append(f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')} · {html.escape(r['vpn_ip'])}</div></td><td>{'Healthy' if r['management_ok'] else 'Degraded'}</td><td>{html.escape(status)}</td><td>{enable} {disable if r['rescue_enabled'] else ''}</td></tr>''')
        body = f'''<div class="panel pad"><h2>Local Rescue Ports</h2><div class="muted">Optional static recovery path. Tikcentral refuses to use a port that already has non-rescue IP/DHCP configuration. Enabled ports use 10.255.255.1/24 and hand out 10.255.255.100-200. No Netwatch or RouterOS scheduler/script is installed.</div></div><div class="panel"><table><thead><tr><th>Router</th><th>Access</th><th>Rescue</th><th>Action</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="4">No routers.</td></tr>'}</tbody></table></div>'''
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
        disable_rescue(router_id, user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse("/rescue", status_code=303)
