"""Final Tikcentral production ASGI entrypoint."""

import html
import os

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import entrypoint
from app import fleet
from app import fleet_web
from app import main as core
from app import portal

app = fleet_web.app

_base_page = fleet_web._base_page


def production_page(title: str, body: str, user=None, active: str = "") -> HTMLResponse:
    response = _base_page(title, body, user, active)
    if not user:
        return response
    text = response.body.decode("utf-8")
    automation_cls = "active" if active == "automation" else ""
    ssh_cls = "active" if active == "ssh" else ""
    text = text.replace(
        "</nav>",
        f'<a class="{automation_cls}" href="/automation">Automation</a>'
        f'<a class="{ssh_cls}" href="/ssh">SSH</a></nav>',
        1,
    )
    return HTMLResponse(text, status_code=response.status_code)


portal.portal_page = production_page
core.page = production_page
fleet_web.fleet_page = production_page

_base_managed_script = portal.build_routeros_script


def managed_router_script_with_api_password(site_name: str, token: str) -> str:
    """Build an idempotent enrollment/update script.

    Re-running the script must reconcile Tikcentral-managed objects rather than
    creating additional interfaces, users, peers, routes or firewall rules.
    """
    script = _base_managed_script(site_name, token)

    # Direct SSH-key installation uses only user= and key=. Remove historical
    # key-owner= syntax and make replacement safe when no old key exists.
    script = script.replace(' key-owner="Tikcentral VPS"', '')
    script = script.replace(
        '/user ssh-keys remove [find where user="tikcentral"]',
        ':if ([:len [/user ssh-keys find where user="tikcentral"]] > 0) do={ /user ssh-keys remove [find where user="tikcentral"] }',
    )

    # Remove firewall creation emitted by older generator layers. A canonical
    # firewall reconciliation block is appended below.
    legacy_blocks = [
        ''':if ([:len [/ip/firewall/filter find where comment="Tikcentral relay WinBox"]] = 0) do={
    /ip/firewall/filter add chain=input action=accept in-interface=$wgName src-address=10.250.0.1 protocol=tcp dst-port=8291 place-before=0 comment="Tikcentral relay WinBox"
}''',
        ''':if ([:len [/ip/firewall/filter find where comment="Tikcentral management SSH API"]] = 0) do={
    /ip/firewall/filter add chain=input action=accept in-interface=$wgName src-address=10.250.0.1 protocol=tcp dst-port=22,8728 place-before=0 comment="Tikcentral management SSH API"
}''',
        ''':if ([:len [/ip/firewall/filter find where comment="Tikcentral admin TCP"]] = 0) do={
    /ip/firewall/filter add chain=input action=accept in-interface=$wgName src-address=10.250.254.0/24 protocol=tcp dst-port=22,8291 place-before=0 comment="Tikcentral admin TCP"
}''',
        ''':if ([:len [/ip/firewall/filter find where comment="Tikcentral admin ICMP"]] = 0) do={
    /ip/firewall/filter add chain=input action=accept in-interface=$wgName src-address=10.250.254.0/24 protocol=icmp place-before=0 comment="Tikcentral admin ICMP"
}''',
    ]
    for block in legacy_blocks:
        script = script.replace(block, "")

    password = os.getenv("TIKCENTRAL_ROUTER_API_PASSWORD", "").replace('"', "")
    lines = script.splitlines()
    insert_at = len(lines)
    if lines and lines[-1].strip() == "}":
        insert_at -= 1

    reconcile = [
        "",
        "# Reconcile Tikcentral-managed objects; safe to run repeatedly",
        ':local tcIf [/interface/wireguard find where name="opticable-wg"]',
        ':if ([:len $tcIf] = 0) do={ :error "Tikcentral WireGuard interface missing after enrollment" }',
        "",
        "# Remove every legacy/canonical Tikcentral firewall rule, then recreate exactly one of each",
        ':if ([:len [/ip/firewall/filter find where comment="Tikcentral relay WinBox"]] > 0) do={ /ip/firewall/filter remove [find where comment="Tikcentral relay WinBox"] }',
        ':if ([:len [/ip/firewall/filter find where comment="Tikcentral management SSH API"]] > 0) do={ /ip/firewall/filter remove [find where comment="Tikcentral management SSH API"] }',
        ':if ([:len [/ip/firewall/filter find where comment="Tikcentral management TCP"]] > 0) do={ /ip/firewall/filter remove [find where comment="Tikcentral management TCP"] }',
        ':if ([:len [/ip/firewall/filter find where comment="Tikcentral admin TCP"]] > 0) do={ /ip/firewall/filter remove [find where comment="Tikcentral admin TCP"] }',
        ':if ([:len [/ip/firewall/filter find where comment="Tikcentral admin ICMP"]] > 0) do={ /ip/firewall/filter remove [find where comment="Tikcentral admin ICMP"] }',
        '/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.0.1/32 protocol=tcp dst-port=22,8291,8728 place-before=0 comment="Tikcentral management TCP"',
        '/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.254.0/24 protocol=tcp dst-port=22,8291 place-before=0 comment="Tikcentral admin TCP"',
        '/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.254.0/24 protocol=icmp place-before=0 comment="Tikcentral admin ICMP"',
    ]

    if password:
        reconcile += [
            "",
            "# Reuse the existing Tikcentral user and update its managed API password",
            f'/user set [find where name="tikcentral"] password="{password}" group=full address=10.250.0.1/32 disabled=no comment="Tikcentral managed service"',
        ]

    reconcile += [
        ':put "Tikcentral reconciliation complete: existing managed objects reused/updated"',
    ]

    return "\n".join(lines[:insert_at] + reconcile + lines[insert_at:])


portal.build_routeros_script = managed_router_script_with_api_password


def _admin(request: Request):
    return core.require_web_admin(request)


@app.get("/ssh", response_class=HTMLResponse)
def ssh_router_list(request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with core.db() as conn:
        routers = conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled FROM routers ORDER BY site_name COLLATE NOCASE,id"
        ).fetchall()
    rows = "".join(
        f'''<tr><td>{html.escape(r['site_name'])}</td><td>{html.escape(r['identity'] or '-')}</td><td>{html.escape(r['model'] or '-')}</td><td><code>{html.escape(r['vpn_ip'])}</code></td><td>{'Enabled' if r['enabled'] else 'Disabled'}</td><td><a href="/ssh/{r['id']}"><button {'disabled' if not r['enabled'] else ''}>Open SSH console</button></a></td></tr>'''
        for r in routers
    ) or '<tr><td colspan="6" class="muted">No routers enrolled.</td></tr>'
    body = f'''<div class="panel pad"><h2>Web SSH</h2><div class="muted">Commands are executed from the Tikcentral VPS over the private WireGuard address using the managed SSH key. Each submitted command is a separate SSH command session.</div></div><div class="panel"><table><thead><tr><th>Site</th><th>Identity</th><th>Model</th><th>VPN IP</th><th>State</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>'''
    return production_page("SSH", body, user, "ssh")


@app.get("/ssh/{router_id}", response_class=HTMLResponse)
def ssh_console(router_id: int, request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with core.db() as conn:
        router = conn.execute("SELECT id,site_name,identity,model,vpn_ip,enabled FROM routers WHERE id=?", (router_id,)).fetchone()
    if not router:
        raise HTTPException(status_code=404, detail="router not found")
    csrf = core.csrf_token(request)
    body = f'''<div class="panel pad"><h2>SSH — {html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['identity'] or '')} · {html.escape(router['model'] or '')} · <code>{html.escape(router['vpn_ip'])}</code></div><form method="post" action="/ssh/{router_id}" style="margin-top:16px"><input type="hidden" name="csrf" value="{csrf}"><textarea name="command" style="width:100%;min-height:100px" placeholder="/system resource print" required></textarea><div class="inline" style="margin-top:10px"><button class="primary">Run command</button><a href="/ssh">Back to routers</a></div></form></div>'''
    return production_page("SSH Console", body, user, "ssh")


@app.post("/ssh/{router_id}", response_class=HTMLResponse)
async def ssh_console_run(router_id: int, request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request)
    core.require_csrf(request, data.get("csrf", ""))
    command = data.get("command", "").strip()
    if not command:
        raise HTTPException(status_code=400, detail="command required")
    with core.db() as conn:
        router = conn.execute("SELECT id,site_name,identity,model,vpn_ip,enabled FROM routers WHERE id=?", (router_id,)).fetchone()
    if not router or not router["enabled"]:
        raise HTTPException(status_code=404, detail="enabled router not found")
    try:
        output = fleet.ssh_exec(router["vpn_ip"], command, timeout=90)
        status = "Success"
    except Exception as exc:
        output = str(exc)
        status = "Error"
    csrf = core.csrf_token(request)
    body = f'''<div class="panel pad"><h2>SSH — {html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['identity'] or '')} · <code>{html.escape(router['vpn_ip'])}</code></div><div style="margin-top:14px"><strong>{status}</strong></div><pre style="white-space:pre-wrap;background:#0d1528;padding:14px;border-radius:8px;max-height:520px;overflow:auto">{html.escape(output or '(no output)')}</pre><form method="post" action="/ssh/{router_id}"><input type="hidden" name="csrf" value="{csrf}"><textarea name="command" style="width:100%;min-height:100px" placeholder="Next RouterOS command" required></textarea><div class="inline" style="margin-top:10px"><button class="primary">Run command</button><a href="/ssh">Back to routers</a></div></form></div>'''
    return production_page("SSH Console", body, user, "ssh")
