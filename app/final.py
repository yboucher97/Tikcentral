"""Tikcentral final production entrypoint with live audit and Access Guardian."""

import html

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import changes
from app import enrollment_v2
from app import fleet
from app import guardian
from app import main as core
from app import portal
from app import production

app = production.app

_base_page = production.production_page


def final_page(title: str, body: str, user=None, active: str = "") -> HTMLResponse:
    response = _base_page(title, body, user, active)
    if not user:
        return response
    text = response.body.decode("utf-8")
    audit_cls = "active" if active == "audit" else ""
    guardian_cls = "active" if active == "guardian" else ""
    changes_cls = "active" if active == "changes" else ""
    text = text.replace(
        "</nav>",
        f'<a class="{guardian_cls}" href="/guardian">Guardian</a>'
        f'<a class="{changes_cls}" href="/changes">Changes</a>'
        f'<a class="{audit_cls}" href="/audit">Audit</a></nav>',
        1,
    )
    return HTMLResponse(text, status_code=response.status_code)


portal.portal_page = final_page
core.page = final_page


def _admin(request: Request):
    return core.require_web_admin(request)


def _router(router_id: int):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


@app.get("/audit", response_class=HTMLResponse)
def audit_index(request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with core.db() as conn:
        routers = conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled FROM routers ORDER BY site_name COLLATE NOCASE,id"
        ).fetchall()
    rows = "".join(
        f'''<tr><td>{html.escape(r['site_name'])}</td><td>{html.escape(r['identity'] or '-')}</td><td>{html.escape(r['model'] or '-')}</td><td><code>{html.escape(r['vpn_ip'])}</code></td><td>{'Enabled' if r['enabled'] else 'Disabled'}</td><td><a href="/audit/{r['id']}"><button {'disabled' if not r['enabled'] else ''}>Audit configuration</button></a></td></tr>'''
        for r in routers
    ) or '<tr><td colspan="6" class="muted">No routers enrolled.</td></tr>'
    body = f'''<div class="panel pad"><h2>Router Audit</h2><div class="muted">Live, read-only audit over the private WireGuard connection. Configuration export uses <code>show-sensitive=no</code>.</div></div><div class="panel"><table><thead><tr><th>Site</th><th>Identity</th><th>Model</th><th>VPN IP</th><th>State</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>'''
    return final_page("Audit", body, user, "audit")


AUDIT_COMMAND = '''/system resource print; /system identity print; /ip service print; /user print; /user ssh-keys print; /interface/wireguard print; /interface/wireguard/peers print; /ip/address print where interface="opticable-wg"; /ip/route print where comment~"Tikcentral"; /ip/firewall/filter print detail where comment~"Tikcentral"; /ip/firewall/nat print detail where comment~"Tikcentral"; /export show-sensitive=no'''


@app.get("/audit/{router_id}", response_class=HTMLResponse)
def audit_router(router_id: int, request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise HTTPException(status_code=404, detail="enabled router not found")
    try:
        output = fleet.ssh_exec(router["vpn_ip"], AUDIT_COMMAND, timeout=120)
        status = "Audit completed"
    except Exception as exc:
        output = str(exc)
        status = "Audit failed"
    csrf = core.csrf_token(request)
    body = f'''<div class="panel pad"><h2>{html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['identity'] or '')} · {html.escape(router['model'] or '')} · <code>{html.escape(router['vpn_ip'])}</code></div><div style="margin-top:14px"><strong>{status}</strong></div><div class="inline" style="margin-top:14px"><form method="post" action="/audit/{router_id}/normalize"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="confirm" value="NORMALIZE"><button class="primary">Normalize Tikcentral rules</button></form><a href="/audit"><button>Back</button></a></div><div class="muted" style="margin-top:10px">Normalize removes only firewall filter rules with Tikcentral-owned comments, then recreates the canonical management/admin rules. Other firewall rules are untouched.</div></div><div class="panel pad"><pre style="white-space:pre-wrap;background:#0d1528;padding:14px;border-radius:8px;max-height:75vh;overflow:auto">{html.escape(output or '(no output)')}</pre></div>'''
    return final_page("Router Audit", body, user, "audit")


NORMALIZE_COMMAND = '''
:local tc [/ip/firewall/filter find where comment~"^Tikcentral "];
:if ([:len $tc] > 0) do={ /ip/firewall/filter remove $tc };
/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.0.1/32 protocol=tcp dst-port=22,8291,8728 place-before=0 comment="Tikcentral management TCP";
/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.254.0/24 protocol=tcp dst-port=22,8291 place-before=0 comment="Tikcentral admin TCP";
/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.254.0/24 protocol=icmp place-before=0 comment="Tikcentral admin ICMP";
/ip/firewall/filter print detail where comment~"^Tikcentral "
'''.strip()


@app.post("/audit/{router_id}/normalize", response_class=HTMLResponse)
async def normalize_router(router_id: int, request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request)
    core.require_csrf(request, data.get("csrf", ""))
    if data.get("confirm") != "NORMALIZE":
        raise HTTPException(status_code=400, detail="confirmation required")
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise HTTPException(status_code=404, detail="enabled router not found")
    try:
        output = fleet.ssh_exec(router["vpn_ip"], NORMALIZE_COMMAND, timeout=90)
        status = "Tikcentral firewall rules normalized"
    except Exception as exc:
        output = str(exc)
        status = "Normalization failed"
    body = f'''<div class="panel pad"><h2>{html.escape(router['site_name'])}</h2><strong>{html.escape(status)}</strong><div class="inline" style="margin-top:14px"><a href="/audit/{router_id}"><button class="primary">Run audit again</button></a><a href="/audit"><button>Back</button></a></div></div><div class="panel pad"><pre style="white-space:pre-wrap;background:#0d1528;padding:14px;border-radius:8px;max-height:520px;overflow:auto">{html.escape(output or '(no output)')}</pre></div>'''
    return final_page("Normalize Tikcentral", body, user, "audit")


guardian.register(app, final_page)
changes.register(app, final_page)
enrollment_v2.register(app, final_page)
