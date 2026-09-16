import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core

app = core.app


def portal_page(title: str, body: str, user=None, active: str = "") -> HTMLResponse:
    nav = ""
    if user:
        links = [
            ("dashboard", "/", "Dashboard"),
            ("routers", "/routers", "Routers"),
            ("enroll", "/enroll", "Enrollment"),
            ("users", "/admin/users", "Users"),
            ("settings", "/settings", "Settings"),
        ]
        items = "".join(
            f'<a class="{"active" if active == key else ""}" href="{href}">{label}</a>'
            for key, href, label in links
        )
        nav = (
            f'<nav class="topnav">{items}</nav>'
            f'<div class="account"><span>{html.escape(user["email"])}</span>'
            f'<form method="post" action="/logout"><button>Logout</button></form></div>'
        )

    return HTMLResponse(
        f'''<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} - Tikcentral</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2d;--line:#26324c;--text:#ecf2ff;--muted:#92a0bb;--ok:#46d17d;--bad:#68758d;--accent:#5b86e5;--danger:#b94c5a}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}}main{{max-width:1700px;margin:0 auto;padding:24px 20px 48px}}a{{color:#9dbaff;text-decoration:none}}
.shell-head{{display:flex;align-items:center;gap:18px;flex-wrap:wrap;padding:8px 0 22px;border-bottom:1px solid var(--line);margin-bottom:24px}}.brand{{min-width:180px}}.brand h1{{font-size:23px;margin:0}}.sub,.muted{{color:var(--muted)}}
.topnav{{display:flex;gap:7px;align-items:center;flex:1;flex-wrap:wrap}}.topnav a{{padding:8px 11px;border-radius:8px;color:#b8c5df}}.topnav a:hover,.topnav a.active{{background:#1a2846;color:#fff}}.account{{display:flex;align-items:center;gap:10px;color:var(--muted);flex-wrap:wrap}}
h2{{margin:0 0 14px}}.panel{{overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:14px;margin-bottom:22px}}.pad{{padding:18px}}table{{width:100%;border-collapse:collapse;min-width:1000px}}th,td{{padding:12px 14px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}}th{{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}}code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px}}.online{{background:var(--ok)}}.offline{{background:var(--bad)}}button{{border:1px solid #395182;background:#1a2846;color:var(--text);border-radius:7px;padding:8px 12px;cursor:pointer}}button.primary{{background:#294d8f}}button.danger{{border-color:#6f3340;background:#3e2027}}input,select{{background:#0d1528;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:9px 10px}}.inline{{display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.login{{max-width:430px;margin:90px auto}}.error{{background:#3a2028;border:1px solid #6f3340;padding:10px;border-radius:8px;margin-bottom:12px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:22px}}.card{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}}.card .value{{font-size:28px;font-weight:700;margin-top:5px}}.searchbar{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}}.searchbar input{{min-width:340px;max-width:680px;width:60%}}.badge{{padding:3px 8px;border-radius:999px;background:#1a2846;color:#b8c5df;font-size:12px}}
@media(max-width:780px){{main{{padding:16px 12px}}.account{{width:100%;justify-content:space-between}}.searchbar input{{width:100%;min-width:0}}}}
</style></head><body><main><div class="shell-head"><div class="brand"><h1>Tikcentral</h1><div class="sub">MikroTik remote management</div></div>{nav}</div>{body}</main></body></html>'''
    )


# Existing pages call core.page at request time, so replacing it gives the whole
# authenticated application the same navigation shell without duplicating auth logic.
core.page = portal_page


@app.get("/routers", response_class=HTMLResponse)
def portal_routers(request: Request):
    user = core.require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    peers = core.wireguard_peers()
    with core.db() as conn:
        rows = conn.execute(
            """SELECT id,site_name,identity,serial,model,routeros_version,routerboot_version,
                      public_key,vpn_ip,public_winbox_port,enabled,created_at
               FROM routers ORDER BY site_name COLLATE NOCASE,id"""
        ).fetchall()

    rendered = []
    online_count = 0
    for row in rows:
        live = peers.get(row["public_key"], {})
        is_online = bool(live.get("online")) and bool(row["enabled"])
        if is_online:
            online_count += 1
        public_ip = live.get("public_ip") or "-"
        latest = live.get("latest_handshake", 0)
        last_seen = (
            datetime.fromtimestamp(latest, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            if latest else "Never"
        )
        remote_winbox = f'{core.PUBLIC_HOSTNAME}:{row["public_winbox_port"]}'
        vpn_winbox = f'{row["vpn_ip"]}:8291'
        searchable = " ".join(
            str(x or "") for x in [
                row["site_name"], row["identity"], row["serial"], row["model"],
                row["routeros_version"], row["routerboot_version"], public_ip,
                row["vpn_ip"], remote_winbox, "online" if is_online else "offline",
            ]
        ).lower()
        rendered.append(
            f'''<tr class="router-row" data-search="{html.escape(searchable)}">
<td><span class="dot {'online' if is_online else 'offline'}"></span>{'Online' if is_online else 'Offline'}</td>
<td><strong>{html.escape(row['site_name'] or '-')}</strong></td>
<td>{html.escape(row['identity'] or '-')}</td><td>{html.escape(row['model'] or '-')}</td>
<td>{html.escape(row['serial'] or '-')}</td><td>{html.escape(row['routeros_version'] or '-')}</td>
<td>{html.escape(row['routerboot_version'] or '-')}</td><td><code>{html.escape(public_ip)}</code></td>
<td><code>{html.escape(row['vpn_ip'])}</code></td><td><code>{html.escape(remote_winbox)}</code></td>
<td><code>{html.escape(vpn_winbox)}</code></td><td>{'Enabled' if row['enabled'] else 'Disabled'}</td>
<td class="muted">{html.escape(last_seen)}</td></tr>'''
        )

    if not rendered:
        rendered.append('<tr><td colspan="13" class="muted">No routers enrolled yet.</td></tr>')

    body = f'''<div class="cards">
<div class="card"><div class="muted">Total routers</div><div class="value">{len(rows)}</div></div>
<div class="card"><div class="muted">Online</div><div class="value">{online_count}</div></div>
<div class="card"><div class="muted">Offline / disabled</div><div class="value">{len(rows)-online_count}</div></div>
</div>
<div class="panel pad"><div class="searchbar">
<input id="routerSearch" type="search" placeholder="Search site, identity, model, serial, IP, RouterOS, WinBox...">
<span id="routerCount" class="badge">{len(rows)} shown</span><a href="/enroll"><button class="primary">Enroll router</button></a>
</div><div class="muted">Search site name, identity, model, serial, public IP, VPN IP, RouterOS/RouterBOOT, status or Remote WinBox endpoint.</div></div>
<div class="panel"><table><thead><tr><th>Status</th><th>Site</th><th>Identity</th><th>Model</th><th>Serial</th><th>RouterOS</th><th>RouterBOOT</th><th>Public IP</th><th>VPN IP</th><th>Remote WinBox</th><th>VPN WinBox</th><th>State</th><th>Last handshake UTC</th></tr></thead><tbody>{''.join(rendered)}</tbody></table></div>
<script>
const input=document.getElementById('routerSearch');
const rows=[...document.querySelectorAll('.router-row')];
const count=document.getElementById('routerCount');
function filterRouters(){{const q=input.value.trim().toLowerCase();let shown=0;rows.forEach(r=>{{const show=!q||r.dataset.search.includes(q);r.style.display=show?'':'none';if(show)shown++;}});count.textContent=shown+' shown';}}
input.addEventListener('input',filterRouters);
</script>'''
    return portal_page("Routers", body, user, "routers")


@app.get("/settings", response_class=HTMLResponse)
def portal_settings(request: Request):
    user = core.require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with core.db() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_routers = conn.execute("SELECT COUNT(*) FROM routers").fetchone()[0]

    body = f'''<div class="panel pad"><h2>Settings</h2><div class="cards">
<div class="card"><div class="muted">Signed in as</div><div style="margin-top:8px"><strong>{html.escape(user['email'])}</strong></div></div>
<div class="card"><div class="muted">Users</div><div class="value">{total_users}</div><a href="/admin/users">Manage users</a></div>
<div class="card"><div class="muted">Routers</div><div class="value">{total_routers}</div><a href="/routers">Router inventory</a></div>
<div class="card"><div class="muted">Session duration</div><div class="value">{core.SESSION_DAYS}d</div></div></div>
<div class="inline"><a href="/account/password"><button class="primary">Change my password</button></a><a href="/admin/users"><button>Users</button></a><a href="/enroll"><button>Enrollment</button></a></div></div>
<div class="panel pad"><h2>System</h2><table style="min-width:0"><tbody>
<tr><td>Public hostname</td><td><code>{html.escape(core.PUBLIC_HOSTNAME)}</code></td></tr>
<tr><td>WireGuard endpoint</td><td><code>{html.escape(core.WG_ENDPOINT)}</code></td></tr>
<tr><td>Router VPN pool</td><td><code>{html.escape(str(core.WG_ROUTER_POOL))}</code></td></tr>
<tr><td>Remote WinBox port range</td><td><code>{core.WINBOX_PUBLIC_PORT_MIN}-{core.WINBOX_PUBLIC_PORT_MAX}</code></td></tr>
<tr><td>Enrollment token lifetime</td><td>{core.TOKEN_TTL_HOURS} hours</td></tr>
</tbody></table></div>'''
    return portal_page("Settings", body, user, "settings")
