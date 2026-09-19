"""Core inventory and settings web routes."""

import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import fleet_health
from app import main as core
from app import settings
from app import ui

app = core.app


@app.get("/routers", response_class=HTMLResponse)
def routers_page(request: Request):
    user = core.require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    peers = core.wireguard_peers()
    health = fleet_health.all_states()
    with core.db() as conn:
        rows = conn.execute(
            """SELECT id,site_name,identity,serial,model,routeros_version,routerboot_version,
                      public_key,vpn_ip,public_winbox_port,enabled,created_at
               FROM routers ORDER BY site_name COLLATE NOCASE,id"""
        ).fetchall()

    rendered = []
    for row in rows:
        live = peers.get(row["public_key"], {})
        public_ip = live.get("public_ip") or "-"
        latest = int(live.get("latest_handshake", 0) or 0)
        last_seen = datetime.fromtimestamp(latest, timezone.utc).isoformat() if latest else "Never"
        remote_winbox = f'{settings.PUBLIC_HOSTNAME}:{row["public_winbox_port"]}' if row["public_winbox_port"] else "-"
        item_health = health.get(row["id"])
        state = item_health.state if item_health else ("Disabled" if not row["enabled"] else "Unknown")
        detail = item_health.detail if item_health else ""
        actions = f'<a href="/operations/{row["id"]}"><button>Open</button></a> <a href="/ai/{row["id"]}"><button class="primary">AI Analysis</button></a>' if row["enabled"] else '<span class="muted">Disabled</span>'
        rendered.append(
            f'''<tr><td>{html.escape(state)}<div class="muted">{html.escape(detail)}</div></td>
<td><strong>{html.escape(row['site_name'] or '-')}</strong></td>
<td>{html.escape(row['identity'] or '-')}</td><td>{html.escape(row['model'] or '-')}</td>
<td>{html.escape(row['serial'] or '-')}</td><td>{html.escape(row['routeros_version'] or '-')}</td>
<td>{html.escape(row['routerboot_version'] or '-')}</td><td><code>{html.escape(public_ip)}</code></td>
<td><code>{html.escape(row['vpn_ip'])}</code></td><td><code>{html.escape(remote_winbox)}</code></td>
<td><code>{html.escape(row['vpn_ip'])}:8291</code></td><td>{'Enabled' if row['enabled'] else 'Disabled'}</td>
<td class="muted">{html.escape(last_seen)}</td><td>{actions}</td></tr>'''
        )
    if not rendered:
        rendered.append('<tr><td colspan="14">No routers enrolled yet.</td></tr>')

    counts = fleet_health.counts()
    cards = ''.join(
        f'<div class="card"><div class="muted">{html.escape(label)}</div><div class="value">{count}</div></div>'
        for label, count in sorted(counts.items())
    )
    body = f'''<div class="cards"><div class="card"><div class="muted">Total routers</div><div class="value">{len(rows)}</div></div>{cards}</div>
<div class="panel pad"><div class="inline"><a href="/enroll"><button class="primary">Enroll router</button></a><span class="muted">Fleet state comes from Guardian, active changes, drift, commissioning and upgrade state.</span></div></div>
<div class="panel"><table data-default-hidden="4,6,7,10"><thead><tr><th>Health</th><th>Site</th><th>Identity</th><th>Model</th><th>Serial</th><th>RouterOS</th><th>RouterBOOT</th><th>Public IP</th><th>VPN IP</th><th>Remote WinBox</th><th>VPN WinBox</th><th>State</th><th>Last handshake</th><th>Actions</th></tr></thead><tbody>{''.join(rendered)}</tbody></table></div>'''
    return ui.page("Routers", body, user, "routers")


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
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
<div class="card"><div class="muted">Session duration</div><div class="value">{settings.SESSION_DAYS}d</div></div></div>
<div class="inline"><a href="/account/password"><button class="primary">Change my password</button></a><a href="/admin/users"><button>Users</button></a><a href="/enroll"><button>Enrollment</button></a></div></div>
<div class="panel pad"><h2>System</h2><table style="min-width:0"><tbody>
<tr><td>Public hostname</td><td><code>{html.escape(settings.PUBLIC_HOSTNAME)}</code></td></tr>
<tr><td>WireGuard endpoint</td><td><code>{html.escape(settings.WG_ENDPOINT)}</code></td></tr>
<tr><td>Router VPN pool</td><td><code>{html.escape(str(settings.WG_ROUTER_POOL))}</code></td></tr>
<tr><td>Remote WinBox port range</td><td><code>{settings.WINBOX_PUBLIC_PORT_MIN}-{settings.WINBOX_PUBLIC_PORT_MAX}</code></td></tr>
<tr><td>Enrollment token lifetime</td><td>{settings.TOKEN_TTL_HOURS} hours</td></tr>
<tr><td>UI timezone</td><td><code>Montréal local time</code><div class="muted">{html.escape(settings.TIMEZONE)} Eastern/DST rules</div></td></tr>
<tr><td>Codex AI</td><td><code>{html.escape(settings.AI_CODEX_HELPER)}</code> · isolated read-only router analysis</td></tr>
</tbody></table></div>'''
    return ui.page("Settings", body, user, "settings")
