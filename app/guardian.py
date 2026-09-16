"""Tikcentral Access Guardian.

Access comes first: continuously distinguish WireGuard reachability from actual
management access, retain history, and provide conservative repair actions that
only touch Tikcentral-owned management paths.
"""

import html
import socket
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import fleet
from app import main as core

SCHEMA = """
CREATE TABLE IF NOT EXISTS router_access_state (
    router_id INTEGER PRIMARY KEY,
    checked_at TEXT NOT NULL,
    wg_online INTEGER NOT NULL DEFAULT 0,
    ssh_open INTEGER NOT NULL DEFAULT 0,
    winbox_open INTEGER NOT NULL DEFAULT 0,
    api_open INTEGER NOT NULL DEFAULT 0,
    management_ok INTEGER NOT NULL DEFAULT 0,
    last_good_at TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS router_access_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    checked_at TEXT NOT NULL,
    wg_online INTEGER NOT NULL DEFAULT 0,
    ssh_open INTEGER NOT NULL DEFAULT 0,
    winbox_open INTEGER NOT NULL DEFAULT 0,
    api_open INTEGER NOT NULL DEFAULT 0,
    management_ok INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_router_access_history_router_time
    ON router_access_history(router_id, checked_at DESC);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_schema():
    with core.db() as conn:
        conn.executescript(SCHEMA)


def tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_router(row):
    peers = core.wireguard_peers()
    live = peers.get(row["public_key"], {})
    wg = bool(live.get("online")) and bool(row["enabled"])
    ssh = tcp_open(row["vpn_ip"], 22) if wg else False
    winbox = tcp_open(row["vpn_ip"], 8291) if wg else False
    api = tcp_open(row["vpn_ip"], 8728) if wg else False
    # Access-first policy: remote management is considered healthy when WG is
    # alive and at least one command path (SSH/API) plus WinBox is available.
    ok = wg and winbox and (ssh or api)
    return {
        "router_id": row["id"], "wg_online": wg, "ssh_open": ssh,
        "winbox_open": winbox, "api_open": api, "management_ok": ok,
    }


def guardian_tick():
    ensure_schema()
    with core.db() as conn:
        routers = conn.execute(
            "SELECT id,site_name,vpn_ip,public_key,enabled FROM routers ORDER BY id"
        ).fetchall()
    checked = now_iso()
    results = []
    for row in routers:
        result = probe_router(row)
        last_error = ""
        if result["wg_online"] and not result["winbox_open"]:
            last_error = "WireGuard online but WinBox TCP/8291 is unreachable"
        elif result["wg_online"] and not (result["ssh_open"] or result["api_open"]):
            last_error = "WireGuard online but SSH/API command paths are unreachable"
        elif not result["wg_online"]:
            last_error = "WireGuard peer is offline"
        with core.db() as conn:
            previous = conn.execute(
                "SELECT last_good_at FROM router_access_state WHERE router_id=?",
                (row["id"],),
            ).fetchone()
            last_good = checked if result["management_ok"] else ((previous["last_good_at"] if previous else "") or "")
            conn.execute(
                """INSERT INTO router_access_state
                   (router_id,checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok,last_good_at,last_error)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(router_id) DO UPDATE SET
                     checked_at=excluded.checked_at,wg_online=excluded.wg_online,
                     ssh_open=excluded.ssh_open,winbox_open=excluded.winbox_open,
                     api_open=excluded.api_open,management_ok=excluded.management_ok,
                     last_good_at=excluded.last_good_at,last_error=excluded.last_error""",
                (row["id"], checked, int(result["wg_online"]), int(result["ssh_open"]),
                 int(result["winbox_open"]), int(result["api_open"]), int(result["management_ok"]),
                 last_good, last_error),
            )
            conn.execute(
                """INSERT INTO router_access_history
                   (router_id,checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok)
                   VALUES(?,?,?,?,?,?,?)""",
                (row["id"], checked, int(result["wg_online"]), int(result["ssh_open"]),
                 int(result["winbox_open"]), int(result["api_open"]), int(result["management_ok"])),
            )
            # Keep roughly 30 days at a 5-minute cadence per router.
            conn.execute(
                """DELETE FROM router_access_history WHERE router_id=? AND id NOT IN
                   (SELECT id FROM router_access_history WHERE router_id=? ORDER BY id DESC LIMIT 9000)""",
                (row["id"], row["id"]),
            )
        results.append(result)
    return results


REPAIR_COMMAND = r'''
:if ([:len [/interface/wireguard find where name="opticable-wg"]] = 0) do={ :error "opticable-wg missing" }
/ip service set [find where name="winbox"] disabled=no
/ip service set [find where name="ssh"] disabled=no
/ip service set [find where name="api"] disabled=no address=10.250.0.1/32
:if ([:len [/ip/firewall/filter find where comment="Tikcentral relay WinBox"]] > 0) do={ /ip/firewall/filter remove [find where comment="Tikcentral relay WinBox"] }
:if ([:len [/ip/firewall/filter find where comment="Tikcentral management SSH API"]] > 0) do={ /ip/firewall/filter remove [find where comment="Tikcentral management SSH API"] }
:if ([:len [/ip/firewall/filter find where comment="Tikcentral management TCP"]] > 0) do={ /ip/firewall/filter remove [find where comment="Tikcentral management TCP"] }
/ip/firewall/filter add chain=input action=accept in-interface="opticable-wg" src-address=10.250.0.1/32 protocol=tcp dst-port=22,8291,8728 place-before=0 comment="Tikcentral management TCP"
:put "Tikcentral management access repaired"
'''.strip()


def repair_router(router_id: int):
    ensure_schema()
    with core.db() as conn:
        router = conn.execute(
            "SELECT id,site_name,vpn_ip,enabled FROM routers WHERE id=?", (router_id,)
        ).fetchone()
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    # Only attempt repair over the already-established managed SSH path. If SSH
    # itself is gone we intentionally do not guess or modify unrelated config.
    output = fleet.ssh_exec(router["vpn_ip"], REPAIR_COMMAND, timeout=90)
    guardian_tick()
    return output


def register(app, page_func):
    ensure_schema()

    @app.get("/guardian", response_class=HTMLResponse)
    def guardian_page(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        guardian_tick()
        csrf = core.csrf_token(request)
        with core.db() as conn:
            rows = conn.execute(
                """SELECT r.id,r.site_name,r.identity,r.model,r.vpn_ip,r.public_winbox_port,
                          s.checked_at,s.wg_online,s.ssh_open,s.winbox_open,s.api_open,
                          s.management_ok,s.last_good_at,s.last_error
                   FROM routers r LEFT JOIN router_access_state s ON s.router_id=r.id
                   ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()
        def badge(ok, label):
            return f'<span class="badge" style="margin-right:5px">{"●" if ok else "○"} {label}</span>'
        body_rows = []
        for r in rows:
            state = "Healthy" if r["management_ok"] else "Degraded"
            details = badge(r["wg_online"], "WG") + badge(r["winbox_open"], "WinBox") + badge(r["ssh_open"], "SSH") + badge(r["api_open"], "API")
            repair = f'''<form method="post" action="/guardian/{r['id']}/repair" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><button class="danger" onclick="return confirm('Repair only Tikcentral-owned management access on this router?')">Repair access</button></form>'''
            body_rows.append(
                f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')}</div></td>
<td><code>{html.escape(r['vpn_ip'])}</code></td><td>{html.escape(state)}</td><td>{details}</td>
<td class="muted">{html.escape(r['last_good_at'] or 'Never')}</td><td>{html.escape(r['last_error'] or '')}</td><td>{repair}</td></tr>'''
            )
        body = f'''<div class="panel pad"><h2>Access Guardian</h2><div class="muted">Access is evaluated separately from WireGuard status. Healthy means WinBox is reachable and at least one command path (SSH or API) is available over the management tunnel.</div></div>
<div class="panel"><table><thead><tr><th>Router</th><th>VPN IP</th><th>Access</th><th>Paths</th><th>Last known good</th><th>Issue</th><th>Recovery</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="7">No routers.</td></tr>'}</tbody></table></div>'''
        return page_func("Access Guardian", body, user, "guardian")

    @app.post("/guardian/{router_id}/repair", response_class=HTMLResponse)
    async def guardian_repair(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        try:
            output = repair_router(router_id)
            message = html.escape(output or "Repair completed")
        except Exception as exc:
            message = "Repair failed: " + html.escape(str(exc))
        return RedirectResponse("/guardian", status_code=303)
