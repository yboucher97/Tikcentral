"""Tikcentral Access Guardian.

Access comes first: WireGuard status is not enough. Healthy means WinBox plus at
least one command path is reachable through the management tunnel.
"""

import html
import socket
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import errors
from app import events
from app import jobs
from app import main as core
from app import management_script
from app import migrations
from app import router_exec
from app import settings


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_schema():
    migrations.migrate()


def tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_router(row, peers=None):
    """Probe one router, optionally reusing a caller-provided WireGuard snapshot."""
    if peers is None:
        peers = core.wireguard_peers()
    live = peers.get(row["public_key"], {}) if "public_key" in row.keys() else {}
    wg = bool(live.get("online")) and bool(row["enabled"])
    ssh = tcp_open(row["vpn_ip"], 22) if wg else False
    winbox = tcp_open(row["vpn_ip"], 8291) if wg else False
    api = tcp_open(row["vpn_ip"], 8728) if wg else False
    ok = wg and winbox and (ssh or api)
    return {
        "router_id": row["id"], "wg_online": wg, "ssh_open": ssh,
        "winbox_open": winbox, "api_open": api, "management_ok": ok,
    }


def _error_for(result):
    if result["wg_online"] and not result["winbox_open"]:
        return "WireGuard online but WinBox TCP/8291 is unreachable"
    if result["wg_online"] and not (result["ssh_open"] or result["api_open"]):
        return "WireGuard online but SSH/API command paths are unreachable"
    if not result["wg_online"]:
        return "WireGuard peer is offline"
    return ""


def guardian_tick():
    ensure_schema()
    with core.db() as conn:
        routers = conn.execute(
            "SELECT id,site_name,vpn_ip,public_key,enabled FROM routers ORDER BY id"
        ).fetchall()
        previous = {
            r["router_id"]: (bool(r["management_ok"]), r["last_error"] or "")
            for r in conn.execute("SELECT router_id,management_ok,last_error FROM router_access_state").fetchall()
        }

    # One privileged WireGuard snapshot per fleet tick. Individual callers of
    # probe_router() still get a fresh snapshot when they do not provide one.
    peers = core.wireguard_peers()
    checked = now_iso()
    results = []
    transitions = []
    for row in routers:
        result = probe_router(row, peers)
        last_error = _error_for(result)
        with core.db() as conn:
            old = conn.execute("SELECT last_good_at FROM router_access_state WHERE router_id=?", (row["id"],)).fetchone()
            last_good = checked if result["management_ok"] else ((old["last_good_at"] if old else "") or "")
            conn.execute(
                """INSERT INTO router_access_state
                   (router_id,checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok,last_good_at,last_error)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(router_id) DO UPDATE SET checked_at=excluded.checked_at,
                     wg_online=excluded.wg_online,ssh_open=excluded.ssh_open,
                     winbox_open=excluded.winbox_open,api_open=excluded.api_open,
                     management_ok=excluded.management_ok,last_good_at=excluded.last_good_at,last_error=excluded.last_error""",
                (row["id"], checked, int(result["wg_online"]), int(result["ssh_open"]),
                 int(result["winbox_open"]), int(result["api_open"]), int(result["management_ok"]), last_good, last_error),
            )
            conn.execute(
                """INSERT INTO router_access_history(router_id,checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok)
                   VALUES(?,?,?,?,?,?,?)""",
                (row["id"], checked, int(result["wg_online"]), int(result["ssh_open"]),
                 int(result["winbox_open"]), int(result["api_open"]), int(result["management_ok"])),
            )
            conn.execute(
                """DELETE FROM router_access_history WHERE router_id=? AND id NOT IN
                   (SELECT id FROM router_access_history WHERE router_id=? ORDER BY id DESC LIMIT ?)""",
                (row["id"], row["id"], settings.GUARDIAN_RETENTION_ROWS),
            )
        before = previous.get(row["id"])
        now_ok = bool(result["management_ok"])
        if before is None:
            transitions.append((row["id"], "Guardian baseline: healthy" if now_ok else "Guardian baseline: degraded", last_error, "info" if now_ok else "warning"))
        elif before[0] != now_ok:
            transitions.append((row["id"], "Management access restored" if now_ok else "Management access degraded", last_error, "info" if now_ok else "critical"))
        elif not now_ok and before[1] != last_error:
            transitions.append((row["id"], "Management access issue changed", last_error, "warning"))
        results.append(result)
    for rid, summary, detail, severity in transitions:
        events.record(rid, "access", summary, detail, severity)
    return results


def repair_router(router_id: int, actor: str = "guardian"):
    """Repair only Tikcentral-owned access objects.

    Access recovery intentionally does not require a backup and is not blocked by
    an existing router job; recovering management access has priority over other
    control-plane work. It is still recorded in the unified job lifecycle.
    """
    ensure_schema()
    with core.db() as conn:
        router = conn.execute(
            "SELECT id,site_name,vpn_ip,public_key,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()
    if not router or not router["enabled"]:
        raise errors.OperationError("ROUTER_NOT_FOUND", "Enabled router not found")

    with jobs.operation(
        router_id,
        "guardian_repair",
        actor,
        serialize_router=False,
        fail_code="GUARDIAN_REPAIR_FAILED",
        fail_message="Guardian access repair failed",
    ) as job_id:
        output = router_exec.mutate(
            router["vpn_ip"],
            management_script.access_repair_command(),
            timeout=settings.MUTATION_TIMEOUT,
            label="Guardian access repair",
        )
        jobs.verifying(job_id)
        result = probe_router(router)
        if not result["management_ok"]:
            raise errors.OperationError(
                "ACCESS_VERIFY_FAILED",
                "Management repair completed but access verification still failed",
                _error_for(result),
                severity="critical",
            )

    guardian_tick()
    events.record(router_id, "access", "Guardian access repair verified", severity="info")
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
        body_rows = []
        for r in rows:
            state = "Healthy" if r["management_ok"] else "Degraded"
            def badge(ok, label):
                return f'<span class="badge">{"●" if ok else "○"} {label}</span>'
            details = " ".join([badge(r["wg_online"], "WG"), badge(r["winbox_open"], "WinBox"), badge(r["ssh_open"], "SSH"), badge(r["api_open"], "API")])
            repair = f'''<form method="post" action="/guardian/{r['id']}/repair" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><button class="danger" onclick="return confirm('Repair only Tikcentral-owned management access on this router?')">Repair access</button></form>'''
            body_rows.append(f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')}</div></td><td><code>{html.escape(r['vpn_ip'])}</code></td><td>{state}</td><td>{details}</td><td>{html.escape(r['last_good_at'] or 'Never')}</td><td>{html.escape(r['last_error'] or '')}</td><td>{repair}</td></tr>''')
        body = f'''<div class="panel pad"><h2>Access Guardian</h2><div class="muted">Healthy means WireGuard + WinBox + at least one command path (SSH or API). History retention is sized for the one-minute Guardian cadence.</div></div><div class="panel"><table><thead><tr><th>Router</th><th>VPN IP</th><th>Access</th><th>Paths</th><th>Last known good</th><th>Issue</th><th>Recovery</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="7">No routers.</td></tr>'}</tbody></table></div>'''
        return page_func("Access Guardian", body, user, "guardian")

    @app.post("/guardian/{router_id}/repair")
    async def guardian_repair(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        actor = user["email"] if "email" in user.keys() else "admin"
        try:
            repair_router(router_id, actor)
        except Exception as exc:
            err = errors.from_exception(exc)
            events.record(router_id, "access", "Guardian repair failed", f"{err.code}: {err.detail}", err.severity)
        return RedirectResponse("/guardian", status_code=303)
