"""Tikcentral Access Guardian.

Access comes first: WireGuard status is not enough. Healthy means WinBox plus at
least one command path is reachable through the management tunnel.
"""

import html
import socket
from datetime import datetime, timezone
from urllib.parse import quote

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


def access_issue(result):
    """Return the operator-facing reason a Guardian probe is not healthy."""
    if result["wg_online"] and not result["winbox_open"]:
        return "WireGuard online but WinBox TCP/8291 is unreachable"
    if result["wg_online"] and not (result["ssh_open"] or result["api_open"]):
        return "WireGuard online but SSH/API command paths are unreachable"
    if not result["wg_online"]:
        return "WireGuard peer is offline"
    return ""


def _error_for(result):
    return access_issue(result)


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

    peers = core.wireguard_peers()
    checked = now_iso()
    results = []
    transitions = []
    for row in routers:
        result = probe_router(row, peers)
        last_error = access_issue(result)
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

    before = probe_router(router)
    if not before["wg_online"]:
        raise errors.OperationError(
            "GUARDIAN_REPAIR_UNREACHABLE",
            "Repair cannot run while the WireGuard peer is offline",
            "Tikcentral needs the management tunnel before it can repair router-side access.",
        )
    if not before["ssh_open"]:
        raise errors.OperationError(
            "GUARDIAN_REPAIR_NO_SSH",
            "Repair requires the Tikcentral SSH path",
            "SSH TCP/22 is not reachable, so Tikcentral cannot safely execute the repair command. WinBox/API state is still shown for diagnosis.",
        )

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
                access_issue(result),
                severity="critical",
            )

    guardian_tick()
    events.record(router_id, "access", "Guardian access repair verified", output[-800:], severity="info")
    return output


def _state_for(row):
    if not row["enabled"]:
        return "Disabled"
    if not row["checked_at"]:
        return "Unknown"
    if not row["wg_online"]:
        return "Offline"
    if row["management_ok"]:
        return "Healthy"
    return "Degraded"


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
                """SELECT r.id,r.site_name,r.identity,r.model,r.vpn_ip,r.public_winbox_port,r.enabled,
                          s.checked_at,s.wg_online,s.ssh_open,s.winbox_open,s.api_open,
                          s.management_ok,s.last_good_at,s.last_error,
                          (SELECT j.status FROM router_jobs j WHERE j.router_id=r.id AND j.kind='guardian_repair' ORDER BY j.id DESC LIMIT 1) AS repair_status,
                          (SELECT j.updated_at FROM router_jobs j WHERE j.router_id=r.id AND j.kind='guardian_repair' ORDER BY j.id DESC LIMIT 1) AS repair_at,
                          (SELECT j.error_code FROM router_jobs j WHERE j.router_id=r.id AND j.kind='guardian_repair' ORDER BY j.id DESC LIMIT 1) AS repair_error_code,
                          (SELECT j.error_message FROM router_jobs j WHERE j.router_id=r.id AND j.kind='guardian_repair' ORDER BY j.id DESC LIMIT 1) AS repair_error_message
                   FROM routers r LEFT JOIN router_access_state s ON s.router_id=r.id
                   ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()

        notice_kind = request.query_params.get("repair", "")
        notice_text = request.query_params.get("detail", "")[:1000]
        if notice_kind == "ok":
            notice = f'<div class="panel pad"><strong>Repair completed and verified.</strong><div class="muted">{html.escape(notice_text)}</div></div>'
        elif notice_kind == "failed":
            notice = f'<div class="panel pad"><div class="error"><strong>Repair not completed.</strong><div>{html.escape(notice_text)}</div></div></div>'
        else:
            notice = ""

        body_rows = []
        for r in rows:
            state = _state_for(r)

            def badge(ok, label):
                return f'<span class="badge">{"●" if ok else "○"} {label}</span>'

            details = " ".join([
                badge(r["wg_online"], "WG"),
                badge(r["winbox_open"], "WinBox"),
                badge(r["ssh_open"], "SSH"),
                badge(r["api_open"], "API"),
            ])

            repair_status = r["repair_status"] or "Never run"
            repair_detail = repair_status
            if r["repair_at"]:
                repair_detail += f' · {r["repair_at"]}'
            if r["repair_error_code"]:
                repair_detail += f' · {r["repair_error_code"]}'
            if r["repair_error_message"]:
                repair_detail += f' · {r["repair_error_message"]}'

            if not r["enabled"]:
                repair = '<span class="muted">Disabled</span>'
            elif not r["wg_online"]:
                repair = '<button disabled title="WireGuard must be online before router-side repair is possible">Repair unavailable</button>'
            elif not r["ssh_open"]:
                repair = '<button disabled title="Tikcentral repair currently executes through SSH, and TCP/22 is not reachable">Repair needs SSH</button>'
            else:
                repair = f'''<form method="post" action="/guardian/{r['id']}/repair" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><button class="danger" onclick="return confirm('Repair only Tikcentral-owned management access on this router?')">Repair access</button></form>'''

            body_rows.append(
                f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')}</div></td>
<td><code>{html.escape(r['vpn_ip'])}</code></td><td><strong>{html.escape(state)}</strong></td><td>{details}</td>
<td>{html.escape(r['last_good_at'] or 'Never')}</td><td>{html.escape(r['last_error'] or '')}</td>
<td><div>{repair}</div><div class="muted" style="margin-top:6px">Last repair: {html.escape(repair_detail)}</div></td></tr>'''
            )

        legend = '''<div class="panel pad"><h3>Access status legend</h3><div class="cards">
<div class="card"><strong>Healthy</strong><div class="muted">WireGuard is online, WinBox is reachable, and at least one command path (SSH or API) is reachable.</div></div>
<div class="card"><strong>Degraded</strong><div class="muted">WireGuard is online, but either WinBox is unreachable or both SSH and API command paths are unavailable. Check the path indicators and Issue column.</div></div>
<div class="card"><strong>Offline</strong><div class="muted">The WireGuard peer is not currently online. Router-side repair cannot run until the tunnel returns.</div></div>
<div class="card"><strong>Unknown</strong><div class="muted">Guardian has not yet completed a probe for this router.</div></div>
<div class="card"><strong>Disabled</strong><div class="muted">The router is disabled in Tikcentral and is not considered available for management.</div></div>
</div><div class="muted" style="margin-top:10px">Path indicators: ● reachable, ○ unreachable. Repair uses SSH to execute the router-side recovery command; if SSH itself is down, Tikcentral will show that repair cannot be started rather than silently failing.</div></div>'''

        body = f'''<div class="panel pad"><h2>Access Guardian</h2><div class="muted">Guardian probes the management tunnel and services. A state is only Healthy when the complete management requirement is met.</div></div>{notice}{legend}<div class="panel"><table><thead><tr><th>Router</th><th>VPN IP</th><th>Access</th><th>Paths</th><th>Last known good</th><th>Issue</th><th>Recovery / last repair</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="7">No routers.</td></tr>'}</tbody></table></div>'''
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
            return RedirectResponse("/guardian?repair=ok&detail=" + quote("Guardian repair completed and management access was verified."), status_code=303)
        except Exception as exc:
            err = errors.from_exception(exc)
            detail = f"{err.code}: {err.message}" + (f" — {err.detail}" if err.detail else "")
            events.record(router_id, "access", "Guardian repair failed", detail, err.severity)
            return RedirectResponse("/guardian?repair=failed&detail=" + quote(detail), status_code=303)
