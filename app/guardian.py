"""Tikcentral Access Guardian.

Access comes first: WireGuard status is not enough. Healthy means WinBox plus at
least one command path is reachable through the management tunnel.
"""

import html
import json
import socket
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import change_control
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


def tcp_probe(ip: str, port: int, timeout: float = 2.0):
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, round((time.monotonic() - started) * 1000, 1)
    except OSError:
        return False, None


def tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    return tcp_probe(ip, port, timeout)[0]


def probe_router(row, peers=None):
    """Probe one router, optionally reusing a caller-provided WireGuard snapshot."""
    if peers is None:
        peers = core.wireguard_peers()
    live = peers.get(row["public_key"], {}) if "public_key" in row.keys() else {}
    wg = bool(live.get("online")) and bool(row["enabled"])
    ssh, ssh_ms = tcp_probe(row["vpn_ip"], 22) if wg else (False, None)
    winbox, winbox_ms = tcp_probe(row["vpn_ip"], 8291) if wg else (False, None)
    api, api_ms = tcp_probe(row["vpn_ip"], 8728) if wg else (False, None)
    ok = wg and winbox and (ssh or api)
    return {
        "router_id": row["id"], "wg_online": wg, "ssh_open": ssh,
        "winbox_open": winbox, "api_open": api, "management_ok": ok,
        "ssh_latency_ms": ssh_ms, "winbox_latency_ms": winbox_ms, "api_latency_ms": api_ms,
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
        now = now_iso()
        maintenance = {
            int(r["router_id"]): r
            for r in conn.execute(
                "SELECT * FROM router_maintenance WHERE start_at<=? AND end_at>?",
                (now, now),
            ).fetchall()
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
                """INSERT INTO router_access_history
                   (router_id,checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok,
                    ssh_latency_ms,winbox_latency_ms,api_latency_ms)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (row["id"], checked, int(result["wg_online"]), int(result["ssh_open"]),
                 int(result["winbox_open"]), int(result["api_open"]), int(result["management_ok"]),
                 result["ssh_latency_ms"], result["winbox_latency_ms"], result["api_latency_ms"]),
            )
            conn.execute(
                """DELETE FROM router_access_history WHERE router_id=? AND id NOT IN
                   (SELECT id FROM router_access_history WHERE router_id=? ORDER BY id DESC LIMIT ?)""",
                (row["id"], row["id"], settings.GUARDIAN_RETENTION_ROWS),
            )
        before = previous.get(row["id"])
        now_ok = bool(result["management_ok"])
        in_maintenance = int(row["id"]) in maintenance
        if before is None:
            transitions.append((row["id"], "Guardian baseline: healthy" if now_ok else "Guardian baseline: degraded", last_error, "info" if now_ok or in_maintenance else "warning", in_maintenance))
        elif before[0] != now_ok:
            summary = "Management access restored" if now_ok else "Management access degraded"
            if in_maintenance and not now_ok:
                summary = "Maintenance window: management access degraded"
            transitions.append((row["id"], summary, last_error, "info" if now_ok or in_maintenance else "critical", in_maintenance))
        elif not now_ok and before[1] != last_error:
            transitions.append((row["id"], "Maintenance window: access issue changed" if in_maintenance else "Management access issue changed", last_error, "info" if in_maintenance else "warning", in_maintenance))
        results.append(result)

    for rid, summary, detail, severity, _ in transitions:
        events.record(rid, "access", summary, detail, severity)

    # Correlate simultaneous failures so a central outage is visible as one incident.
    degraded_ids = [rid for rid, summary, _, _, in_maintenance in transitions if "degraded" in summary.lower() and not in_maintenance]
    if len(degraded_ids) >= 2:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        with core.db() as conn:
            existing = conn.execute(
                "SELECT id FROM fleet_incidents WHERE status='open' AND kind='access' AND opened_at>=? ORDER BY id DESC LIMIT 1",
                (cutoff,),
            ).fetchone()
            if not existing:
                names = [r["site_name"] for r in routers if int(r["id"]) in degraded_ids]
                conn.execute(
                    """INSERT INTO fleet_incidents(opened_at,status,kind,router_count,router_ids,summary,details)
                       VALUES(?,'open','access',?,?,?,?)""",
                    (checked, len(degraded_ids), json.dumps(degraded_ids),
                     f"Correlated management outage affecting {len(degraded_ids)} routers",
                     ", ".join(names)),
                )
                events.record(None, "incident", f"Correlated access incident: {len(degraded_ids)} routers degraded", ", ".join(names), "critical")

    # Automatically resolve correlated incidents once every affected router is healthy.
    result_map = {int(x["router_id"]): bool(x["management_ok"]) for x in results}
    with core.db() as conn:
        open_incidents = conn.execute("SELECT * FROM fleet_incidents WHERE status='open' ORDER BY id").fetchall()
        for incident in open_incidents:
            try:
                ids = [int(x) for x in json.loads(incident["router_ids"] or "[]")]
            except Exception:
                ids = []
            if ids and all(result_map.get(rid, False) for rid in ids):
                conn.execute(
                    "UPDATE fleet_incidents SET status='resolved',resolved_at=? WHERE id=?",
                    (checked, incident["id"]),
                )
                events.record(None, "incident", f"Incident #{incident['id']} resolved", incident["summary"], "info")
    return results


def repair_router(router_id: int, actor: str = "guardian"):
    """Repair only Tikcentral-owned access objects and keep a full transcript."""
    ensure_schema()
    with core.db() as conn:
        router = conn.execute(
            "SELECT id,site_name,vpn_ip,public_key,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()
    if not router or not router["enabled"]:
        raise errors.OperationError("ROUTER_NOT_FOUND", "Enabled router not found")

    before = probe_router(router)
    tx_id = change_control.begin(router_id, "guardian_repair", actor, pre_access=before)
    change_control.step(
        tx_id,
        "probe",
        "ok" if before["wg_online"] else "failed",
        "Initial management probe completed",
        json.dumps(before, sort_keys=True),
    )

    try:
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

        change_control.step(
            tx_id,
            "preflight",
            "ok",
            "WireGuard and SSH recovery path reachable",
            access_issue(before) or "Recovery prerequisites satisfied",
        )
        with jobs.operation(
            router_id,
            "guardian_repair",
            actor,
            serialize_router=False,
            fail_code="GUARDIAN_REPAIR_FAILED",
            fail_message="Guardian access repair failed",
        ) as job_id:
            change_control.attach_job(tx_id, job_id)
            change_control.step(tx_id, "apply", "info", "Applying Tikcentral-owned access repair")
            output = router_exec.mutate(
                router["vpn_ip"],
                management_script.access_repair_command(),
                timeout=settings.MUTATION_TIMEOUT,
                label="Guardian access repair",
            )
            change_control.step(
                tx_id,
                "apply",
                "ok",
                "Tikcentral-owned access repair command completed",
                router_exec.sanitize(output, 2000),
            )
            jobs.verifying(job_id)
            result = probe_router(router)
            change_control.step(
                tx_id,
                "verify",
                "ok" if result["management_ok"] else "failed",
                "Management paths re-probed",
                json.dumps(result, sort_keys=True),
            )
            if not result["management_ok"]:
                raise errors.OperationError(
                    "ACCESS_VERIFY_FAILED",
                    "Management repair completed but access verification still failed",
                    access_issue(result),
                    severity="critical",
                )
            change_control.finish(tx_id, post_access=result)
    except Exception as exc:
        try:
            change_control.fail(tx_id, exc, post_access=probe_router(router))
        except Exception:
            pass
        raise

    guardian_tick()
    events.record(router_id, "access", "Guardian access repair verified", output[-800:], severity="info")
    return output


def _diagnosis(row, history):
    """Explain current management-path health in operator terms."""
    if not row["enabled"]:
        return "Router is disabled in Tikcentral."
    if not row["checked_at"]:
        return "Guardian has not completed a probe yet."
    if not row["wg_online"]:
        return "Management WireGuard is offline. Tikcentral cannot run router-side repair until the tunnel returns."
    if not row["winbox_open"] and (row["ssh_open"] or row["api_open"]):
        return "WinBox is the failing required path. Command access still exists, so Repair access can reconcile Tikcentral-owned management rules."
    if row["winbox_open"] and not row["ssh_open"] and row["api_open"]:
        return "SSH is unavailable, but WinBox and API are reachable. Guardian remains Healthy because API is a valid command path; automated repair cannot run without SSH."
    if row["winbox_open"] and row["ssh_open"] and not row["api_open"]:
        return "API is unavailable, but WinBox and SSH are reachable. Guardian remains Healthy because SSH is a valid command path."
    if row["winbox_open"] and not row["ssh_open"] and not row["api_open"]:
        return "WinBox is reachable but both command paths are unavailable. Tikcentral can see WinBox, but cannot safely execute normal router changes."
    if row["management_ok"]:
        return "All required management conditions are satisfied."
    return row["last_error"] or "Management access is degraded."


def _quality_metrics(history):
    rows = list(history or [])
    if not rows:
        return {"samples": 0, "success_pct": None, "consecutive_failures": 0, "failure_since": "", "avg_ms": None, "max_ms": None}
    success = sum(1 for x in rows if x["management_ok"])
    consecutive = 0
    failure_since = ""
    for x in rows:
        if x["management_ok"]:
            break
        consecutive += 1
        failure_since = x["checked_at"] or failure_since
    latency = [
        float(x["winbox_latency_ms"])
        for x in rows
        if x["winbox_latency_ms"] is not None
    ]
    return {
        "samples": len(rows),
        "success_pct": round((success / len(rows)) * 100, 1),
        "consecutive_failures": consecutive,
        "failure_since": failure_since,
        "avg_ms": round(sum(latency) / len(latency), 1) if latency else None,
        "max_ms": round(max(latency), 1) if latency else None,
    }


def _state_for(row):
    if not row["enabled"]:
        return "Disabled"
    if "maintenance_end" in row.keys() and row["maintenance_end"] and row["maintenance_end"] > now_iso():
        return "Maintenance"
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
                          m.end_at AS maintenance_end,m.reason AS maintenance_reason,
                          (SELECT j.status FROM router_jobs j WHERE j.router_id=r.id AND j.kind='guardian_repair' ORDER BY j.id DESC LIMIT 1) AS repair_status,
                          (SELECT j.updated_at FROM router_jobs j WHERE j.router_id=r.id AND j.kind='guardian_repair' ORDER BY j.id DESC LIMIT 1) AS repair_at,
                          (SELECT j.error_code FROM router_jobs j WHERE j.router_id=r.id AND j.kind='guardian_repair' ORDER BY j.id DESC LIMIT 1) AS repair_error_code,
                          (SELECT j.error_message FROM router_jobs j WHERE j.router_id=r.id AND j.kind='guardian_repair' ORDER BY j.id DESC LIMIT 1) AS repair_error_message,
                          (SELECT t.id FROM change_transactions t WHERE t.router_id=r.id AND t.kind='guardian_repair' ORDER BY t.id DESC LIMIT 1) AS repair_tx_id
                   FROM routers r LEFT JOIN router_access_state s ON s.router_id=r.id
                   LEFT JOIN router_maintenance m ON m.router_id=r.id
                   ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()
            histories = {
                int(r["id"]): conn.execute(
                    """SELECT checked_at,management_ok,ssh_latency_ms,winbox_latency_ms,api_latency_ms
                       FROM router_access_history WHERE router_id=? ORDER BY id DESC LIMIT 240""",
                    (r["id"],),
                ).fetchall()
                for r in rows
            }
            access_events = conn.execute(
                """SELECT e.event_at,e.severity,e.category,e.summary,e.details,r.site_name
                   FROM router_events e LEFT JOIN routers r ON r.id=e.router_id
                   WHERE e.category='access'
                   ORDER BY e.id DESC LIMIT 40"""
            ).fetchall()

        notice_kind = request.query_params.get("repair", "")
        notice_text = request.query_params.get("detail", "")[:1000]
        if notice_kind == "ok":
            notice = f'<div class="panel pad tc-toast"><strong>✓ Repair completed and verified.</strong><div class="muted">{html.escape(notice_text)}</div></div>'
        elif notice_kind == "failed":
            notice = f'<div class="panel pad tc-toast bad"><div class="error"><strong>✕ Repair not completed.</strong><div>{html.escape(notice_text)}</div></div></div>'
        else:
            notice = ""

        body_rows = []
        for r in rows:
            state = _state_for(r)

            def badge(ok, label):
                tone = "ok" if ok else "bad"
                state_text = "reachable" if ok else "unreachable"
                return f'<span class="tc-path {tone}" title="{html.escape(label)} is {state_text}"><span class="tc-status-dot"></span>{html.escape(label)}</span>'

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

            state_tone = "ok" if state == "Healthy" else ("warn" if state in {"Degraded", "Unknown", "Maintenance"} else "bad")
            newest_first = histories.get(int(r["id"]), [])
            probes = list(reversed(newest_first[-60:]))
            strip = ''.join(
                f'<span title="{html.escape(p["checked_at"] or "")}" style="display:inline-block;width:4px;height:18px;border-radius:2px;background:{("var(--green)" if p["management_ok"] else "var(--danger)")};opacity:.85"></span>'
                for p in probes
            ) or '<span class="muted">No history</span>'
            quality = _quality_metrics(newest_first)
            quality_text = (
                f'{quality["success_pct"]}% healthy · {quality["avg_ms"]} ms avg / {quality["max_ms"]} ms max WinBox'
                if quality["success_pct"] is not None and quality["avg_ms"] is not None
                else (f'{quality["success_pct"]}% healthy · no latency sample' if quality["success_pct"] is not None else 'No quality history')
            )
            if quality["consecutive_failures"]:
                quality_text += f' · {quality["consecutive_failures"]} consecutive failed probes'
            diagnosis = _diagnosis(r, newest_first)
            maintenance_note = f'<div class="muted">Maintenance until {html.escape(r["maintenance_end"])} · {html.escape(r["maintenance_reason"] or "")}</div>' if state == "Maintenance" else ''
            tx_link = f'<div style="margin-top:6px"><a href="/reliability#tx-{r["repair_tx_id"]}">View repair transcript #{r["repair_tx_id"]}</a></div>' if r["repair_tx_id"] else ''
            body_rows.append(
                f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')}</div></td>
<td><code>{html.escape(r['vpn_ip'])}</code></td><td><span class="tc-status {state_tone} live"><span class="tc-status-dot"></span>{html.escape(state)}</span></td><td><div class="tc-paths">{details}</div></td>
<td>{html.escape(r['last_good_at'] or 'Never')}<div style="display:flex;gap:2px;margin-top:7px;align-items:end;max-width:280px;overflow:hidden">{strip}</div><div class="muted">{html.escape(quality_text)}</div></td><td><strong>{html.escape(diagnosis)}</strong>{f'<div class="muted">Failure run since {html.escape(quality["failure_since"])}</div>' if quality["failure_since"] else ''}{maintenance_note}</td>
<td><div>{repair}</div><div class="muted" style="margin-top:6px">Last repair: {html.escape(repair_detail)}</div>{tx_link}</td></tr>'''
            )

        legend = '''<div class="panel pad"><h3>Access status legend</h3><div class="cards">
<div class="card"><strong>Healthy</strong><div class="muted">WireGuard is online, WinBox is reachable, and at least one command path (SSH or API) is reachable.</div></div>
<div class="card"><strong>Degraded</strong><div class="muted">WireGuard is online, but either WinBox is unreachable or both SSH and API command paths are unavailable. Check the path indicators and Issue column.</div></div>
<div class="card"><strong>Offline</strong><div class="muted">The WireGuard peer is not currently online. Router-side repair cannot run until the tunnel returns.</div></div>
<div class="card"><strong>Unknown</strong><div class="muted">Guardian has not yet completed a probe for this router.</div></div>
<div class="card"><strong>Disabled</strong><div class="muted">The router is disabled in Tikcentral and is not considered available for management.</div></div>
</div><div class="muted" style="margin-top:10px">Path indicators: ● reachable, ○ unreachable. Repair uses SSH to execute the router-side recovery command; if SSH itself is down, Tikcentral will show that repair cannot be started rather than silently failing.</div></div>'''

        counts = {"Healthy": 0, "Degraded": 0, "Offline": 0, "Unknown": 0, "Disabled": 0, "Maintenance": 0}
        for r in rows:
            counts[_state_for(r)] = counts.get(_state_for(r), 0) + 1
        summary = f'''<div class="tc-health-grid">
<div class="tc-health-card ok"><div class="big">{counts["Healthy"]} Healthy</div><div class="muted">Full management access verified</div></div>
<div class="tc-health-card warn"><div class="big">{counts["Degraded"]} Degraded</div><div class="muted">Tunnel online, one or more required paths failing</div></div>
<div class="tc-health-card bad"><div class="big">{counts["Offline"]} Offline</div><div class="muted">WireGuard management tunnel unavailable</div></div>
<div class="tc-health-card"><div class="big">{counts["Unknown"] + counts["Disabled"] + counts["Maintenance"]} Other</div><div class="muted">{counts["Unknown"]} unknown · {counts["Disabled"]} disabled · {counts["Maintenance"]} maintenance</div></div>
</div>'''

        log_rows = []
        for e in access_events:
            sev = e["severity"] if e["severity"] in {"info", "warning", "critical"} else "info"
            detail = e["details"] or ""
            log_rows.append(
                f'''<div class="tc-log {sev}"><div>{html.escape(e["event_at"] or "")}</div><div class="sev">{html.escape(sev)}</div><div>{html.escape(e["site_name"] or "System")}</div><div><strong>{html.escape(e["summary"] or "")}</strong>{f'<div class="muted">{html.escape(detail)}</div>' if detail else ''}</div></div>'''
            )
        logs = ''.join(log_rows) or '<div class="pad muted">No Guardian access events yet.</div>'

        body = f'''<div class="panel pad"><h2>Access Guardian</h2><div class="muted">Guardian probes the management tunnel and services. A state is only Healthy when the complete management requirement is met.</div></div>{notice}<div class="panel pad"><h3>Fleet access status</h3>{summary}</div>{legend}<div class="panel"><table><thead><tr><th>Router</th><th>VPN IP</th><th>Access</th><th>Paths</th><th>Last known good</th><th>Issue</th><th>Recovery / last repair</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="7">No routers.</td></tr>'}</tbody></table></div><div class="panel"><div class="pad"><h3>Guardian activity log</h3><div class="muted">Recent access transitions, repair attempts, failures and recoveries.</div></div>{logs}</div>'''
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
