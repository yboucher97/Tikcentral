"""Read-only Codex analysis for router snapshots.

Tikcentral remains the only component that talks to routers. Codex receives a
sanitized snapshot through a dedicated helper and can only return an
operator-facing report. It never receives router credentials and never executes
RouterOS mutations.
"""

import difflib
import html
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import errors, main as core, migrations, operations, router_exec, settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _router(router_id: int):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,serial,model,routeros_version,routerboot_version,vpn_ip,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _sanitize(text: str) -> str:
    value = router_exec.sanitize(text or "")
    patterns = (
        r'(?i)(password|passwd|passphrase|secret|token|private[-_ ]?key|preshared[-_ ]?key|community)\s*[=:]\s*([^\s;]+)',
        r'(?i)(pppoe[^\n]{0,80}password\s*[=:]\s*)([^\s;]+)',
    )
    for pattern in patterns:
        value = re.sub(pattern, lambda m: f"{m.group(1)}=<redacted>", value)
    return value[: settings.AI_MAX_SECTION_CHARS]


def _safe_read(ip: str, command: str, label: str) -> dict:
    try:
        data = router_exec.read(ip, command, timeout=settings.AI_ROUTER_READ_TIMEOUT, label=label)
        return {"ok": True, "data": _sanitize(data)}
    except Exception as exc:
        return {"ok": False, "error": errors.short(exc)}


def collect_snapshot(router_id: int, focus_start: str = "", focus_end: str = "", focus_note: str = "") -> dict:
    """Collect a fresh, sanitized, read-only router snapshot."""
    migrations.migrate()
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise errors.OperationError("ROUTER_NOT_FOUND", "Enabled router not found")

    telemetry_error = ""
    try:
        operations.collect_telemetry(router_id, False)
    except Exception as exc:
        telemetry_error = errors.short(exc)

    with core.db() as conn:
        access = conn.execute("SELECT * FROM router_access_state WHERE router_id=?", (router_id,)).fetchone()
        expected = conn.execute("SELECT * FROM router_expected_state WHERE router_id=?", (router_id,)).fetchone()
        update = conn.execute("SELECT * FROM router_update_status WHERE router_id=?", (router_id,)).fetchone()
        window_args = (router_id, focus_start, focus_start, focus_end, focus_end)
        telemetry = conn.execute(
            """SELECT * FROM router_telemetry WHERE router_id=?
               AND (?='' OR captured_at>=?) AND (?='' OR captured_at<=?)
               ORDER BY id DESC LIMIT 500""", window_args
        ).fetchall()
        recent_events = conn.execute(
            """SELECT * FROM router_events WHERE router_id=?
               AND (?='' OR event_at>=?) AND (?='' OR event_at<=?)
               ORDER BY id DESC LIMIT 500""", window_args
        ).fetchall()
        recent_jobs = conn.execute(
            """SELECT * FROM router_jobs WHERE router_id=?
               AND (?='' OR created_at>=?) AND (?='' OR created_at<=?)
               ORDER BY id DESC LIMIT 200""", window_args
        ).fetchall()
        access_history = conn.execute(
            """SELECT checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok,
                      ssh_latency_ms,winbox_latency_ms,api_latency_ms
               FROM router_access_history WHERE router_id=?
                 AND (?='' OR checked_at>=?) AND (?='' OR checked_at<=?)
               ORDER BY id DESC LIMIT 1000""",
            window_args,
        ).fetchall()
        snapshots = conn.execute(
            """SELECT id,captured_at,sha256,content FROM router_snapshots WHERE router_id=?
               AND (?='' OR captured_at>=?) AND (?='' OR captured_at<=?)
               ORDER BY id DESC LIMIT 5""",
            window_args,
        ).fetchall()
        maintenance = conn.execute("SELECT * FROM router_maintenance WHERE router_id=?", (router_id,)).fetchone()
        compliance = conn.execute("SELECT * FROM router_policy_compliance WHERE router_id=?", (router_id,)).fetchone()
        site_metadata = conn.execute("SELECT * FROM router_site_metadata WHERE router_id=?", (router_id,)).fetchone()
        outage_assessment = conn.execute("SELECT * FROM router_outage_assessment WHERE router_id=?", (router_id,)).fetchone()
        capacity_forecast = conn.execute("SELECT * FROM router_capacity_forecast WHERE router_id=?", (router_id,)).fetchone()
        wan_probe = conn.execute("SELECT * FROM router_wan_probe_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
        desired_state = conn.execute("SELECT * FROM router_desired_state_status WHERE router_id=?",(router_id,)).fetchone()
        topology_time = conn.execute("SELECT MAX(captured_at) t FROM router_topology_devices WHERE router_id=?",(router_id,)).fetchone()["t"]
        topology_devices = conn.execute(
            """SELECT source,device_type,vendor,name,ip_address,local_interface,confidence
               FROM router_topology_devices WHERE router_id=? AND captured_at=? ORDER BY device_type,vendor,name LIMIT 300""",
            (router_id,topology_time or ""),
        ).fetchall() if topology_time else []
        operator_notes = conn.execute(
            """SELECT created_at,object_type,object_id,ticket_reference,visibility,note,created_by
               FROM operator_notes WHERE router_id=?
                 AND (?='' OR created_at>=?) AND (?='' OR created_at<=?)
               ORDER BY id DESC LIMIT 300""",
            window_args,
        ).fetchall()
        security_audit = conn.execute("SELECT * FROM router_security_audit WHERE router_id=?", (router_id,)).fetchone()
        automation_time = conn.execute("SELECT MAX(captured_at) t FROM router_automation_inventory WHERE router_id=?", (router_id,)).fetchone()["t"]
        automation_inventory = conn.execute(
            """SELECT object_type,name,enabled,managed,schedule,target,metadata
               FROM router_automation_inventory WHERE router_id=? AND captured_at=?
               ORDER BY object_type,name LIMIT 500""",
            (router_id,automation_time or ""),
        ).fetchall() if automation_time else []
        traffic_history = conn.execute(
            """SELECT captured_at,interface,interval_seconds,rx_bps,tx_bps,rx_delta_bytes,tx_delta_bytes
               FROM router_traffic_history WHERE router_id=?
                 AND (?='' OR captured_at>=?) AND (?='' OR captured_at<=?)
               ORDER BY id DESC LIMIT 1500""",
            window_args,
        ).fetchall()
        interface_history = conn.execute(
            """SELECT captured_at,name,interface_type,running,disabled,rx_bytes,tx_bytes,rx_packets,tx_packets,
                      rx_errors,tx_errors,rx_drops,tx_drops,link_downs,rate,full_duplex,auto_negotiation,poe_out
               FROM router_interface_history WHERE router_id=?
                 AND (?='' OR captured_at>=?) AND (?='' OR captured_at<=?)
               ORDER BY id DESC LIMIT 1500""",
            window_args,
        ).fetchall()
        lte_history = conn.execute(
            """SELECT captured_at,interface,registered,operator,access_technology,band,ca_band,
                      cell_id,enb_id,sector_id,phy_cell_id,rsrp,rsrq,sinr,rssi
               FROM router_lte_history WHERE router_id=?
                 AND (?='' OR captured_at>=?) AND (?='' OR captured_at<=?)
               ORDER BY id DESC LIMIT 500""",
            window_args,
        ).fetchall()
        incidents = conn.execute(
            "SELECT * FROM fleet_incidents ORDER BY id DESC LIMIT 30"
        ).fetchall()
        transactions = conn.execute(
            """SELECT * FROM change_transactions WHERE router_id=?
               AND (?='' OR created_at>=?) AND (?='' OR created_at<=?)
               ORDER BY id DESC LIMIT 100""",
            window_args,
        ).fetchall()
        prior_ai = conn.execute(
            """SELECT id,status,created_at,finished_at,report,error_code,error_detail
               FROM router_ai_analyses WHERE router_id=? AND status='succeeded'
               ORDER BY id DESC LIMIT 2""",
            (router_id,),
        ).fetchall()

    diff_summary = ""
    if len(snapshots) >= 2:
        diff_lines = list(difflib.unified_diff(
            snapshots[1]["content"].splitlines(),
            snapshots[0]["content"].splitlines(),
            fromfile=f"snapshot-{snapshots[1]['id']}",
            tofile=f"snapshot-{snapshots[0]['id']}",
            lineterm="",
        ))
        diff_summary = "\n".join(diff_lines[:400])

    def row_dict(row):
        return dict(row) if row else None

    return {
        "snapshot_version": 2,
        "captured_at": _now(),
        "incident_focus": {"start": focus_start, "end": focus_end, "note": _sanitize(focus_note)},
        "router": dict(router),
        "access": row_dict(access),
        "expected_state": row_dict(expected),
        "update_status": row_dict(update),
        "telemetry_error": telemetry_error,
        "telemetry_history": [dict(r) for r in telemetry],
        "access_history": [dict(r) for r in access_history],
        "recent_events": [dict(r) for r in recent_events],
        "recent_jobs": [dict(r) for r in recent_jobs],
        "maintenance": row_dict(maintenance),
        "golden_policy_compliance": row_dict(compliance),
        "site_metadata": (
            {
                "customer_name": site_metadata["customer_name"],
                "site_code": site_metadata["site_code"],
                "circuit_type": site_metadata["circuit_type"],
            } if site_metadata else None
        ),
        "outage_assessment": row_dict(outage_assessment),
        "capacity_forecast": row_dict(capacity_forecast),
        "wan_probe": row_dict(wan_probe),
        "desired_state": row_dict(desired_state),
        "site_topology": [dict(r) for r in topology_devices],
        "operator_notes": [dict(r) for r in operator_notes],
        "security_exposure_audit": row_dict(security_audit),
        "automation_inventory": [dict(r) for r in automation_inventory],
        "traffic_history": [dict(r) for r in traffic_history],
        "interface_history": [dict(r) for r in interface_history],
        "lte_history": [dict(r) for r in lte_history],
        "recent_incidents": [dict(r) for r in incidents],
        "change_transactions": [dict(r) for r in transactions],
        "configuration_history": {
            "snapshots": [{"id": r["id"], "captured_at": r["captured_at"], "sha256": r["sha256"]} for r in snapshots],
            "latest_diff": _sanitize(diff_summary),
        },
        "previous_ai_reports": [
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "finished_at": r["finished_at"],
                "report": _sanitize(r["report"] or "")[-12000:],
            }
            for r in prior_ai
        ],
        "live": {
            # `/export` redacts sensitive values by default. `show-sensitive` is
            # an enabling flag on RouterOS, not a boolean `=no` option.
            "configuration": _safe_read(router["vpn_ip"], "/export", "AI configuration export"),
            "logs": _safe_read(router["vpn_ip"], "/log print without-paging", "AI log collection"),
            "interfaces": _safe_read(router["vpn_ip"], "/interface print stats-detail without-paging", "AI interface collection"),
            "routes": _safe_read(router["vpn_ip"], "/ip route print detail without-paging", "AI route collection"),
            "dhcp_clients": _safe_read(router["vpn_ip"], "/ip dhcp-client print detail without-paging", "AI DHCP collection"),
            "pppoe_clients": _safe_read(router["vpn_ip"], "/interface pppoe-client print detail without-paging", "AI PPPoE collection"),
        },
    }


def build_prompt(snapshot: dict) -> str:
    payload = json.dumps(snapshot, indent=2, ensure_ascii=False)
    return f"""You are analyzing one MikroTik RouterOS site for an experienced network technician.
Use ONLY the supplied Tikcentral snapshot. Do not use tools, shell commands, network access, or outside assumptions.
Never claim an observed condition unless the snapshot supports it. Clearly separate confirmed findings from things worth checking.
Do not output RouterOS commands and do not claim to have changed anything.

Return concise Markdown with these headings exactly:
# Overall
# Good
# Attention
# Unusual / Recent Changes
# What Happened Recently
# Improvements to Consider
# Data Gaps

Prioritize management access, multi-target WAN probe evidence, outage-domain evidence, ISP correlation, desired-state results, external UniFi/Omada topology context, capacity-trend evidence, security exposure findings, RouterOS automation changes, traffic-rate/usage anomalies, interface errors/drops/link flaps, LTE signal/band/cell changes when present, routes, DHCP/PPPoE, CPU/memory, versions, golden-policy compliance, configuration drift, recent jobs/events, operator notes/tickets, and suspicious log patterns. Treat operator notes as human context, not measured evidence. Treat topology as dependency context only; do not assume Tikcentral manages external switches or APs. Use site/customer metadata only as operational context.
If incident_focus contains a time window or operator note, treat that as the primary investigation scope and distinguish evidence inside that window from current live state.
Use access-history timing, maintenance windows, correlated incidents, configuration diffs and change transactions to explain what likely changed and when. Distinguish a Tikcentral-attributed change from a change that has no matching Tikcentral job. Treat previous AI reports only as historical context, not as authoritative evidence.
End with: **No action was taken.**

TIKCENTRAL SNAPSHOT:
{payload}
"""


def run_codex(snapshot: dict) -> str:
    """Invoke the fixed root-owned wrapper; Codex itself runs as tikcentral-ai."""
    proc = subprocess.run(
        ["sudo", "-n", settings.AI_CODEX_HELPER],
        input=build_prompt(snapshot),
        text=True,
        capture_output=True,
        timeout=settings.AI_TIMEOUT,
    )
    if proc.returncode != 0:
        detail = _sanitize((proc.stderr or proc.stdout or "Codex returned an error")[-4000:])
        raise errors.OperationError("AI_CODEX_FAILED", "Codex analysis failed", detail)
    report = _sanitize((proc.stdout or "").strip())[: settings.AI_MAX_REPORT_CHARS]
    if not report:
        raise errors.OperationError("AI_EMPTY_RESULT", "Codex returned an empty analysis")
    return report


def queue_analysis(router_id: int, actor: str, focus_start: str = "", focus_end: str = "", focus_note: str = "") -> int:
    """Queue at most one pending/running analysis per router."""
    migrations.migrate()
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise errors.OperationError("ROUTER_NOT_FOUND", "Enabled router not found")
    with core.db() as conn:
        existing = conn.execute(
            "SELECT id FROM router_ai_analyses WHERE router_id=? AND status IN ('queued','running') ORDER BY id DESC LIMIT 1",
            (router_id,),
        ).fetchone()
        if existing:
            return int(existing["id"])
        cur = conn.execute(
            """INSERT INTO router_ai_analyses
               (router_id,status,requested_by,created_at,focus_start,focus_end,focus_note)
               VALUES(?, 'queued', ?, ?, ?, ?, ?)""",
            (router_id, actor, _now(), focus_start, focus_end, focus_note[:1000]),
        )
        return int(cur.lastrowid)


def _render_report(text: str) -> str:
    out = []
    for raw in (text or "").splitlines():
        line = html.escape(raw)
        if line.startswith("# "):
            out.append(f"<h3>{line[2:]}</h3>")
        elif line.startswith("- ") or line.startswith("* "):
            out.append(f"<div style='margin:5px 0 5px 12px'>• {line[2:]}</div>")
        elif line.strip():
            out.append(f"<div style='margin:5px 0'>{line}</div>")
    return "".join(out)


def register(app, page_func):
    migrations.migrate()

    @app.get("/ai/{router_id}", response_class=HTMLResponse)
    def ai_router(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        router = _router(router_id)
        if not router:
            return RedirectResponse("/routers", status_code=303)
        csrf = core.csrf_token(request)
        with core.db() as conn:
            rows = conn.execute(
                "SELECT id,status,requested_by,created_at,started_at,finished_at,report,error_code,error_detail,focus_start,focus_end,focus_note FROM router_ai_analyses WHERE router_id=? ORDER BY id DESC LIMIT 20",
                (router_id,),
            ).fetchall()
        requested = request.query_params.get("report", "")
        selected = None
        if requested.isdigit():
            selected = next((r for r in rows if int(r["id"]) == int(requested)), None)
        if selected is None:
            selected = next((r for r in rows if r["status"] == "succeeded" and r["report"]), None)

        if selected and selected["report"]:
            report_html = _render_report(selected["report"])
        else:
            report_html = '<div class="muted">No completed AI analysis yet.</div>'

        active = next((r for r in rows if r["status"] in {"queued", "running"}), None)
        if active:
            status_notice = f'''<div class="panel pad"><strong>AI analysis {html.escape(active['status'])}.</strong><div class="muted">Job #{active['id']} is isolated from Guardian and router-changing jobs. Refresh this page shortly.</div></div>'''
            button = '<button disabled>Analysis in progress…</button>'
        else:
            status_notice = ""
            button = '<button class="primary">Analyze router now</button>'

        history_rows = []
        for r in rows:
            detail = ""
            if r["status"] == "failed":
                detail = f'<div class="error"><strong>{html.escape(r["error_code"] or "AI_ANALYSIS_FAILED")}</strong> {html.escape(r["error_detail"] or "")}</div>'
            link = f'<a href="/ai/{router_id}?report={r["id"]}">View report</a>' if r["report"] else ""
            history_rows.append(
                f'''<tr><td>#{r['id']}</td><td>{html.escape(r['created_at'] or '')}<div class="muted">{html.escape((r['focus_start'] or '') + (' → ' + r['focus_end'] if r['focus_end'] else ''))}</div></td><td>{html.escape(r['status'])}</td><td>{html.escape(r['requested_by'] or '-')}<div class="muted">{html.escape(r['focus_note'] or '')}</div></td><td>{link}{detail}</td></tr>'''
            )
        history = "".join(history_rows) or '<tr><td colspan="5">No AI analysis history.</td></tr>'

        body = f'''<div class="panel pad"><h2>AI analysis · {html.escape(router['site_name'])}</h2><div class="muted">Read-only. Tikcentral collects live RouterOS data, sanitizes sensitive values, and sends only that snapshot to an isolated Codex CLI identity. Codex cannot apply RouterOS changes.</div><div class="inline" style="margin-top:12px"><form method="post" action="/ai/{router_id}/analyze"><input type="hidden" name="csrf" value="{csrf}"><select name="focus_hours"><option value="0">General analysis</option><option value="2">Incident · last 2h</option><option value="6">Incident · last 6h</option><option value="24">Incident · last 24h</option><option value="168">Incident · last 7d</option></select><input name="focus_note" maxlength="500" placeholder="Optional incident note / symptom">{button}</form><a href="/operations/{router_id}"><button>Back to router</button></a></div></div>{status_notice}<div class="panel pad">{report_html}</div><div class="panel"><table><thead><tr><th>Job</th><th>Requested</th><th>Status</th><th>By</th><th>Result</th></tr></thead><tbody>{history}</tbody></table></div>'''
        return page_func("AI Analysis", body, user, "operations")

    @app.post("/ai/{router_id}/analyze", response_class=HTMLResponse)
    async def analyze_router(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        actor = user["email"] if "email" in user.keys() else "admin"
        try:
            hours = int(data.get("focus_hours", "0") or 0)
        except ValueError:
            hours = 0
        hours = hours if hours in {0, 2, 6, 24, 168} else 0
        focus_end = _now() if hours else ""
        focus_start = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat() if hours else ""
        focus_note = data.get("focus_note", "").strip()[:500]
        try:
            queue_analysis(router_id, actor, focus_start, focus_end, focus_note)
        except Exception:
            pass
        return RedirectResponse(f"/ai/{router_id}", status_code=303)
