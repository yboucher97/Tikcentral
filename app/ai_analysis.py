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
from datetime import datetime, timezone

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


def collect_snapshot(router_id: int) -> dict:
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
        telemetry = conn.execute("SELECT * FROM router_telemetry WHERE router_id=? ORDER BY id DESC LIMIT 24", (router_id,)).fetchall()
        recent_events = conn.execute("SELECT * FROM router_events WHERE router_id=? ORDER BY id DESC LIMIT 100", (router_id,)).fetchall()
        recent_jobs = conn.execute("SELECT * FROM router_jobs WHERE router_id=? ORDER BY id DESC LIMIT 30", (router_id,)).fetchall()
        access_history = conn.execute(
            """SELECT checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok,
                      ssh_latency_ms,winbox_latency_ms,api_latency_ms
               FROM router_access_history WHERE router_id=? ORDER BY id DESC LIMIT 120""",
            (router_id,),
        ).fetchall()
        snapshots = conn.execute(
            "SELECT id,captured_at,sha256,content FROM router_snapshots WHERE router_id=? ORDER BY id DESC LIMIT 3",
            (router_id,),
        ).fetchall()
        maintenance = conn.execute("SELECT * FROM router_maintenance WHERE router_id=?", (router_id,)).fetchone()
        incidents = conn.execute(
            "SELECT * FROM fleet_incidents ORDER BY id DESC LIMIT 30"
        ).fetchall()
        transactions = conn.execute(
            "SELECT * FROM change_transactions WHERE router_id=? ORDER BY id DESC LIMIT 20",
            (router_id,),
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
        "snapshot_version": 1,
        "captured_at": _now(),
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

Prioritize management access, WAN, interface errors/flaps, routes, DHCP/PPPoE, CPU/memory, versions, configuration drift, recent jobs/events, and suspicious log patterns.
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


def queue_analysis(router_id: int, actor: str) -> int:
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
            "INSERT INTO router_ai_analyses(router_id,status,requested_by,created_at) VALUES(?, 'queued', ?, ?)",
            (router_id, actor, _now()),
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
                "SELECT id,status,requested_by,created_at,started_at,finished_at,report,error_code,error_detail FROM router_ai_analyses WHERE router_id=? ORDER BY id DESC LIMIT 20",
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
                f'''<tr><td>#{r['id']}</td><td>{html.escape(r['created_at'] or '')}</td><td>{html.escape(r['status'])}</td><td>{html.escape(r['requested_by'] or '-')}</td><td>{link}{detail}</td></tr>'''
            )
        history = "".join(history_rows) or '<tr><td colspan="5">No AI analysis history.</td></tr>'

        body = f'''<div class="panel pad"><h2>AI analysis · {html.escape(router['site_name'])}</h2><div class="muted">Read-only. Tikcentral collects live RouterOS data, sanitizes sensitive values, and sends only that snapshot to an isolated Codex CLI identity. Codex cannot apply RouterOS changes.</div><div class="inline" style="margin-top:12px"><form method="post" action="/ai/{router_id}/analyze"><input type="hidden" name="csrf" value="{csrf}">{button}</form><a href="/operations/{router_id}"><button>Back to router</button></a></div></div>{status_notice}<div class="panel pad">{report_html}</div><div class="panel"><table><thead><tr><th>Job</th><th>Requested</th><th>Status</th><th>By</th><th>Result</th></tr></thead><tbody>{history}</tbody></table></div>'''
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
            queue_analysis(router_id, actor)
        except Exception:
            pass
        return RedirectResponse(f"/ai/{router_id}", status_code=303)
