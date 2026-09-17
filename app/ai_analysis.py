"""Read-only Codex analysis for router snapshots.

Tikcentral remains the only component that talks to routers. Codex receives a
sanitized snapshot through a dedicated helper and can only return an
operator-facing report. It never receives router credentials and never executes
RouterOS mutations.
"""

import html
import json
import re
import subprocess
import threading
from datetime import datetime, timezone

from fastapi import BackgroundTasks, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import errors, events, main as core, migrations, operations, router_exec, settings

_ACTIVE: set[int] = set()
_ACTIVE_LOCK = threading.Lock()


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
    for pattern in (
        r'(?i)(password|passwd|passphrase|secret|token|private[-_ ]?key|preshared[-_ ]?key|community)\s*[=:]\s*([^\s;]+)',
        r'(?i)(pppoe[^\n]{0,80}password\s*[=:]\s*)([^\s;]+)',
    ):
        value = re.sub(pattern, lambda m: f"{m.group(1)}=<redacted>" if m.lastindex == 2 else "<redacted>", value)
    return value[: settings.AI_MAX_SECTION_CHARS]


def _safe_read(ip: str, command: str, label: str) -> dict:
    try:
        return {"ok": True, "data": _sanitize(router_exec.read(ip, command, timeout=settings.AI_ROUTER_READ_TIMEOUT, label=label))}
    except Exception as exc:
        return {"ok": False, "error": errors.short(exc)}


def collect_snapshot(router_id: int) -> dict:
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
        recent_events = conn.execute("SELECT * FROM router_events WHERE router_id=? AND category<>'ai-analysis' ORDER BY id DESC LIMIT 100", (router_id,)).fetchall()
        recent_jobs = conn.execute("SELECT * FROM router_jobs WHERE router_id=? ORDER BY id DESC LIMIT 30", (router_id,)).fetchall()

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
        "recent_events": [dict(r) for r in recent_events],
        "recent_jobs": [dict(r) for r in recent_jobs],
        "live": {
            "configuration": _safe_read(router["vpn_ip"], "/export show-sensitive=no", "AI configuration export"),
            "logs": _safe_read(router["vpn_ip"], "/log print without-paging", "AI log collection"),
            "interfaces": _safe_read(router["vpn_ip"], "/interface print stats-detail without-paging", "AI interface collection"),
            "routes": _safe_read(router["vpn_ip"], "/ip route print detail without-paging", "AI route collection"),
            "dhcp_clients": _safe_read(router["vpn_ip"], "/ip dhcp-client print detail without-paging", "AI DHCP collection"),
            "pppoe_clients": _safe_read(router["vpn_ip"], "/interface pppoe-client print detail without-paging", "AI PPPoE collection"),
        },
    }


def _prompt(snapshot: dict) -> str:
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
End with: **No action was taken.**

TIKCENTRAL SNAPSHOT:
{payload}
"""


def run_analysis(router_id: int, actor: str) -> int:
    snapshot = collect_snapshot(router_id)
    proc = subprocess.run(
        ["sudo", "-n", settings.AI_CODEX_HELPER],
        input=_prompt(snapshot),
        text=True,
        capture_output=True,
        timeout=settings.AI_TIMEOUT,
    )
    if proc.returncode != 0:
        detail = _sanitize((proc.stderr or proc.stdout or "Codex returned an error")[-4000:])
        raise errors.OperationError("AI_CODEX_FAILED", "Codex analysis failed", detail)
    report = (proc.stdout or "").strip()
    if not report:
        raise errors.OperationError("AI_EMPTY_RESULT", "Codex returned an empty analysis")
    report = _sanitize(report)[: settings.AI_MAX_REPORT_CHARS]
    with core.db() as conn:
        cur = conn.execute(
            "INSERT INTO router_events(router_id,event_at,severity,category,summary,details) VALUES(?,?,?,?,?,?)",
            (router_id, _now(), "info", "ai-analysis", f"AI router analysis by {actor}", report),
        )
        return int(cur.lastrowid)


def _background_analysis(router_id: int, actor: str):
    try:
        run_analysis(router_id, actor)
    except Exception as exc:
        err = errors.from_exception(exc, "AI_ANALYSIS_FAILED", "AI router analysis failed")
        try:
            events.record(router_id, "ai", "AI router analysis failed", f"{err.code}: {err.detail}", "warning")
        except Exception:
            pass
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE.discard(router_id)


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
            rows = conn.execute("SELECT id,event_at,summary,details FROM router_events WHERE router_id=? AND category='ai-analysis' ORDER BY id DESC LIMIT 12", (router_id,)).fetchall()
        latest = rows[0] if rows else None
        latest_html = _render_report(latest["details"]) if latest else '<div class="muted">No AI analysis has been run for this router.</div>'
        history = ''.join(f'<tr><td>{html.escape(r["event_at"])}</td><td><a href="/ai/{router_id}?report={r["id"]}">{html.escape(r["summary"])}</a></td></tr>' for r in rows) or '<tr><td colspan="2">No history.</td></tr>'
        requested = request.query_params.get("report", "")
        if requested.isdigit():
            with core.db() as conn:
                selected = conn.execute("SELECT details FROM router_events WHERE id=? AND router_id=? AND category='ai-analysis'", (int(requested), router_id)).fetchone()
            if selected:
                latest_html = _render_report(selected["details"])
        with _ACTIVE_LOCK:
            running = router_id in _ACTIVE
        queued_notice = '<div class="panel pad"><strong>AI analysis is running.</strong><div class="muted">Refresh this page shortly. Router operations and Guardian continue normally.</div></div>' if running or request.query_params.get("queued") else ""
        button = '<button disabled>Analysis running…</button>' if running else '<button class="primary">Analyze router now</button>'
        body = f'''<div class="panel pad"><h2>AI analysis · {html.escape(router['site_name'])}</h2><div class="muted">Read-only. Tikcentral collects and sanitizes router data; Codex runs under an isolated Linux identity and cannot apply RouterOS changes.</div><div class="inline" style="margin-top:12px"><form method="post" action="/ai/{router_id}/analyze"><input type="hidden" name="csrf" value="{csrf}">{button}</form><a href="/operations/{router_id}"><button>Back to router</button></a></div></div>{queued_notice}<div class="panel pad">{latest_html}</div><div class="panel"><table><thead><tr><th>Time</th><th>Analysis</th></tr></thead><tbody>{history}</tbody></table></div>'''
        return page_func("AI Analysis", body, user, "operations")

    @app.post("/ai/{router_id}/analyze", response_class=HTMLResponse)
    async def analyze_router(router_id: int, request: Request, background_tasks: BackgroundTasks):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        router = _router(router_id)
        if not router or not router["enabled"]:
            return RedirectResponse("/routers", status_code=303)
        actor = user["email"] if "email" in user.keys() else "admin"
        with _ACTIVE_LOCK:
            if router_id not in _ACTIVE:
                _ACTIVE.add(router_id)
                background_tasks.add_task(_background_analysis, router_id, actor)
        return RedirectResponse(f"/ai/{router_id}?queued=1", status_code=303)
