"""Read-only Codex analysis for router snapshots.

Tikcentral remains the only component that talks to routers. Codex receives a
sanitized snapshot in an isolated temporary directory and can only return an
operator-facing report. It never receives router credentials and never executes
RouterOS mutations.
"""

import html
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import errors, events, main as core, migrations, operations, router_exec, settings


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
        value = re.sub(pattern, lambda m: f"{m.group(1)}=<redacted>" if m.lastindex == 2 else "<redacted>", value)
    return value[: settings.AI_MAX_SECTION_CHARS]


def _safe_read(ip: str, command: str, label: str, timeout: int = 60) -> dict:
    try:
        return {"ok": True, "data": _sanitize(router_exec.read(ip, command, timeout=timeout, label=label))}
    except Exception as exc:
        return {"ok": False, "error": errors.short(exc)}


def collect_snapshot(router_id: int) -> dict:
    migrations.migrate()
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise errors.OperationError("ROUTER_NOT_FOUND", "Enabled router not found")

    # Refresh the lightweight core telemetry first, but analysis is still useful
    # if an optional telemetry probe fails.
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

    def row_dict(row):
        return dict(row) if row else None

    live = {
        "configuration": _safe_read(router["vpn_ip"], "/export show-sensitive=no", "AI configuration export", settings.AI_ROUTER_READ_TIMEOUT),
        "logs": _safe_read(router["vpn_ip"], "/log print without-paging", "AI log collection", settings.AI_ROUTER_READ_TIMEOUT),
        "interfaces": _safe_read(router["vpn_ip"], "/interface print stats-detail without-paging", "AI interface collection", settings.AI_ROUTER_READ_TIMEOUT),
        "routes": _safe_read(router["vpn_ip"], "/ip route print detail without-paging", "AI route collection", settings.AI_ROUTER_READ_TIMEOUT),
        "dhcp_clients": _safe_read(router["vpn_ip"], "/ip dhcp-client print detail without-paging", "AI DHCP collection", settings.AI_ROUTER_READ_TIMEOUT),
        "pppoe_clients": _safe_read(router["vpn_ip"], "/interface pppoe-client print detail without-paging", "AI PPPoE collection", settings.AI_ROUTER_READ_TIMEOUT),
    }

    return {
        "snapshot_version": 1,
        "captured_at": _now(),
        "router": {k: router[k] for k in router.keys() if k not in {"public_key"}},
        "access": row_dict(access),
        "expected_state": row_dict(expected),
        "update_status": row_dict(update),
        "telemetry_error": telemetry_error,
        "telemetry_history": [dict(r) for r in telemetry],
        "recent_events": [dict(r) for r in recent_events],
        "recent_jobs": [dict(r) for r in recent_jobs],
        "live": live,
    }


def _prompt(snapshot: dict) -> str:
    payload = json.dumps(snapshot, indent=2, ensure_ascii=False)
    return f"""You are analyzing one MikroTik RouterOS site for an experienced network technician.
Use ONLY the supplied Tikcentral snapshot. Do not use tools, shell commands, network access, or outside assumptions.
Never suggest that an observed condition exists unless the snapshot supports it. Distinguish confirmed findings from things worth checking.
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
    captured = snapshot["captured_at"]
    with core.db() as conn:
        cur = conn.execute(
            "INSERT INTO router_ai_analyses(router_id,created_at,created_by,status,snapshot_json) VALUES(?,?,?,?,?)",
            (router_id, captured, actor, "running", json.dumps(snapshot, ensure_ascii=False)),
        )
        analysis_id = int(cur.lastrowid)

    codex_home = Path(settings.AI_CODEX_HOME)
    codex_home.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="tikcentral-ai-", dir=settings.AI_TEMP_ROOT) as tmp:
            tmp_path = Path(tmp)
            os.chmod(tmp_path, 0o700)
            (tmp_path / "snapshot.json").write_text(json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
            env = os.environ.copy()
            env["HOME"] = str(codex_home)
            command = [
                settings.AI_CODEX_BIN, "exec", "--ephemeral", "--ignore-user-config",
                "--skip-git-repo-check", "--sandbox", "read-only", "-",
            ]
            proc = subprocess.run(
                command,
                input=_prompt(snapshot),
                text=True,
                capture_output=True,
                cwd=tmp,
                env=env,
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
            conn.execute(
                "UPDATE router_ai_analyses SET status='completed',finished_at=?,report_markdown=?,error='' WHERE id=?",
                (_now(), report, analysis_id),
            )
        events.record(router_id, "ai", "AI router analysis completed", f"analysis_id={analysis_id}")
        return analysis_id
    except Exception as exc:
        err = errors.from_exception(exc, "AI_ANALYSIS_FAILED", "AI router analysis failed")
        with core.db() as conn:
            conn.execute(
                "UPDATE router_ai_analyses SET status='failed',finished_at=?,error=? WHERE id=?",
                (_now(), f"{err.code}: {err.message} {err.detail}"[:4000], analysis_id),
            )
        events.record(router_id, "ai", "AI router analysis failed", f"{err.code}: {err.detail}", "warning")
        raise


def _render_report(text: str) -> str:
    # Keep rendering deliberately simple: escape everything, then support only
    # Markdown headings and bullet prefixes needed by the fixed report format.
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
            rows = conn.execute("SELECT id,created_at,created_by,status,finished_at,report_markdown,error FROM router_ai_analyses WHERE router_id=? ORDER BY id DESC LIMIT 12", (router_id,)).fetchall()
        latest = rows[0] if rows else None
        latest_html = '<div class="muted">No AI analysis has been run for this router.</div>'
        if latest:
            if latest["status"] == "completed":
                latest_html = _render_report(latest["report_markdown"])
            elif latest["status"] == "failed":
                latest_html = f'<div class="error">{html.escape(latest["error"] or "Analysis failed")}</div>'
            else:
                latest_html = f'<div class="muted">Analysis status: {html.escape(latest["status"])}</div>'
        history = ''.join(f'<tr><td>{html.escape(r["created_at"])}</td><td>{html.escape(r["created_by"])}</td><td>{html.escape(r["status"])}</td><td>{html.escape(r["finished_at"] or "-")}</td></tr>' for r in rows) or '<tr><td colspan="4">No history.</td></tr>'
        body = f'''<div class="panel pad"><h2>AI analysis · {html.escape(router['site_name'])}</h2><div class="muted">Read-only. Tikcentral collects and sanitizes router data; Codex never receives SSH credentials and cannot apply RouterOS changes.</div><div class="inline" style="margin-top:12px"><form method="post" action="/ai/{router_id}/analyze"><input type="hidden" name="csrf" value="{csrf}"><button class="primary">Analyze router now</button></form><a href="/operations/{router_id}"><button>Back to router</button></a></div></div><div class="panel pad">{latest_html}</div><div class="panel"><table><thead><tr><th>Started</th><th>By</th><th>Status</th><th>Finished</th></tr></thead><tbody>{history}</tbody></table></div>'''
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
            run_analysis(router_id, actor)
        except Exception as exc:
            err = errors.from_exception(exc)
            body = f'''<div class="panel pad"><h2>AI analysis failed</h2><div class="error"><strong>{html.escape(err.code)}</strong><div>{html.escape(err.message)}</div><div class="muted">{html.escape(err.detail)}</div></div><div style="margin-top:12px"><a href="/ai/{router_id}"><button class="primary">Back</button></a></div></div>'''
            return page_func("AI Analysis", body, user, "operations")
        return RedirectResponse(f"/ai/{router_id}", status_code=303)
