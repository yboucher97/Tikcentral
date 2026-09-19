"""Fleet backup/analysis web routes.

Fleet-wide mutations are intentionally not exposed here. RouterOS/RouterBOOT
changes use the serialized Operations workflow one router at a time.
"""

import html
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import fleet
from app import main as core
from app import ui

app = core.app


def require_user(request: Request):
    return core.require_web_admin(request)


def job_table(rows):
    out = []
    for row in rows:
        out.append(
            f'''<tr><td><a href="/automation/jobs/{row['id']}">#{row['id']}</a></td><td>{html.escape(row['job_type'])}</td><td>{html.escape(row['status'])}</td><td>{row['succeeded']}/{row['total']}</td><td>{row['failed']}</td><td>{html.escape(row['created_by'])}</td><td class="muted">{html.escape(row['created_at'])}</td></tr>'''
        )
    return "".join(out) or '<tr><td colspan="7">No fleet jobs yet.</td></tr>'


@app.get("/automation", response_class=HTMLResponse)
def automation_page(request: Request):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    csrf = core.csrf_token(request)
    fleet.ensure_schema()
    with core.db() as conn:
        config = conn.execute("SELECT * FROM fleet_settings WHERE id=1").fetchone()
        fleet_jobs = conn.execute("SELECT * FROM fleet_jobs ORDER BY id DESC LIMIT 25").fetchall()
        findings = conn.execute(
            """SELECT f.*,r.site_name FROM fleet_findings f
               JOIN routers r ON r.id=f.router_id ORDER BY f.id DESC LIMIT 20"""
        ).fetchall()
        managed_count = conn.execute("SELECT COUNT(*) FROM routers WHERE enabled=1 AND COALESCE(lifecycle_state,'production')<>'retired'").fetchone()[0]

    finding_rows = "".join(
        f'''<tr><td>{html.escape(x['severity'])}</td><td>{html.escape(x['site_name'])}</td><td>{html.escape(x['category'])}</td><td>{html.escape(x['summary'])}</td><td class="muted">{html.escape(x['detected_at'])}</td></tr>'''
        for x in findings
    ) or '<tr><td colspan="5">No findings recorded yet.</td></tr>'

    checked = "checked" if config["backups_enabled"] else ""
    analysis_checked = "checked" if config["analysis_enabled"] else ""
    can_manage = user["role"] == "admin"
    disabled = "" if can_manage else "disabled"
    settings_note = "" if can_manage else '<div class="muted" style="margin-top:10px">Administrator access is required to change the fleet schedule.</div>'
    body = f'''
<div class="cards"><div class="card"><div class="muted">Enabled routers</div><div class="value">{managed_count}</div></div><div class="card"><div class="muted">Daily backup</div><div class="value">{html.escape(config['backup_time'])}</div><div class="muted">{html.escape(config['timezone'])}</div></div><div class="card"><div class="muted">Daily backup retention</div><div class="value">{config['backup_retention_days']}d</div></div></div>
<div class="panel pad"><h2>Backup schedule</h2><form class="inline" method="post" action="/automation/settings"><input type="hidden" name="csrf" value="{csrf}"><label><input type="checkbox" name="backups_enabled" value="1" {checked} {disabled}> Daily backups</label><input type="time" name="backup_time" value="{html.escape(config['backup_time'])}" required {disabled}><input name="timezone" value="{html.escape(config['timezone'])}" style="min-width:180px" {disabled}><input type="number" min="1" max="3650" name="retention" value="{config['backup_retention_days']}" style="width:100px" {disabled}><label><input type="checkbox" name="analysis_enabled" value="1" {analysis_checked} {disabled}> Read-only analysis after backup</label><button class="primary" {disabled}>Save schedule</button></form><div class="muted" style="margin-top:10px">Daily backups rotate. Pre-change and commissioning backups are retained separately.</div>{settings_note}</div>
<div class="panel pad"><h2>Run now</h2><div class="inline"><form method="post" action="/automation/backup"><input type="hidden" name="csrf" value="{csrf}"><button class="primary">Backup all routers now</button></form><form method="post" action="/automation/analyze"><input type="hidden" name="csrf" value="{csrf}"><button>Run read-only analysis</button></form><a href="/operations"><button>Router changes / upgrades</button></a></div><div class="muted" style="margin-top:10px">Fleet-wide arbitrary commands and mass RouterOS upgrades are intentionally not available. Changes are serialized per router under Operations.</div></div>
<div class="panel"><table><thead><tr><th>Job</th><th>Type</th><th>Status</th><th>Success</th><th>Errors</th><th>Started by</th><th>Created</th></tr></thead><tbody>{job_table(fleet_jobs)}</tbody></table></div>
<div class="panel"><table><thead><tr><th>Severity</th><th>Site</th><th>Category</th><th>Finding</th><th>Detected</th></tr></thead><tbody>{finding_rows}</tbody></table></div>'''
    return ui.page("Automation", body, user, "automation")


@app.post("/automation/settings")
async def automation_settings(request: Request):
    user = core.require_web_role(request, "admin")
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request)
    core.require_csrf(request, data.get("csrf", ""))
    backup_time = data.get("backup_time", "03:00")
    try:
        hour, minute = (int(x) for x in backup_time.split(":", 1))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="invalid backup time")
    if not (0 <= hour <= 23 and 0 <= minute <= 59) or backup_time != f"{hour:02d}:{minute:02d}":
        raise HTTPException(status_code=400, detail="invalid backup time")
    try:
        retention = max(1, min(3650, int(data.get("retention", "30"))))
    except ValueError:
        retention = 30
    timezone_name = data.get("timezone", "America/Toronto").strip()[:80] or "America/Toronto"
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError):
        raise HTTPException(status_code=400, detail="invalid timezone")
    with core.db() as conn:
        conn.execute(
            "UPDATE fleet_settings SET backups_enabled=?,backup_time=?,timezone=?,backup_retention_days=?,analysis_enabled=? WHERE id=1",
            (
                1 if data.get("backups_enabled") else 0,
                backup_time,
                timezone_name,
                retention,
                1 if data.get("analysis_enabled") else 0,
            ),
        )
    return RedirectResponse("/automation", status_code=303)


@app.post("/automation/backup")
async def automation_backup(request: Request):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request)
    core.require_csrf(request, data.get("csrf", ""))
    job_id = fleet.run_backup_job(user["email"])
    return RedirectResponse(f"/automation/jobs/{job_id}", status_code=303)


@app.post("/automation/analyze")
async def automation_analyze(request: Request):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request)
    core.require_csrf(request, data.get("csrf", ""))
    job_id = fleet.run_analysis_job(user["email"])
    return RedirectResponse(f"/automation/jobs/{job_id}", status_code=303)


@app.get("/automation/jobs/{job_id}", response_class=HTMLResponse)
def automation_job(job_id: int, request: Request):
    user = require_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with core.db() as conn:
        job = conn.execute("SELECT * FROM fleet_jobs WHERE id=?", (job_id,)).fetchone()
        results = conn.execute(
            "SELECT * FROM fleet_job_results WHERE job_id=? ORDER BY site_name COLLATE NOCASE",
            (job_id,),
        ).fetchall()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    rows = []
    for result in results:
        details = html.escape((result["output"] or result["error"] or "-")[:20000])
        rows.append(
            f'''<tr><td>{html.escape(result['site_name'])}</td><td><code>{html.escape(result['vpn_ip'])}</code></td><td>{html.escape(result['status'])}</td><td><details><summary>View result</summary><pre style="white-space:pre-wrap;max-width:900px">{details}</pre></details></td></tr>'''
        )
    body = f'''<div class="panel pad"><h2>Fleet job #{job['id']}</h2><div><strong>{html.escape(job['job_type'])}</strong> — {html.escape(job['status'])}</div><div class="muted">{job['succeeded']} succeeded, {job['failed']} failed of {job['total']}</div><a href="/automation">Back to Automation</a></div><div class="panel"><table><thead><tr><th>Site</th><th>VPN IP</th><th>Status</th><th>Output / Error</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="4">No results.</td></tr>'}</tbody></table></div>'''
    return ui.page(f"Job {job_id}", body, user, "automation")
