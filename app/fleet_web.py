import html
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import entrypoint
from app import fleet
from app import main as core
from app import portal

app = entrypoint.app
fleet.ensure_schema()

# Add Automation to the shared navigation without duplicating the portal shell.
_base_page = portal.portal_page


def fleet_page(title: str, body: str, user=None, active: str = "") -> HTMLResponse:
    response = _base_page(title, body, user, active)
    if not user:
        return response
    text = response.body.decode("utf-8")
    cls = "active" if active == "automation" else ""
    text = text.replace("</nav>", f'<a class="{cls}" href="/automation">Automation</a></nav>', 1)
    return HTMLResponse(text, status_code=response.status_code, headers=dict(response.headers))


portal.portal_page = fleet_page
core.page = fleet_page

# Extend every newly generated enrollment script with the Tikcentral machine identity.
_base_router_script = portal.build_routeros_script


def _ssh_public_key():
    path = Path("/etc/tikcentral/ssh/tikcentral_ed25519.pub")
    if not path.exists():
        return ""
    parts = path.read_text(encoding="utf-8").strip().split()
    return " ".join(parts[:2]) if len(parts) >= 2 else ""


def managed_router_script(site_name: str, token: str) -> str:
    script = _base_router_script(site_name, token)
    pub = _ssh_public_key().replace('"', '')
    if not pub:
        return script
    lines = script.splitlines()
    insert_at = len(lines)
    if lines and lines[-1].strip() == "}":
        insert_at -= 1
    managed = [
        "",
        "# Install Tikcentral managed service identity (WireGuard-only source)",
        ':if ([:len [/user find where name="tikcentral"]] = 0) do={',
        '    /user add name="tikcentral" group=full address=10.250.0.1/32 disabled=no comment="Tikcentral managed service"',
        '} else={',
        '    /user set [find where name="tikcentral"] group=full address=10.250.0.1/32 disabled=no comment="Tikcentral managed service"',
        '}',
        '/user ssh-keys remove [find where user="tikcentral"]',
        f'/user ssh-keys add user="tikcentral" key="{pub}" key-owner="Tikcentral VPS"',
        ':do { /ip service set [find where name="api"] disabled=no address=10.250.0.1/32 } on-error={ :put "Tikcentral warning: could not enable/restrict API service" }',
        ':if ([:len [/ip/firewall/filter find where comment="Tikcentral management SSH API"]] = 0) do={',
        '    /ip/firewall/filter add chain=input action=accept in-interface=$wgName src-address=10.250.0.1 protocol=tcp dst-port=22,8728 place-before=0 comment="Tikcentral management SSH API"',
        '}',
        ':put "Tikcentral managed SSH/API identity installed"',
    ]
    return "\n".join(lines[:insert_at] + managed + lines[insert_at:])


portal.build_routeros_script = managed_router_script


def require_admin(request: Request):
    user = core.require_web_admin(request)
    if not user:
        return None
    return user


def job_table(rows):
    out = []
    for r in rows:
        out.append(
            f'''<tr><td><a href="/automation/jobs/{r['id']}">#{r['id']}</a></td><td>{html.escape(r['job_type'])}</td><td>{html.escape(r['status'])}</td><td>{r['succeeded']}/{r['total']}</td><td>{r['failed']}</td><td>{html.escape(r['created_by'])}</td><td class="muted">{html.escape(r['created_at'])}</td></tr>'''
        )
    return "".join(out) or '<tr><td colspan="7" class="muted">No fleet jobs yet.</td></tr>'


@app.get("/automation", response_class=HTMLResponse)
def automation_page(request: Request):
    user = require_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    csrf = core.csrf_token(request)
    fleet.ensure_schema()
    with core.db() as conn:
        s = conn.execute("SELECT * FROM fleet_settings WHERE id=1").fetchone()
        jobs = conn.execute("SELECT * FROM fleet_jobs ORDER BY id DESC LIMIT 25").fetchall()
        findings = conn.execute(
            """SELECT f.*,r.site_name FROM fleet_findings f JOIN routers r ON r.id=f.router_id ORDER BY f.id DESC LIMIT 20"""
        ).fetchall()
        managed_count = conn.execute("SELECT COUNT(*) FROM routers WHERE enabled=1").fetchone()[0]

    finding_rows = "".join(
        f'''<tr><td>{html.escape(x['severity'])}</td><td>{html.escape(x['site_name'])}</td><td>{html.escape(x['category'])}</td><td>{html.escape(x['summary'])}</td><td class="muted">{html.escape(x['detected_at'])}</td></tr>'''
        for x in findings
    ) or '<tr><td colspan="5" class="muted">No findings recorded yet.</td></tr>'

    checked = "checked" if s["backups_enabled"] else ""
    analysis_checked = "checked" if s["analysis_enabled"] else ""
    body = f'''
<div class="cards"><div class="card"><div class="muted">Enabled routers</div><div class="value">{managed_count}</div></div><div class="card"><div class="muted">Daily backup</div><div class="value">{html.escape(s['backup_time'])}</div><div class="muted">{html.escape(s['timezone'])}</div></div><div class="card"><div class="muted">Retention</div><div class="value">{s['backup_retention_days']}d</div></div></div>
<div class="panel pad"><h2>Backup schedule</h2><form class="inline" method="post" action="/automation/settings"><input type="hidden" name="csrf" value="{csrf}"><label><input type="checkbox" name="backups_enabled" value="1" {checked}> Daily backups</label><input type="time" name="backup_time" value="{html.escape(s['backup_time'])}" required><input name="timezone" value="{html.escape(s['timezone'])}" style="min-width:180px"><input type="number" min="1" max="3650" name="retention" value="{s['backup_retention_days']}" style="width:100px"><label><input type="checkbox" name="analysis_enabled" value="1" {analysis_checked}> Analyze after backup</label><button class="primary">Save schedule</button></form><div class="muted" style="margin-top:10px">Each backup stores a sanitized RouterOS export and attempts an encrypted binary .backup copy. Binary backups use a server-generated backup password kept on the Tikcentral VPS.</div></div>
<div class="panel pad"><h2>Run now</h2><div class="inline"><form method="post" action="/automation/backup"><input type="hidden" name="csrf" value="{csrf}"><button class="primary">Backup all routers now</button></form><form method="post" action="/automation/analyze"><input type="hidden" name="csrf" value="{csrf}"><button>Analyze all routers now</button></form></div></div>
<div class="panel pad"><h2>Mass command</h2><form method="post" action="/automation/command"><input type="hidden" name="csrf" value="{csrf}"><textarea name="command" style="width:100%;min-height:110px" placeholder='/user add name="example" group=read password="..."' required></textarea><div class="inline" style="margin-top:10px"><label><input type="checkbox" name="confirm" value="yes" required> I reviewed this RouterOS command and want to run it on every enabled router.</label><button class="danger">Run on all routers</button></div></form><div class="muted" style="margin-top:10px">Tikcentral records success, output and error separately for every router.</div></div>
<div class="panel pad"><h2>Mass RouterOS update</h2><div class="inline"><form method="post" action="/automation/update/check"><input type="hidden" name="csrf" value="{csrf}"><button>Check updates on all routers</button></form><form method="post" action="/automation/update/install"><input type="hidden" name="csrf" value="{csrf}"><label><input type="checkbox" name="confirm" value="yes" required> Routers may reboot</label><button class="danger">Install updates on all routers</button></form></div></div>
<div class="panel"><table><thead><tr><th>Job</th><th>Type</th><th>Status</th><th>Success</th><th>Errors</th><th>Started by</th><th>Created UTC</th></tr></thead><tbody>{job_table(jobs)}</tbody></table></div>
<div class="panel"><table><thead><tr><th>Severity</th><th>Site</th><th>Category</th><th>Finding</th><th>Detected UTC</th></tr></thead><tbody>{finding_rows}</tbody></table></div>
<div class="panel pad"><h2>Existing routers</h2><div class="muted">Routers enrolled before this feature do not yet have the Tikcentral SSH key. Generate a fresh enrollment script for the same site and paste it once on that router. Existing WireGuard IP and Remote WinBox assignment are retained; the script adds the managed Tikcentral identity.</div><div style="margin-top:12px"><a href="/enroll"><button>Generate provisioning/enrollment script</button></a></div></div>'''
    return fleet_page("Automation", body, user, "automation")


@app.post("/automation/settings")
async def automation_settings(request: Request):
    user = require_admin(request)
    if not user: return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
    backup_time = data.get("backup_time", "03:00")
    if len(backup_time) != 5 or backup_time[2] != ":": raise HTTPException(status_code=400, detail="invalid backup time")
    try: retention = max(1, min(3650, int(data.get("retention", "30"))))
    except ValueError: retention = 30
    timezone_name = data.get("timezone", "America/Toronto").strip()[:80] or "America/Toronto"
    with core.db() as conn:
        conn.execute("UPDATE fleet_settings SET backups_enabled=?,backup_time=?,timezone=?,backup_retention_days=?,analysis_enabled=? WHERE id=1", (1 if data.get("backups_enabled") else 0, backup_time, timezone_name, retention, 1 if data.get("analysis_enabled") else 0))
    return RedirectResponse("/automation", status_code=303)


@app.post("/automation/command")
async def automation_command(request: Request):
    user = require_admin(request)
    if not user: return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
    command = data.get("command", "").strip()
    if data.get("confirm") != "yes" or not command: raise HTTPException(status_code=400, detail="command confirmation required")
    job = fleet.run_mass_command(command, user["email"])
    return RedirectResponse(f"/automation/jobs/{job}", status_code=303)


@app.post("/automation/backup")
async def automation_backup(request: Request):
    user = require_admin(request)
    if not user: return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
    job = fleet.run_backup_job(user["email"])
    return RedirectResponse(f"/automation/jobs/{job}", status_code=303)


@app.post("/automation/analyze")
async def automation_analyze(request: Request):
    user = require_admin(request)
    if not user: return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
    job = fleet.run_analysis_job(user["email"])
    return RedirectResponse(f"/automation/jobs/{job}", status_code=303)


@app.post("/automation/update/check")
async def automation_update_check(request: Request):
    user = require_admin(request)
    if not user: return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
    job = fleet.run_mass_command('/system package update check-for-updates; :delay 3s; /system package update print', user["email"])
    return RedirectResponse(f"/automation/jobs/{job}", status_code=303)


@app.post("/automation/update/install")
async def automation_update_install(request: Request):
    user = require_admin(request)
    if not user: return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
    if data.get("confirm") != "yes": raise HTTPException(status_code=400, detail="reboot confirmation required")
    job = fleet.run_mass_command('/system package update install', user["email"])
    return RedirectResponse(f"/automation/jobs/{job}", status_code=303)


@app.get("/automation/jobs/{job_id}", response_class=HTMLResponse)
def automation_job(job_id: int, request: Request):
    user = require_admin(request)
    if not user: return RedirectResponse("/login", status_code=303)
    with core.db() as conn:
        job = conn.execute("SELECT * FROM fleet_jobs WHERE id=?", (job_id,)).fetchone()
        results = conn.execute("SELECT * FROM fleet_job_results WHERE job_id=? ORDER BY site_name COLLATE NOCASE", (job_id,)).fetchall()
    if not job: raise HTTPException(status_code=404, detail="job not found")
    rows = []
    for r in results:
        details = html.escape((r["output"] or r["error"] or "-")[:20000])
        rows.append(f'''<tr><td>{html.escape(r['site_name'])}</td><td><code>{html.escape(r['vpn_ip'])}</code></td><td>{html.escape(r['status'])}</td><td><details><summary>View result</summary><pre style="white-space:pre-wrap;max-width:900px">{details}</pre></details></td></tr>''')
    body = f'''<div class="panel pad"><h2>Fleet job #{job['id']}</h2><div><strong>{html.escape(job['job_type'])}</strong> — {html.escape(job['status'])}</div><div class="muted">{job['succeeded']} succeeded, {job['failed']} failed of {job['total']}</div><pre style="white-space:pre-wrap">{html.escape(job['command'] or '')}</pre><a href="/automation">← Automation</a></div><div class="panel"><table><thead><tr><th>Site</th><th>VPN IP</th><th>Status</th><th>Output / Error</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="4">No results.</td></tr>'}</tbody></table></div>'''
    return fleet_page(f"Job {job_id}", body, user, "automation")
