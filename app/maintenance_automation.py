"""Post-change verification/maintenance automation."""

from datetime import datetime, timezone

from app import compliance, desired_state, events, interface_monitor, main as core, migrations, operations, security_audit, wan_probe


def _now(): return datetime.now(timezone.utc).isoformat()


def _eligible(kind,settings):
    if settings["run_on_all_changes"]: return kind not in {"backup"}
    if settings["run_on_upgrades"] and kind.startswith("upgrade"): return True
    if settings["run_on_routerboot"] and kind.startswith("routerboot"): return True
    return False


def process():
    migrations.migrate()
    with core.db() as conn:
        s=conn.execute("SELECT * FROM maintenance_automation_settings WHERE id=1").fetchone()
        if not s or not s["enabled"]: return 0
        jobs=conn.execute(
            """SELECT j.* FROM router_jobs j LEFT JOIN maintenance_automation_runs a ON a.job_id=j.id
               WHERE j.status='succeeded' AND j.router_id IS NOT NULL AND a.job_id IS NULL
               ORDER BY j.id LIMIT 20"""
        ).fetchall()
    count=0
    for j in jobs:
        if not _eligible(j["kind"],s):
            with core.db() as conn:
                conn.execute("INSERT OR IGNORE INTO maintenance_automation_runs(job_id,router_id,job_kind,processed_at,status,summary) VALUES(?,?,?,?,?,?)",
                             (j["id"],j["router_id"],j["kind"],_now(),"skipped","Trigger not enabled"))
            continue
        results=[]
        def run(label,fn):
            try:
                fn(); results.append(f"{label}=ok")
            except Exception as exc:
                results.append(f"{label}=failed:{str(exc)[:180]}")
        if s["capture_backup"]: run("backup",lambda: operations.backup_router(j["router_id"],"post-change","maintenance-automation",track_job=False))
        if s["run_compliance"]: run("compliance",lambda: compliance.evaluate(j["router_id"]))
        if s["run_security"]: run("security",lambda: security_audit.collect(j["router_id"]))
        if s["run_wan_probe"]: run("wan_probe",lambda: wan_probe.collect(j["router_id"]))
        if s["run_interfaces"]: run("interfaces",lambda: interface_monitor.collect(j["router_id"]))
        if s["run_desired_state"]: run("desired_state",lambda: desired_state.check(j["router_id"]))
        summary="; ".join(results)
        status="completed" if not any("=failed:" in x for x in results) else "partial"
        with core.db() as conn:
            conn.execute("INSERT OR REPLACE INTO maintenance_automation_runs(job_id,router_id,job_kind,processed_at,status,summary) VALUES(?,?,?,?,?,?)",
                         (j["id"],j["router_id"],j["kind"],_now(),status,summary))
            conn.execute(
                """INSERT INTO router_maintenance_history(router_id,occurred_at,technician,work_type,ticket_reference,issue,work_performed,result,follow_up,created_by,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (j["router_id"],_now(),"Tikcentral automation","maintenance","","Post-change automated verification",
                 f'Completed after job #{j["id"]} ({j["kind"]})',summary,"Review failed checks if any","maintenance-automation",_now()),
            )
        events.record(j["router_id"],"maintenance-automation",f"Post-change verification {status}",summary,"warning" if status=="partial" else "info")
        count+=1
    return count


def register(app,page_func):
    from fastapi import Request
    from fastapi.responses import HTMLResponse, RedirectResponse
    import html

    @app.get("/maintenance-automation",response_class=HTMLResponse)
    def page(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        with core.db() as conn:
            s=conn.execute("SELECT * FROM maintenance_automation_settings WHERE id=1").fetchone()
            runs=conn.execute(
                """SELECT a.*,r.site_name FROM maintenance_automation_runs a JOIN routers r ON r.id=a.router_id
                   ORDER BY a.processed_at DESC LIMIT 100"""
            ).fetchall()
        csrf=core.csrf_token(request)
        def ck(k): return "checked" if s[k] else ""
        rows="".join(f'<tr><td>{html.escape(x["processed_at"])}</td><td>{html.escape(x["site_name"])}</td><td>#{x["job_id"]} {html.escape(x["job_kind"])}</td><td>{html.escape(x["status"])}</td><td>{html.escape(x["summary"])}</td></tr>' for x in runs) or '<tr><td colspan="5">No runs yet.</td></tr>'
        body=f'''<div class="panel pad"><h2>Maintenance automation</h2>
<div class="muted">Default standard: run after successful RouterOS upgrades and RouterBOOT changes. Backup + compliance + security + WAN + interfaces + desired-state checks.</div>
<form method="post" action="/maintenance-automation"><input type="hidden" name="csrf" value="{csrf}">
<label><input type="checkbox" name="enabled" value="1" {ck("enabled")}> Enabled</label>
<label><input type="checkbox" name="run_on_upgrades" value="1" {ck("run_on_upgrades")}> After upgrades</label>
<label><input type="checkbox" name="run_on_routerboot" value="1" {ck("run_on_routerboot")}> After RouterBOOT</label>
<label><input type="checkbox" name="run_on_all_changes" value="1" {ck("run_on_all_changes")}> After all successful changes</label>
<label><input type="checkbox" name="capture_backup" value="1" {ck("capture_backup")}> Capture post-change backup</label>
<label><input type="checkbox" name="run_compliance" value="1" {ck("run_compliance")}> Compliance</label>
<label><input type="checkbox" name="run_security" value="1" {ck("run_security")}> Security audit</label>
<label><input type="checkbox" name="run_wan_probe" value="1" {ck("run_wan_probe")}> WAN probe</label>
<label><input type="checkbox" name="run_interfaces" value="1" {ck("run_interfaces")}> Interfaces</label>
<label><input type="checkbox" name="run_desired_state" value="1" {ck("run_desired_state")}> Desired state</label>
<button class="primary">Save automation standard</button></form></div>
<div class="panel"><table><thead><tr><th>Time</th><th>Site</th><th>Job</th><th>Status</th><th>Summary</th></tr></thead><tbody>{rows}</tbody></table></div>'''
        return page_func("Maintenance Automation",body,user,"operations")

    @app.post("/maintenance-automation")
    async def save(request:Request):
        user=core.require_web_role(request,"admin")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        keys=["enabled","run_on_upgrades","run_on_routerboot","run_on_all_changes","capture_backup","run_compliance","run_security","run_wan_probe","run_interfaces","run_desired_state"]
        vals=[1 if data.get(k)=="1" else 0 for k in keys]
        with core.db() as conn:
            conn.execute("UPDATE maintenance_automation_settings SET "+",".join(f"{k}=?" for k in keys)+" WHERE id=1",vals)
        return RedirectResponse("/maintenance-automation",303)
