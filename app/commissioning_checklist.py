"""Operational commissioning checklist and optional automatic Production promotion."""

import html
import json
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations


def _now():return datetime.now(timezone.utc).isoformat()


def evaluate(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        r=conn.execute("SELECT * FROM routers WHERE id=?",(router_id,)).fetchone()
        if not r:return None
        cfg=conn.execute("SELECT * FROM commissioning_checklist_settings WHERE id=1").fetchone()
        site=conn.execute("SELECT * FROM router_site_metadata WHERE router_id=?",(router_id,)).fetchone()
        access=conn.execute("SELECT * FROM router_access_state WHERE router_id=?",(router_id,)).fetchone()
        wan=conn.execute("SELECT * FROM router_wan_probe_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
        desired=conn.execute("SELECT * FROM router_desired_state_status WHERE router_id=?",(router_id,)).fetchone()
        security=conn.execute("SELECT * FROM router_security_audit WHERE router_id=?",(router_id,)).fetchone()
        backup=conn.execute("SELECT id,created_at FROM router_backup_records WHERE router_id=? AND tier='commissioning' ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
        hardware=conn.execute("SELECT COUNT(*) c FROM hardware_inventory WHERE router_id=? AND status='installed'",(router_id,)).fetchone()["c"]
        expected=conn.execute("SELECT baseline_sha256,commissioning_status FROM router_expected_state WHERE router_id=?",(router_id,)).fetchone()

    checks=[]
    def add(key,label,required,passed,detail):
        checks.append({"key":key,"label":label,"required":bool(required),"passed":bool(passed),"detail":detail})

    add("enrolled","Enrolled in Tikcentral",True,True,f'Router #{router_id} · {r["model"] or "model unknown"}')
    add("management","WireGuard / management healthy",cfg["require_management"],bool(access and access["management_ok"]),"Healthy" if access and access["management_ok"] else "Management path not healthy yet")
    site_ok=bool(site and ((site["address"] or "").strip() or (site["site_code"] or "").strip() or (site["circuit_type"] or "").strip()))
    add("site_metadata","Site metadata entered",cfg["require_site_metadata"],site_ok,"Site code/address/circuit information" if site_ok else "Add at least site code, address, or circuit type")
    customer_ok=bool(site and (site["customer_name"] or "").strip())
    add("customer","Customer assigned",cfg["require_customer"],customer_ok,(site["customer_name"] if customer_ok else "Customer name missing"))
    wan_ok=bool(wan and wan["classification"]=="healthy")
    add("wan","WAN verified",cfg["require_wan"],wan_ok,(wan["summary"] if wan else "No WAN probe yet"))
    desired_ok=bool(desired and desired["status"]=="pass")
    add("desired","Desired state passing",cfg["require_desired_state"],desired_ok,(f'{desired["failed"]} failed / {desired["warnings"]} warning' if desired else "Not checked"))
    security_ok=bool(security and int(security["critical_count"] or 0)==0)
    add("security","Security audit acceptable",cfg["require_security"],security_ok,(f'{security["critical_count"]} critical / {security["warning_count"]} review item(s)' if security else "Not checked"))
    add("backup","Commissioning backup captured",cfg["require_backup"],bool(backup),(backup["created_at"] if backup else "No commissioning backup"))
    add("hardware","Hardware inventory entered",cfg["require_hardware"],int(hardware or 0)>0,f"{int(hardware or 0)} installed item(s)")
    baseline_ok=bool(expected and (expected["baseline_sha256"] or "").strip())
    add("baseline","Configuration baseline accepted",cfg["require_baseline"],baseline_ok,"Baseline present" if baseline_ok else "No accepted baseline")

    required=[x for x in checks if x["required"]]
    passed=sum(1 for x in required if x["passed"])
    complete=bool(required) and passed==len(required)
    status="complete" if complete else "incomplete"
    promoted=""
    current=(r["lifecycle_state"] or "production")
    should_promote=bool(complete and cfg["auto_promote"] and current in {"new","commissioning"})
    checked_at=_now()
    with core.db() as conn:
        prior=conn.execute("SELECT promoted_at FROM commissioning_checklist_status WHERE router_id=?",(router_id,)).fetchone()
        if should_promote:
            promoted=checked_at
            conn.execute(
                "UPDATE routers SET lifecycle_state='production',lifecycle_updated_at=?,lifecycle_updated_by='commissioning-checklist' WHERE id=?",
                (promoted,router_id),
            )
        conn.execute(
            """INSERT INTO commissioning_checklist_status(router_id,checked_at,status,passed,required,details_json,promoted_at)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET checked_at=excluded.checked_at,status=excluded.status,passed=excluded.passed,
                 required=excluded.required,details_json=excluded.details_json,
                 promoted_at=CASE WHEN excluded.promoted_at<>'' THEN excluded.promoted_at ELSE commissioning_checklist_status.promoted_at END""",
            (router_id,checked_at,status,passed,len(required),json.dumps(checks),promoted or (prior["promoted_at"] if prior else "")),
        )
    if promoted:
        events.record(router_id,"commissioning","Commissioning checklist complete · promoted to Production",f"{passed}/{len(required)} required checks passed","info")
    return {"status":status,"passed":passed,"required":len(required),"checks":checks,"promoted":bool(promoted)}


def evaluate_candidates():
    migrations.migrate()
    with core.db() as conn:
        ids=[int(x["id"]) for x in conn.execute("SELECT id FROM routers WHERE enabled=1 AND lifecycle_state IN ('new','commissioning') ORDER BY id").fetchall()]
    for rid in ids:
        try:evaluate(rid)
        except Exception:pass
    return len(ids)


def register(app,page_func):
    migrations.migrate()

    @app.get("/commissioning-checklist/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        result=evaluate(router_id)
        if not result:return RedirectResponse("/operations",303)
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
            cfg=conn.execute("SELECT * FROM commissioning_checklist_settings WHERE id=1").fetchone()
        rows="".join(
            f'<tr><td>{"Required" if x["required"] else "Optional"}</td><td>{html.escape(x["label"])}</td><td>{"PASS" if x["passed"] else "MISSING"}</td><td>{html.escape(str(x["detail"]))}</td></tr>'
            for x in result["checks"]
        )
        csrf=core.csrf_token(request)
        setting_defs=(
            ("require_site_metadata","Require site metadata"),("require_customer","Require customer assignment"),("require_management","Require healthy management"),
            ("require_wan","Require fully healthy WAN verification"),("require_desired_state","Require desired-state pass"),("require_security","Require no critical security findings"),
            ("require_backup","Require commissioning backup"),("require_hardware","Require hardware inventory"),("require_baseline","Require accepted baseline"),
            ("auto_promote","Automatically promote complete routers to Production"),
        )
        setting_rows=[]
        for key,label in setting_defs:
            checked="checked" if cfg[key] else ""
            setting_rows.append(f'<label style="display:block"><input type="checkbox" name="{key}" value="1" {checked}> {html.escape(label)}</label>')
        settings_html="".join(setting_rows)
        body=f'''<div class="panel pad"><h2>Commissioning checklist · {html.escape(r["site_name"])}</h2>
<div><strong>{result["passed"]}/{result["required"]} required checks passed</strong> · lifecycle {html.escape(r["lifecycle_state"] or "")}</div>
<div class="muted">With the standard enabled, a New/Commissioning router moves to Production automatically only when every required item passes. Existing Production routers are never demoted.</div></div>
<div class="panel"><table><thead><tr><th>Requirement</th><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="panel pad"><h3>Checklist standard</h3><form method="post" action="/commissioning-checklist/settings"><input type="hidden" name="csrf" value="{csrf}">
{settings_html}
<button class="primary">Save checklist standard</button></form></div>'''
        return page_func("Commissioning Checklist",body,user,"operations")

    @app.post("/commissioning-checklist/settings")
    async def settings_save(request:Request):
        user=core.require_web_role(request,"admin")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        keys=["require_site_metadata","require_customer","require_management","require_wan","require_desired_state","require_security","require_backup","require_hardware","require_baseline","auto_promote"]
        vals=[1 if data.get(k)=="1" else 0 for k in keys]
        with core.db() as conn:
            conn.execute("UPDATE commissioning_checklist_settings SET "+",".join(f"{k}=?" for k in keys)+" WHERE id=1",vals)
        return RedirectResponse(request.headers.get("referer") or "/operations",303)
