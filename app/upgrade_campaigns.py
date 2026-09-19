"""Staged RouterOS upgrade campaigns with canary approval gates."""

import html
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import errors, jobs, main as core, migrations, operations


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sync(campaign_id:int):
    queue_stage=""
    queue_actor=""
    with core.db() as conn:
        members=conn.execute("SELECT * FROM upgrade_campaign_members WHERE campaign_id=?",(campaign_id,)).fetchall()
        for m in members:
            if not m["job_id"]:
                continue
            j=conn.execute("SELECT status,error_code,error_message FROM router_jobs WHERE id=?",(m["job_id"],)).fetchone()
            if not j: continue
            mapped="succeeded" if j["status"]=="succeeded" else ("failed" if j["status"]=="failed" else "running")
            conn.execute(
                "UPDATE upgrade_campaign_members SET status=?,last_error=?,updated_at=? WHERE id=?",
                (mapped,(j["error_code"] or "")+" "+(j["error_message"] or ""),_now(),m["id"]),
            )
        rows=conn.execute("SELECT stage,status FROM upgrade_campaign_members WHERE campaign_id=?",(campaign_id,)).fetchall()
        campaign=conn.execute("SELECT status,created_by,approved_by FROM upgrade_campaigns WHERE id=?",(campaign_id,)).fetchone()
        if not campaign: return
        if rows and all(r["status"]=="succeeded" for r in rows):
            conn.execute("UPDATE upgrade_campaigns SET status='completed' WHERE id=?",(campaign_id,))
        elif any(r["status"]=="failed" for r in rows):
            conn.execute("UPDATE upgrade_campaigns SET status='failed' WHERE id=?",(campaign_id,))
        else:
            stage="canary" if campaign["status"]=="canary_running" else ("rollout" if campaign["status"]=="rollout_running" else "")
            if stage:
                active=any(r["stage"]==stage and r["status"] in {"queued","running"} for r in rows)
                pending=any(r["stage"]==stage and r["status"]=="pending" for r in rows)
                if pending and not active:
                    queue_stage=stage
                    queue_actor=(campaign["approved_by"] or campaign["created_by"] or "scheduler")
    if queue_stage:
        _queue_stage(campaign_id,queue_stage,queue_actor)


def sync_all():
    migrations.migrate()
    with core.db() as conn:
        ids=[int(r["id"]) for r in conn.execute(
            "SELECT id FROM upgrade_campaigns WHERE status NOT IN ('completed','cancelled') ORDER BY id"
        ).fetchall()]
    for cid in ids:
        _sync(cid)
    return len(ids)


def _queue_stage(campaign_id:int,stage:str,actor:str):
    """Queue at most one campaign member because upgrades are globally serialized."""
    with core.db() as conn:
        campaign=conn.execute("SELECT * FROM upgrade_campaigns WHERE id=?",(campaign_id,)).fetchone()
        members=conn.execute(
            """SELECT m.*,r.model,r.lifecycle_state FROM upgrade_campaign_members m
               JOIN routers r ON r.id=m.router_id
               WHERE m.campaign_id=? AND m.stage=? AND m.status='pending' ORDER BY m.id""",
            (campaign_id,stage),
        ).fetchall()
    if not campaign: raise ValueError("campaign not found")
    for m in members:
        if (m["lifecycle_state"] or "production") not in {"production","maintenance"}:
            with core.db() as conn:
                conn.execute(
                    "UPDATE upgrade_campaign_members SET status='failed',last_error=?,updated_at=? WHERE id=?",
                    (f'lifecycle state {m["lifecycle_state"] or "production"} is not upgrade-eligible',_now(),m["id"]),
                )
            return 0
        with core.db() as conn:
            st=conn.execute("SELECT latest_version FROM router_update_status WHERE router_id=?",(m["router_id"],)).fetchone()
        if not st or operations._version_number(st["latest_version"]) != operations._version_number(campaign["target_version"]):
            with core.db() as conn:
                conn.execute(
                    "UPDATE upgrade_campaign_members SET status='failed',last_error=?,updated_at=? WHERE id=?",
                    ("target version not confirmed by update check",_now(),m["id"]),
                )
            return 0
        try:
            job_id=jobs.create(
                m["router_id"],"upgrade_routeros",actor,campaign["target_version"],
                {"campaign_id":campaign_id,"campaign_stage":stage,"canary":stage=="canary"},
                serialize_router=True,serialize_global_kind="upgrade_",
            )
        except errors.OperationError as exc:
            if exc.code in {"JOB_BUSY","ROUTER_BUSY"}:
                return 0
            raise
        with core.db() as conn:
            conn.execute(
                "UPDATE upgrade_campaign_members SET status='queued',job_id=?,updated_at=? WHERE id=?",
                (job_id,_now(),m["id"]),
            )
        return 1
    return 0

def register(app,page_func):
    migrations.migrate()

    @app.get("/upgrade-campaigns",response_class=HTMLResponse)
    def campaigns(request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        with core.db() as conn:
            routers=conn.execute(
                """SELECT r.id,r.site_name,r.model,r.lifecycle_state,u.latest_version
                   FROM routers r LEFT JOIN router_update_status u ON u.router_id=r.id
                   WHERE r.enabled=1 AND r.lifecycle_state<>'retired'
                   ORDER BY r.site_name COLLATE NOCASE"""
            ).fetchall()
            campaigns=conn.execute("SELECT * FROM upgrade_campaigns ORDER BY id DESC LIMIT 50").fetchall()
        csrf=core.csrf_token(request)
        checks="".join(
            f'<label style="display:block"><input type="checkbox" name="router_ids" value="{r["id"]}"> {html.escape(r["site_name"])} · {html.escape(r["model"] or "")} · latest {html.escape(r["latest_version"] or "not checked")}</label>'
            for r in routers
        )
        canary_options="".join(
            f'<option value="{r["id"]}">{html.escape(r["site_name"])} · {html.escape(r["model"] or "")}</option>'
            for r in routers
        )
        rows="".join(
            f'<tr><td>#{c["id"]}</td><td><a href="/upgrade-campaigns/{c["id"]}">{html.escape(c["name"])}</a></td><td>{html.escape(c["target_version"])}</td><td>{html.escape(c["status"])}</td><td>{html.escape(c["created_by"])}</td></tr>'
            for c in campaigns
        ) or '<tr><td colspan="5">No campaigns.</td></tr>'
        body=f'''<div class="panel pad"><h2>Upgrade campaigns</h2><div class="muted">Canary first, then explicit approval before rollout. Campaigns only queue RouterOS jobs; the existing serialized upgrade engine still performs backup, reboot, verification and transaction logging.</div></div>
<div class="panel pad"><form method="post" action="/upgrade-campaigns">
<input type="hidden" name="csrf" value="{csrf}">
<div><label>Name<br><input name="name" required></label> <label>Target RouterOS<br><input name="target_version" required></label></div>
<div style="margin-top:10px"><strong>Routers</strong>{checks}</div>
<div style="margin-top:10px"><label>Canary router<br><select name="canary_router_id" required>{canary_options}</select></label></div>
<div style="margin-top:10px"><label>Notes<br><textarea name="notes" style="width:100%;min-height:80px"></textarea></label></div>
<button class="primary">Create campaign</button></form></div>
<div class="panel"><table><thead><tr><th>ID</th><th>Name</th><th>Target</th><th>Status</th><th>Created by</th></tr></thead><tbody>{rows}</tbody></table></div>'''
        return page_func("Upgrade Campaigns",body,user,"operations")

    @app.post("/upgrade-campaigns")
    async def create_campaign(request:Request):
        user=core.require_web_role(request,"admin")
        if not user:
            return RedirectResponse("/login",303)
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        ids=sorted({int(x) for x in data.getlist("router_ids") if str(x).isdigit() and int(x)>0})
        try:
            canary=int(data.get("canary_router_id") or 0)
        except (TypeError,ValueError):
            canary=0
        if canary<=0:
            raise HTTPException(status_code=400,detail="valid canary router required")
        if canary not in ids:
            ids.append(canary)
        name=str(data.get("name","")).strip()[:200]
        target=operations._version_number(str(data.get("target_version","")).strip())
        if not name or not target or not ids:
            raise HTTPException(status_code=400,detail="campaign name, target version and routers are required")
        with core.db() as conn:
            valid_ids={int(r[0]) for r in conn.execute(
                "SELECT id FROM routers WHERE enabled=1 AND lifecycle_state<>'retired' AND id IN ("+(",".join("?" for _ in ids))+")",
                tuple(ids),
            ).fetchall()}
        if canary not in valid_ids or valid_ids != set(ids):
            raise HTTPException(status_code=400,detail="campaign contains an invalid, disabled or retired router")
        now=_now()
        with core.db() as conn:
            cur=conn.execute("INSERT INTO upgrade_campaigns(name,target_version,status,created_by,created_at,notes) VALUES(?,?,'canary_pending',?,?,?)",
                             (name,target,user["email"],now,str(data.get("notes",""))[:2000]))
            cid=cur.lastrowid
            for rid in sorted(set(ids)):
                stage="canary" if rid==canary else "rollout"
                conn.execute("INSERT OR IGNORE INTO upgrade_campaign_members(campaign_id,router_id,stage,status,updated_at) VALUES(?,?,?,'pending',?)",
                             (cid,rid,stage,now))
        _queue_stage(cid,"canary",user["email"])
        with core.db() as conn:
            conn.execute("UPDATE upgrade_campaigns SET status='canary_running' WHERE id=?",(cid,))
        return RedirectResponse(f"/upgrade-campaigns/{cid}",303)

    @app.get("/upgrade-campaigns/{campaign_id}",response_class=HTMLResponse)
    def campaign_page(campaign_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        _sync(campaign_id)
        with core.db() as conn:
            c=conn.execute("SELECT * FROM upgrade_campaigns WHERE id=?",(campaign_id,)).fetchone()
            members=conn.execute(
                """SELECT m.*,r.site_name,r.model,r.lifecycle_state FROM upgrade_campaign_members m
                   JOIN routers r ON r.id=m.router_id WHERE m.campaign_id=? ORDER BY CASE m.stage WHEN 'canary' THEN 0 ELSE 1 END,m.id""",
                (campaign_id,),
            ).fetchall()
        if not c: return RedirectResponse("/upgrade-campaigns",303)
        csrf=core.csrf_token(request)
        canaries=[m for m in members if m["stage"]=="canary"]
        canary_ok=bool(canaries) and all(m["status"]=="succeeded" for m in canaries)
        rows="".join(
            f'<tr><td>{html.escape(m["site_name"])}</td><td>{html.escape(m["stage"])}</td><td>{html.escape(m["status"])}</td><td>{m["job_id"] or "-"}</td><td>{html.escape(m["last_error"] or "")}</td></tr>'
            for m in members
        )
        approve='' if not canary_ok or c["status"] in {"approved","rollout_running","completed"} else f'''<form method="post" action="/upgrade-campaigns/{campaign_id}/approve"><input type="hidden" name="csrf" value="{csrf}"><button class="primary">Approve rollout</button></form>'''
        body=f'''<div class="panel pad"><h2>{html.escape(c["name"])}</h2><div>Target {html.escape(c["target_version"])} · status {html.escape(c["status"])}</div><div class="muted">{html.escape(c["notes"] or "")}</div><div style="margin-top:12px">{approve}</div></div>
<div class="panel"><table><thead><tr><th>Router</th><th>Stage</th><th>Status</th><th>Job</th><th>Error</th></tr></thead><tbody>{rows}</tbody></table></div>'''
        return page_func("Upgrade Campaign",body,user,"operations")

    @app.post("/upgrade-campaigns/{campaign_id}/approve")
    async def approve_rollout(campaign_id:int,request:Request):
        user=core.require_web_role(request,"admin")
        if not user:
            return RedirectResponse("/login",303)
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        _sync(campaign_id)
        with core.db() as conn:
            canaries=conn.execute("SELECT status FROM upgrade_campaign_members WHERE campaign_id=? AND stage='canary'",(campaign_id,)).fetchall()
        if not canaries or not all(x["status"]=="succeeded" for x in canaries):
            return RedirectResponse(f"/upgrade-campaigns/{campaign_id}",303)
        with core.db() as conn:
            conn.execute("UPDATE upgrade_campaigns SET status='approved',approved_by=?,approved_at=? WHERE id=?",(user["email"],_now(),campaign_id))
        _queue_stage(campaign_id,"rollout",user["email"])
        with core.db() as conn:
            conn.execute("UPDATE upgrade_campaigns SET status='rollout_running' WHERE id=?",(campaign_id,))
        return RedirectResponse(f"/upgrade-campaigns/{campaign_id}",303)
