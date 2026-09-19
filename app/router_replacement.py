"""Guided router replacement without blind RouterOS config cloning."""

import html
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations


def _now(): return datetime.now(timezone.utc).isoformat()


def _copy_single(conn, table, columns, source, target):
    row=conn.execute(f"SELECT {','.join(columns)} FROM {table} WHERE router_id=?",(source,)).fetchone()
    if not row:return
    placeholders=",".join("?" for _ in columns)
    updates=",".join(f"{c}=excluded.{c}" for c in columns)
    conn.execute(
        f"INSERT INTO {table}(router_id,{','.join(columns)}) VALUES(?,{placeholders}) ON CONFLICT(router_id) DO UPDATE SET {updates}",
        (target,*[row[c] for c in columns]),
    )


def execute(replacement_id:int,actor:str):
    migrations.migrate()
    now=_now()
    with core.db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rep=conn.execute("SELECT * FROM router_replacements WHERE id=?",(replacement_id,)).fetchone()
        if not rep: raise ValueError("replacement not found")
        if rep["status"]=="completed": return
        src=conn.execute("SELECT * FROM routers WHERE id=?",(rep["source_router_id"],)).fetchone()
        dst=conn.execute("SELECT * FROM routers WHERE id=?",(rep["target_router_id"],)).fetchone()
        if not src or not dst: raise ValueError("source/target router missing")
        if int(src["id"]) == int(dst["id"]): raise ValueError("source and target routers must be different")
        if (src["lifecycle_state"] or "production")=="retired": raise ValueError("source router already retired")
        if (dst["lifecycle_state"] or "production") not in {"new","commissioning"}:
            raise ValueError("target router must be New or Commissioning")

        if rep["copy_site_metadata"]:
            cols=["customer_name","site_code","address","contact_name","contact_phone","contact_email","circuit_type","circuit_reference","circuit_down_mbps","circuit_up_mbps","install_date","ticket_reference","support_notes","updated_by","updated_at"]
            _copy_single(conn,"router_site_metadata",cols,src["id"],dst["id"])
        if rep["copy_desired_state"]:
            _copy_single(conn,"router_desired_state",["profile","intent_json","updated_by","updated_at"],src["id"],dst["id"])
        if rep["copy_wan_profile"]:
            _copy_single(conn,"router_wan_probe_config",["profile","targets_json","dns_name","latency_warn_ms","packet_loss_warn_percent","updated_by","updated_at"],src["id"],dst["id"])
        if rep["copy_protection"]:
            conn.execute("DELETE FROM router_object_protection WHERE router_id=?",(dst["id"],))
            rows=conn.execute("SELECT object_type,selector,ownership,protected,notes FROM router_object_protection WHERE router_id=?",(src["id"],)).fetchall()
            for r in rows:
                conn.execute(
                    """INSERT INTO router_object_protection(router_id,object_type,selector,ownership,protected,notes,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (dst["id"],r["object_type"],r["selector"],r["ownership"],r["protected"],r["notes"],actor,now,now),
                )
        if rep["move_hardware"]:
            conn.execute(
                "UPDATE hardware_inventory SET status='retired',updated_at=? WHERE router_id=? AND category='router' AND status<>'retired'",
                (now,src["id"]),
            )
            conn.execute(
                "UPDATE hardware_inventory SET router_id=?,updated_at=? WHERE router_id=? AND category<>'router' AND status<>'retired'",
                (dst["id"],now,src["id"]),
            )
            existing_router=conn.execute(
                "SELECT id FROM hardware_inventory WHERE router_id=? AND category='router' AND status<>'retired' LIMIT 1",
                (dst["id"],),
            ).fetchone()
            if not existing_router:
                conn.execute(
                    """INSERT INTO hardware_inventory
                       (router_id,category,manufacturer,model,serial,asset_tag,location,installed_at,warranty_until,status,notes,created_by,created_at,updated_at)
                       VALUES(?,'router','MikroTik',?,?,?,'','', '','installed','Replacement router','router-replacement',?,?)""",
                    (dst["id"],dst["model"] or "",dst["serial"] or "",f"router-{dst['id']}",now,now),
                )
        if rep["move_future_changes"]:
            conn.execute("UPDATE planned_changes SET router_id=? WHERE router_id=? AND status IN ('planned','in_progress')",(dst["id"],src["id"]))

        retired_name=src["site_name"] if str(src["site_name"]).endswith(" (retired)") else f'{src["site_name"]} (retired)'
        conn.execute("UPDATE routers SET site_name=?,lifecycle_state='retired',lifecycle_updated_at=?,lifecycle_updated_by=? WHERE id=?",(retired_name,now,actor,src["id"]))
        conn.execute("UPDATE routers SET site_name=?,lifecycle_state='commissioning',lifecycle_updated_at=?,lifecycle_updated_by=? WHERE id=?",(src["site_name"],now,actor,dst["id"]))
        conn.execute("UPDATE router_replacements SET status='completed',completed_by=?,completed_at=? WHERE id=?",(actor,now,replacement_id))
    events.record(src["id"],"replacement",f"Router retired; replaced by #{dst['id']} {src['site_name']}",f"replacement_id={replacement_id}","info")
    events.record(dst["id"],"replacement",f"Router commissioned as replacement for #{src['id']} {src['site_name']}",f"replacement_id={replacement_id}","info")


def register(app,page_func):
    migrations.migrate()

    @app.get("/replacements",response_class=HTMLResponse)
    def replacements(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        with core.db() as conn:
            routers=conn.execute("SELECT id,site_name,model,lifecycle_state FROM routers WHERE enabled=1 ORDER BY site_name").fetchall()
            rows=conn.execute(
                """SELECT x.*,s.site_name source_name,t.site_name target_name
                   FROM router_replacements x
                   JOIN routers s ON s.id=x.source_router_id JOIN routers t ON t.id=x.target_router_id
                   ORDER BY x.id DESC LIMIT 100"""
            ).fetchall()
        csrf=core.csrf_token(request)
        source_hint=request.query_params.get("source","")
        opts="".join(
            f'<option value="{r["id"]}" {"selected" if str(r["id"])==source_hint else ""}>#{r["id"]} {html.escape(r["site_name"])} · {html.escape(r["model"] or "")} · {html.escape(r["lifecycle_state"] or "production")}</option>'
            for r in routers
        )
        rendered="".join(
            f'<tr><td>#{x["id"]}</td><td>{html.escape(x["source_name"])}</td><td>{html.escape(x["target_name"])}</td><td>{html.escape(x["status"])}</td><td>{html.escape(x["created_by"])}</td><td><a href="/replacements/{x["id"]}">Open</a></td></tr>'
            for x in rows
        ) or '<tr><td colspan="6">No replacement workflows.</td></tr>'
        body=f'''<div class="panel pad"><h2>Router replacement</h2>
<div class="muted">Transfers Tikcentral site metadata/intent/protection and selected site associations. The new router keeps its own enrolled WireGuard/public-key identity. Tikcentral does not clone a RouterOS export onto different hardware.</div></div>
<div class="panel pad"><form method="post" action="/replacements">
<input type="hidden" name="csrf" value="{csrf}">
<label>Old router <select name="source_router_id">{opts}</select></label>
<label>New enrolled router <select name="target_router_id">{opts}</select></label>
<label><input type="checkbox" name="copy_site_metadata" value="1" checked> Site/customer metadata</label>
<label><input type="checkbox" name="copy_protection" value="1" checked> Protected objects</label>
<label><input type="checkbox" name="copy_desired_state" value="1" checked> Desired state</label>
<label><input type="checkbox" name="copy_wan_profile" value="1" checked> WAN probe profile</label>
<label><input type="checkbox" name="move_hardware" value="1" checked> Move active hardware inventory</label>
<label><input type="checkbox" name="move_future_changes" value="1" checked> Move planned/in-progress changes</label>
<div><label>Notes<br><textarea name="notes" style="width:100%;min-height:80px"></textarea></label></div>
<button class="primary">Create replacement workflow</button></form></div>
<div class="panel"><table><thead><tr><th>ID</th><th>Old</th><th>New</th><th>Status</th><th>Created by</th><th></th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Router Replacement",body,user,"operations")

    @app.post("/replacements")
    async def create(request:Request):
        user=core.require_web_role(request,"admin")
        if not user:
            return RedirectResponse("/login",303)
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        try:
            src=int(data.get("source_router_id") or 0); dst=int(data.get("target_router_id") or 0)
        except (TypeError,ValueError):
            raise HTTPException(status_code=400,detail="invalid source or target router")
        if src<=0 or dst<=0 or src==dst:
            raise HTTPException(status_code=400,detail="source and target routers must be different")
        with core.db() as conn:
            source=conn.execute("SELECT lifecycle_state,enabled FROM routers WHERE id=?",(src,)).fetchone()
            target=conn.execute("SELECT lifecycle_state,enabled FROM routers WHERE id=?",(dst,)).fetchone()
            if not source or not target or not source["enabled"] or not target["enabled"]:
                raise HTTPException(status_code=400,detail="source and target routers must exist and be enabled")
            if (source["lifecycle_state"] or "production")=="retired" or (target["lifecycle_state"] or "production") not in {"new","commissioning"}:
                raise HTTPException(status_code=400,detail="source must be active and target must be New or Commissioning")
            cur=conn.execute(
                """INSERT INTO router_replacements(source_router_id,target_router_id,status,copy_site_metadata,copy_protection,copy_desired_state,copy_wan_profile,move_hardware,move_future_changes,created_by,created_at,notes)
                   VALUES(?,?,'planned',?,?,?,?,?,?,?,?,?)""",
                (src,dst,1 if data.get("copy_site_metadata")=="1" else 0,1 if data.get("copy_protection")=="1" else 0,
                 1 if data.get("copy_desired_state")=="1" else 0,1 if data.get("copy_wan_profile")=="1" else 0,
                 1 if data.get("move_hardware")=="1" else 0,1 if data.get("move_future_changes")=="1" else 0,
                 user["email"],_now(),str(data.get("notes",""))[:2000]),
            )
        return RedirectResponse(f"/replacements/{cur.lastrowid}",303)

    @app.get("/replacements/{replacement_id}",response_class=HTMLResponse)
    def view(replacement_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        with core.db() as conn:
            x=conn.execute(
                """SELECT x.*,s.site_name source_name,s.model source_model,s.lifecycle_state source_state,
                          t.site_name target_name,t.model target_model,t.lifecycle_state target_state
                   FROM router_replacements x JOIN routers s ON s.id=x.source_router_id JOIN routers t ON t.id=x.target_router_id
                   WHERE x.id=?""",(replacement_id,)).fetchone()
        if not x:return RedirectResponse("/replacements",303)
        csrf=core.csrf_token(request)
        action='' if x["status"]=="completed" else f'''<form method="post" action="/replacements/{replacement_id}/execute"><input type="hidden" name="csrf" value="{csrf}"><button class="danger" onclick="return confirm('Complete this replacement and retire the old router?')">Complete replacement</button></form>'''
        body=f'''<div class="panel pad"><h2>Replacement #{replacement_id}</h2>
<div><strong>Old:</strong> {html.escape(x["source_name"])} · {html.escape(x["source_model"] or "")} · {html.escape(x["source_state"] or "")}</div>
<div><strong>New:</strong> {html.escape(x["target_name"])} · {html.escape(x["target_model"] or "")} · {html.escape(x["target_state"] or "")}</div>
<div class="muted">Status {html.escape(x["status"])} · no RouterOS configuration is cloned.</div><p>{html.escape(x["notes"] or "")}</p>{action}</div>'''
        return page_func("Router Replacement",body,user,"operations")

    @app.post("/replacements/{replacement_id}/execute")
    async def complete(replacement_id:int,request:Request):
        user=core.require_web_role(request,"admin")
        if not user:
            return RedirectResponse("/login",303)
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        execute(replacement_id,user["email"])
        return RedirectResponse(f"/replacements/{replacement_id}",303)
