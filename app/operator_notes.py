"""Cross-object operator comments and ticket references."""

import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations


TYPES={"general","job","change","incident","ai","planned_change","maintenance","outage"}


def _now(): return datetime.now(timezone.utc).isoformat()


def register(app,page_func):
    migrations.migrate()

    @app.get("/notes/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model FROM routers WHERE id=?",(router_id,)).fetchone()
            rows=conn.execute("SELECT * FROM operator_notes WHERE router_id=? ORDER BY id DESC LIMIT 250",(router_id,)).fetchall()
        if not r:return RedirectResponse("/operations",303)
        csrf=core.csrf_token(request)
        typ=request.query_params.get("type","general")
        if typ not in TYPES:typ="general"
        obj=request.query_params.get("id","")
        ticket=request.query_params.get("ticket","")
        rendered="".join(
            f'<tr><td>{html.escape(x["created_at"])}</td><td>{html.escape(x["object_type"])} {("#"+str(x["object_id"])) if x["object_id"] else ""}</td>'
            f'<td>{html.escape(x["ticket_reference"] or "-")}</td><td>{html.escape(x["visibility"])}</td><td><strong>{html.escape(x["created_by"] or "-")}</strong><div>{html.escape(x["note"])}</div></td></tr>'
            for x in rows
        ) or '<tr><td colspan="5">No operator notes.</td></tr>'
        opts="".join(f'<option value="{x}" {"selected" if x==typ else ""}>{x}</option>' for x in sorted(TYPES))
        body=f'''<div class="panel pad"><h2>Operator notes · {html.escape(r["site_name"])}</h2>
<form method="post" action="/notes/{router_id}">
<input type="hidden" name="csrf" value="{csrf}">
<div class="cards"><div><label>Attach to<br><select name="object_type">{opts}</select></label></div>
<div><label>Object ID<br><input name="object_id" value="{html.escape(obj)}"></label></div>
<div><label>Ticket / work order<br><input name="ticket_reference" value="{html.escape(ticket)}"></label></div>
<div><label>Visibility<br><select name="visibility"><option value="internal">Internal only</option><option value="customer">Customer-report eligible</option></select></label></div></div>
<div style="margin-top:10px"><label>Note<br><textarea name="note" required style="width:100%;min-height:100px"></textarea></label></div>
<button class="primary">Add note</button></form></div>
<div class="panel"><table><thead><tr><th>Time</th><th>Attached to</th><th>Ticket</th><th>Visibility</th><th>Note</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Operator Notes",body,user,"operations")

    @app.post("/notes/{router_id}")
    async def add_note(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        typ=str(data.get("object_type","general"))
        if typ not in TYPES:typ="general"
        obj=int(data.get("object_id")) if str(data.get("object_id","")).isdigit() else None
        visibility="customer" if data.get("visibility")=="customer" else "internal"
        ticket=str(data.get("ticket_reference","")).strip()[:200]
        note=str(data.get("note","")).strip()[:6000]
        if not note:return RedirectResponse(f"/notes/{router_id}",303)
        with core.db() as conn:
            conn.execute(
                """INSERT INTO operator_notes(router_id,object_type,object_id,ticket_reference,visibility,note,created_by,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (router_id,typ,obj,ticket,visibility,note,user["email"],_now()),
            )
        events.record(router_id,"operator-note","Operator note added",f"type={typ} object_id={obj or '-'} ticket={ticket or '-'} by={user['email']}","info")
        return RedirectResponse(f"/notes/{router_id}",303)
