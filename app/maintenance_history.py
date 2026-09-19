"""Structured service/maintenance work log."""

import html
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, ui_time


def _now():
    return datetime.now(timezone.utc).isoformat()


def _local_input_now():
    return datetime.now(ui_time.LOCAL_TZ).strftime("%Y-%m-%dT%H:%M")


def _normalize_occurred(value: str) -> str:
    raw=(value or "").strip()
    if not raw:
        return _now()
    dt=datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt=dt.replace(tzinfo=ui_time.LOCAL_TZ)
    return dt.astimezone(timezone.utc).isoformat()


def register(app,page_func):
    migrations.migrate()

    @app.get("/maintenance-history/{router_id}",response_class=HTMLResponse)
    def history_page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        with core.db() as conn:
            router=conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?",(router_id,)).fetchone()
            rows=conn.execute(
                "SELECT * FROM router_maintenance_history WHERE router_id=? ORDER BY occurred_at DESC,id DESC LIMIT 200",
                (router_id,),
            ).fetchall()
        if not router: return RedirectResponse("/operations",303)
        csrf=core.csrf_token(request)
        rendered="".join(
            f'<tr><td>{html.escape(r["occurred_at"])}</td><td>{html.escape(r["work_type"])}</td><td>{html.escape(r["technician"] or "-")}</td>'
            f'<td>{html.escape(r["ticket_reference"] or "-")}</td><td><strong>{html.escape(r["issue"] or "-")}</strong><div class="muted">{html.escape(r["work_performed"] or "")}</div></td>'
            f'<td>{html.escape(r["result"] or "-")}<div class="muted">{html.escape(r["follow_up"] or "")}</div></td></tr>'
            for r in rows
        ) or '<tr><td colspan="6">No maintenance entries yet.</td></tr>'
        body=f'''<div class="panel pad"><h2>Maintenance history · {html.escape(router["site_name"])}</h2>
<form method="post" action="/maintenance-history/{router_id}">
<input type="hidden" name="csrf" value="{csrf}">
<div class="cards">
<div><label>Date/time (Montréal)<br><input type="datetime-local" name="occurred_at" value="{html.escape(_local_input_now())}" style="width:100%"></label></div>
<div><label>Technician<br><input name="technician" value="{html.escape(user["email"])}" style="width:100%"></label></div>
<div><label>Type<br><select name="work_type"><option>service</option><option>installation</option><option>maintenance</option><option>upgrade</option><option>incident</option><option>inspection</option></select></label></div>
<div><label>Ticket / work order<br><input name="ticket_reference" style="width:100%"></label></div>
</div>
<div style="margin-top:10px"><label>Issue / reason<br><textarea name="issue" style="width:100%;min-height:70px"></textarea></label></div>
<div style="margin-top:10px"><label>Work performed<br><textarea name="work_performed" style="width:100%;min-height:100px"></textarea></label></div>
<div style="margin-top:10px"><label>Result<br><textarea name="result" style="width:100%;min-height:70px"></textarea></label></div>
<div style="margin-top:10px"><label>Follow-up<br><textarea name="follow_up" style="width:100%;min-height:70px"></textarea></label></div>
<div style="margin-top:12px"><button class="primary">Add maintenance entry</button></div></form></div>
<div class="panel"><table><thead><tr><th>When</th><th>Type</th><th>Technician</th><th>Ticket</th><th>Issue / work</th><th>Result / follow-up</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Maintenance History",body,user,"operations")

    @app.post("/maintenance-history/{router_id}")
    async def history_add(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        values={k:str(data.get(k,"")).strip() for k in ("occurred_at","technician","work_type","ticket_reference","issue","work_performed","result","follow_up")}
        try:
            occurred=_normalize_occurred(values["occurred_at"])
        except (TypeError,ValueError):
            raise HTTPException(status_code=400,detail="invalid maintenance date/time")
        work_type=values["work_type"] or "service"
        if work_type not in {"service","installation","maintenance","upgrade","incident","inspection"}:
            raise HTTPException(status_code=400,detail="invalid maintenance work type")
        with core.db() as conn:
            if not conn.execute("SELECT 1 FROM routers WHERE id=?",(router_id,)).fetchone():
                raise HTTPException(status_code=404,detail="router not found")
            conn.execute(
                """INSERT INTO router_maintenance_history
                   (router_id,occurred_at,technician,work_type,ticket_reference,issue,work_performed,result,follow_up,created_by,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (router_id,occurred,values["technician"][:200],work_type,values["ticket_reference"][:200],
                 values["issue"][:4000],values["work_performed"][:8000],values["result"][:4000],values["follow_up"][:4000],user["email"],_now()),
            )
        events.record(router_id,"maintenance","Maintenance history entry added",f'ticket={values["ticket_reference"] or "-"} type={values["work_type"] or "service"} by={user["email"]}')
        return RedirectResponse(f"/maintenance-history/{router_id}",303)
