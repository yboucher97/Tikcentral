"""Planned-change calendar and recent completed change view."""

import calendar
import html
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


LOCAL_TZ=ZoneInfo("America/Toronto")

def _now():
    return datetime.now(timezone.utc).isoformat()

def _normalize_datetime(value: str) -> str:
    value=(value or "").strip()
    if not value:
        return ""
    dt=datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt=dt.replace(tzinfo=LOCAL_TZ)
    return dt.astimezone(timezone.utc).isoformat()



def register(app,page_func):
    migrations.migrate()

    @app.get("/change-calendar",response_class=HTMLResponse)
    def calendar_page(request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        raw=request.query_params.get("month","")
        try:
            month_start=datetime.strptime(raw+"-01","%Y-%m-%d").replace(tzinfo=LOCAL_TZ) if raw else datetime.now(LOCAL_TZ).replace(day=1,hour=0,minute=0,second=0,microsecond=0)
        except Exception:
            month_start=datetime.now(LOCAL_TZ).replace(day=1,hour=0,minute=0,second=0,microsecond=0)
        next_month=(month_start.replace(day=28)+timedelta(days=4)).replace(day=1)
        prev_month=(month_start-timedelta(days=1)).replace(day=1)
        query_start=month_start.astimezone(timezone.utc).isoformat()
        query_end=next_month.astimezone(timezone.utc).isoformat()
        with core.db() as conn:
            routers=conn.execute("SELECT id,site_name FROM routers WHERE enabled=1 AND COALESCE(lifecycle_state,'production')<>'retired' ORDER BY site_name COLLATE NOCASE").fetchall()
            planned=conn.execute(
                """SELECT p.*,r.site_name FROM planned_changes p LEFT JOIN routers r ON r.id=p.router_id
                   WHERE p.start_at>=? AND p.start_at<? ORDER BY p.start_at,id""",
                (query_start,query_end),
            ).fetchall()
            completed=conn.execute(
                """SELECT t.id,t.router_id,t.kind,t.actor,t.status,t.created_at,t.finished_at,r.site_name
                   FROM change_transactions t JOIN routers r ON r.id=t.router_id
                   WHERE t.created_at>=? AND t.created_at<? ORDER BY t.created_at DESC LIMIT 100""",
                (query_start,query_end),
            ).fetchall()
        csrf=core.csrf_token(request)
        planned_by_day={}
        for p in planned:
            try: day=datetime.fromisoformat(p["start_at"]).astimezone(LOCAL_TZ).day
            except Exception: continue
            planned_by_day.setdefault(day,[]).append(p)
        cal=calendar.Calendar(firstweekday=6)
        weeks=cal.monthdayscalendar(month_start.year,month_start.month)
        cells=[]
        for week in weeks:
            row=[]
            for day in week:
                if not day:
                    row.append('<td></td>')
                    continue
                items=planned_by_day.get(day,[])
                rendered="".join(
                    f'<div style="margin:4px 0"><a href="/change-calendar/{p["id"]}"><strong>{html.escape(p["title"])}</strong></a><div class="muted">{html.escape((p["site_name"] or "Fleet"))} · {html.escape(p["status"])}</div></div>'
                    for p in items
                )
                row.append(f'<td style="height:130px;min-width:150px"><strong>{day}</strong>{rendered}</td>')
            cells.append("<tr>"+"".join(row)+"</tr>")
        router_opts='<option value="">Fleet / no specific router</option>'+''.join(f'<option value="{r["id"]}">{html.escape(r["site_name"])}</option>' for r in routers)
        completed_rows="".join(
            f'<tr><td>{html.escape(t["created_at"])}</td><td>{html.escape(t["site_name"])}</td><td>{html.escape(t["kind"])}</td><td>{html.escape(t["status"])}</td><td>{html.escape(t["actor"] or "-")}</td></tr>'
            for t in completed
        ) or '<tr><td colspan="5">No completed/recorded changes this month.</td></tr>'
        body=f'''<div class="panel pad"><div class="inline"><a href="/change-calendar?month={prev_month.strftime("%Y-%m")}"><button>←</button></a><h2 style="margin:0">{month_start.strftime("%B %Y")}</h2><a href="/change-calendar?month={next_month.strftime("%Y-%m")}"><button>→</button></a></div></div>
<div class="panel"><table><thead><tr>{''.join(f"<th>{x}</th>" for x in ("Sun","Mon","Tue","Wed","Thu","Fri","Sat"))}</tr></thead><tbody>{''.join(cells)}</tbody></table></div>
<div class="panel pad"><h3>Plan a change</h3><form method="post" action="/change-calendar">
<input type="hidden" name="csrf" value="{csrf}">
<div class="cards"><div><label>Router<br><select name="router_id">{router_opts}</select></label></div>
<div><label>Title<br><input name="title" required style="width:100%"></label></div>
<div><label>Type<br><select name="change_type"><option>maintenance</option><option>upgrade</option><option>configuration</option><option>installation</option><option>incident</option></select></label></div>
<div><label>Start<br><input type="datetime-local" name="start_at" required style="width:100%"></label></div>\n<div><label>End<br><input type="datetime-local" name="end_at" style="width:100%"></label></div>
<div><label>Ticket<br><input name="ticket_reference" style="width:100%"></label></div></div>
<div style="margin-top:10px"><label>Notes<br><textarea name="notes" style="width:100%;min-height:80px"></textarea></label></div>
<button class="primary">Create planned change</button></form></div>
<div class="panel"><div class="pad"><h3>Recorded changes this month</h3></div><table><thead><tr><th>Time</th><th>Site</th><th>Change</th><th>Status</th><th>Actor</th></tr></thead><tbody>{completed_rows}</tbody></table></div>'''
        return page_func("Change Calendar",body,user,"operations")

    @app.post("/change-calendar")
    async def calendar_add(request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        raw_rid=str(data.get("router_id","")).strip()
        if raw_rid:
            if not raw_rid.isdigit() or int(raw_rid)<=0:
                return HTMLResponse("<h1>400</h1><p>Invalid router.</p>",status_code=400)
            rid=int(raw_rid)
        else:
            rid=None
        title=str(data.get("title","")).strip()[:300]
        if not title:
            return HTMLResponse("<h1>400</h1><p>Title is required.</p>",status_code=400)
        change_type=str(data.get("change_type","maintenance")).strip()
        if change_type not in {"maintenance","upgrade","configuration","installation","incident"}:
            return HTMLResponse("<h1>400</h1><p>Invalid change type.</p>",status_code=400)
        try:
            start_at=_normalize_datetime(str(data.get("start_at","")))
            end_at=_normalize_datetime(str(data.get("end_at",""))) if str(data.get("end_at","")).strip() else ""
        except Exception:
            return HTMLResponse("<h1>400</h1><p>Invalid planned change date/time.</p>",status_code=400)
        if not start_at:
            return HTMLResponse("<h1>400</h1><p>Start date/time is required.</p>",status_code=400)
        if end_at and end_at < start_at:
            return HTMLResponse("<h1>400</h1><p>End date/time must be after start.</p>",status_code=400)
        with core.db() as conn:
            if rid is not None:
                router=conn.execute(
                    "SELECT enabled,lifecycle_state FROM routers WHERE id=?",
                    (rid,),
                ).fetchone()
                if not router or not router["enabled"] or (router["lifecycle_state"] or "production")=="retired":
                    return HTMLResponse("<h1>400</h1><p>Selected router is not active.</p>",status_code=400)
            conn.execute(
                """INSERT INTO planned_changes(router_id,title,change_type,start_at,end_at,status,ticket_reference,notes,created_by,created_at)
                   VALUES(?,?,?,?,?,'planned',?,?,?,?)""",
                (rid,title,change_type,
                 start_at,end_at,
                 str(data.get("ticket_reference",""))[:200],str(data.get("notes",""))[:4000],user["email"],_now()),
            )
        return RedirectResponse("/change-calendar",303)

    @app.get("/change-calendar/{change_id}",response_class=HTMLResponse)
    def change_page(change_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        with core.db() as conn:
            p=conn.execute("""SELECT p.*,r.site_name FROM planned_changes p LEFT JOIN routers r ON r.id=p.router_id WHERE p.id=?""",(change_id,)).fetchone()
        if not p:return RedirectResponse("/change-calendar",303)
        csrf=core.csrf_token(request)
        note_link=""
        if p["router_id"]:
            note_link=f'<div style="margin-top:12px"><a href="/notes/{p["router_id"]}?type=planned_change&id={change_id}&ticket={html.escape(p["ticket_reference"] or "")}"><button>Add note / ticket</button></a></div>'
        body=f'''<div class="panel pad"><h2>{html.escape(p["title"])}</h2><div>{html.escape(p["site_name"] or "Fleet")} · {html.escape(p["change_type"])} · {html.escape(p["status"])}</div>
<div class="muted">{html.escape(p["start_at"])} → {html.escape(p["end_at"] or "")} · ticket {html.escape(p["ticket_reference"] or "-")}</div><p>{html.escape(p["notes"] or "")}</p>
<form method="post" action="/change-calendar/{change_id}/status" class="inline"><input type="hidden" name="csrf" value="{csrf}">
<select name="status">{''.join(f'<option value="{s}" {"selected" if s==p["status"] else ""}>{s}</option>' for s in ("planned","in_progress","completed","cancelled"))}</select><button class="primary">Update status</button></form>
{note_link}</div>'''
        return page_func("Planned Change",body,user,"operations")

    @app.post("/change-calendar/{change_id}/status")
    async def change_status(change_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        status=str(data.get("status","planned"))
        if status not in {"planned","in_progress","completed","cancelled"}:
            return HTMLResponse("<h1>400</h1><p>Invalid planned change status.</p>",status_code=400)
        with core.db() as conn:
            conn.execute("UPDATE planned_changes SET status=?,completed_at=? WHERE id=?",(status,_now() if status=="completed" else "",change_id))
        return RedirectResponse(f"/change-calendar/{change_id}",303)
