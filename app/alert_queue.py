"""Persistent NOC-style acknowledgement and assignment queue."""

import html
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


STATUSES=("new","acknowledged","assigned","investigating","resolved")


def _now(): return datetime.now(timezone.utc).isoformat()


def sync():
    migrations.migrate(); cutoff=(datetime.now(timezone.utc)-timedelta(days=7)).isoformat()
    with core.db() as conn:
        events=conn.execute(
            """SELECT e.id,e.router_id,e.event_at,e.severity,e.category,e.summary,e.details,r.site_name
               FROM router_events e LEFT JOIN routers r ON r.id=e.router_id
               WHERE e.severity IN ('warning','critical') AND e.event_at>=?
               ORDER BY e.id""",(cutoff,)
        ).fetchall()
        for e in events:
            key=f'event:{e["id"]}'
            conn.execute(
                """INSERT INTO alert_queue(source_key,router_id,severity,title,details,link,status,first_seen_at,last_seen_at,updated_at)
                   VALUES(?,?,?,?,?,?,'new',?,?,?)
                   ON CONFLICT(source_key) DO UPDATE SET last_seen_at=excluded.last_seen_at""",
                (key,e["router_id"],e["severity"],f'{e["site_name"] or "Tikcentral"} · {e["summary"]}',e["details"] or "",
                 f'/operations/{e["router_id"]}' if e["router_id"] else "/system-health",e["event_at"],e["event_at"],_now()),
            )
    return len(events)


def register(app,page_func):
    migrations.migrate()

    @app.get("/alerts",response_class=HTMLResponse)
    def page(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        sync()
        status=request.query_params.get("status","open")
        with core.db() as conn:
            if status=="resolved":
                rows=conn.execute("SELECT * FROM alert_queue WHERE status='resolved' ORDER BY id DESC LIMIT 250").fetchall()
            else:
                rows=conn.execute("SELECT * FROM alert_queue WHERE status<>'resolved' ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END,id DESC LIMIT 250").fetchall()
        csrf=core.csrf_token(request)
        rendered_parts=[]
        for x in rows:
            options="".join(f'<option {"selected" if s==x["status"] else ""}>{s}</option>' for s in STATUSES)
            rendered_parts.append(
                f'<tr><td>{html.escape(x["last_seen_at"] or x["first_seen_at"] or "")}<div class="muted">first {html.escape(x["first_seen_at"] or "-")}</div></td>'
                f'<td>{html.escape(x["severity"])}</td><td><strong>{html.escape(x["title"])}</strong><div class="muted">{html.escape(x["details"][-300:])}</div></td>'
                f'<td>{html.escape(x["status"])}</td><td>{html.escape(x["assigned_to"] or "-")}</td><td>{html.escape(x["ticket_reference"] or "-")}</td>'
                f'<td><a href="{html.escape(x["link"])}">Open</a><form method="post" action="/alerts/{x["id"]}" class="inline"><input type="hidden" name="csrf" value="{csrf}">'
                f'<select name="status">{options}</select>'
                f'<input name="assigned_to" value="{html.escape(x["assigned_to"] or "")}" placeholder="technician"><input name="ticket_reference" value="{html.escape(x["ticket_reference"] or "")}" placeholder="ticket">'
                f'<input name="resolution_note" value="{html.escape(x["resolution_note"] or "")}" placeholder="note"><button>Update</button></form></td></tr>'
            )
        rendered="".join(rendered_parts) or '<tr><td colspan="7">No alerts.</td></tr>'
        body=f'''<div class="panel pad"><h2>Alert queue</h2>
<div class="muted">Persistent NOC workflow: New → Acknowledged → Assigned → Investigating → Resolved.</div>
<div class="inline"><a href="/alerts"><button>Open</button></a><a href="/alerts?status=resolved"><button>Resolved</button></a></div></div>
<div class="panel"><table><thead><tr><th>Time</th><th>Level</th><th>Alert</th><th>Status</th><th>Assigned</th><th>Ticket</th><th>Workflow</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Alert Queue",body,user,"alerts")

    @app.post("/alerts/{alert_id}")
    async def update(alert_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        status=str(data.get("status","new"))
        if status not in STATUSES:status="new"
        assigned=str(data.get("assigned_to","")).strip()[:200]
        ticket=str(data.get("ticket_reference","")).strip()[:200]
        note=str(data.get("resolution_note","")).strip()[:2000]
        now=_now()
        with core.db() as conn:
            row=conn.execute("SELECT status FROM alert_queue WHERE id=?",(alert_id,)).fetchone()
            if row:
                ack=now if status in {"acknowledged","assigned","investigating","resolved"} and row["status"]=="new" else ""
                resolved=now if status=="resolved" else ""
                conn.execute(
                    """UPDATE alert_queue SET status=?,assigned_to=?,ticket_reference=?,resolution_note=?,
                       acknowledged_at=CASE WHEN ?<>'' THEN ? ELSE acknowledged_at END,
                       resolved_at=?,updated_by=?,updated_at=? WHERE id=?""",
                    (status,assigned,ticket,note,ack,ack,resolved,user["email"],now,alert_id),
                )
        return RedirectResponse("/alerts",303)
