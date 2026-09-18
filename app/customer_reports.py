"""Sanitized customer-facing service report rendered as printable HTML."""

import html
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


def _now(): return datetime.now(timezone.utc)


def _build(router_id:int,days:int):
    end=_now(); start=end-timedelta(days=days)
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,model,routeros_version FROM routers WHERE id=?",(router_id,)).fetchone()
        site=conn.execute("SELECT customer_name,site_code,address,circuit_type FROM router_site_metadata WHERE router_id=?",(router_id,)).fetchone()
        access=conn.execute(
            "SELECT management_ok FROM router_access_history WHERE router_id=? AND checked_at>=? AND checked_at<=?",
            (router_id,start.isoformat(),end.isoformat())).fetchall()
        maintenance=conn.execute(
            """SELECT occurred_at,work_type,ticket_reference,issue,work_performed,result,follow_up
               FROM router_maintenance_history WHERE router_id=? AND occurred_at>=? AND occurred_at<=?
               ORDER BY occurred_at DESC""",(router_id,start.isoformat(),end.isoformat())).fetchall()
        notes=conn.execute(
            """SELECT created_at,ticket_reference,note FROM operator_notes
               WHERE router_id=? AND visibility='customer' AND created_at>=? AND created_at<=?
               ORDER BY id DESC""",(router_id,start.isoformat(),end.isoformat())).fetchall()
        hardware=conn.execute(
            """SELECT category,manufacturer,model,asset_tag,location,status FROM hardware_inventory
               WHERE router_id=? AND status<>'retired' ORDER BY category,model""",(router_id,)).fetchall()
        upgrades=conn.execute(
            """SELECT created_at,status,target FROM router_jobs WHERE router_id=? AND kind LIKE 'upgrade%'
               AND created_at>=? AND created_at<=? ORDER BY id DESC""",(router_id,start.isoformat(),end.isoformat())).fetchall()
        incidents=conn.execute(
            """SELECT event_at,severity,category,summary FROM router_events WHERE router_id=?
               AND event_at>=? AND event_at<=? AND severity IN ('warning','critical')
               AND category IN ('wan','reboot','access','outage_classification','certificate','capacity')
               ORDER BY id DESC LIMIT 100""",(router_id,start.isoformat(),end.isoformat())).fetchall()
        capacity=conn.execute("SELECT status,summary,assessed_at FROM router_capacity_forecast WHERE router_id=?",(router_id,)).fetchone()
    total=len(access); healthy=sum(1 for x in access if x["management_ok"])
    availability=(healthy*100/total) if total else None
    return r,site,start,end,availability,maintenance,notes,hardware,upgrades,incidents,capacity


def register(app,page_func):
    migrations.migrate()

    @app.get("/customer-report/{router_id}",response_class=HTMLResponse)
    def report(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try:days=int(request.query_params.get("days","30"))
        except Exception:days=30
        days=days if days in {7,30,90,365} else 30
        r,site,start,end,availability,maintenance,notes,hardware,upgrades,incidents,capacity=_build(router_id,days)
        if not r:return RedirectResponse("/operations",303)
        customer=(site["customer_name"] if site else "") or r["site_name"]
        location=(site["address"] if site else "") or ""
        maint="".join(
            f'<tr><td>{html.escape(x["occurred_at"])}</td><td>{html.escape(x["work_type"])}</td><td>{html.escape(x["ticket_reference"] or "-")}</td><td>{html.escape(x["issue"] or "")}<div class="muted">{html.escape(x["work_performed"] or "")}</div></td><td>{html.escape(x["result"] or "")}</td></tr>'
            for x in maintenance) or '<tr><td colspan="5">No recorded service interventions in this period.</td></tr>'
        note_rows="".join(f'<tr><td>{html.escape(x["created_at"])}</td><td>{html.escape(x["ticket_reference"] or "-")}</td><td>{html.escape(x["note"])}</td></tr>' for x in notes) or '<tr><td colspan="3">No customer-facing service notes.</td></tr>'
        hw="".join(f'<tr><td>{html.escape(x["category"])}</td><td>{html.escape((x["manufacturer"]+" "+x["model"]).strip())}</td><td>{html.escape(x["asset_tag"] or "-")}</td><td>{html.escape(x["location"] or "-")}</td></tr>' for x in hardware) or '<tr><td colspan="4">No equipment inventory published.</td></tr>'
        up="".join(f'<tr><td>{html.escape(x["created_at"])}</td><td>{html.escape(x["target"] or "-")}</td><td>{html.escape(x["status"])}</td></tr>' for x in upgrades) or '<tr><td colspan="3">No RouterOS upgrades in this period.</td></tr>'
        inc="".join(f'<tr><td>{html.escape(x["event_at"])}</td><td>{html.escape(x["category"])}</td><td>{html.escape(x["summary"])}</td></tr>' for x in incidents) or '<tr><td colspan="3">No reportable service incidents recorded.</td></tr>'
        availability_text=f"{availability:.2f}% management-monitor availability" if availability is not None else "Insufficient monitoring samples"
        capacity_text=(capacity["summary"] if capacity and capacity["status"]=="warning" else "No current capacity trend requiring customer attention")
        csrf=core.csrf_token(request)
        body=f'''<style>@media print{{.tc-head,.tc-nav,button,.no-print{{display:none!important}}.tc-app{{max-width:none;padding:0}}}}</style>
<div class="panel pad"><h1>Service Report</h1><h2>{html.escape(customer)}</h2><div>{html.escape(r["site_name"])} {("· "+html.escape(location)) if location else ""}</div>
<div class="muted">Period: {start.date()} to {end.date()} · Generated {end.isoformat()}</div>
<div class="inline no-print" style="margin-top:12px"><button onclick="window.print()">Print / Save PDF</button><a href="/customer-report/{router_id}?days=7"><button>7d</button></a><a href="/customer-report/{router_id}?days=30"><button>30d</button></a><a href="/customer-report/{router_id}?days=90"><button>90d</button></a><a href="/customer-report/{router_id}?days=365"><button>1y</button></a>
<form method="post" action="/customer-report/{router_id}/record"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="days" value="{days}"><button>Record report generation</button></form></div></div>
<div class="panel pad"><h3>Service health</h3><div><strong>{html.escape(availability_text)}</strong></div><div>{html.escape(capacity_text)}</div></div>
<div class="panel"><div class="pad"><h3>Service interventions</h3></div><table><thead><tr><th>Date</th><th>Type</th><th>Ticket</th><th>Work</th><th>Result</th></tr></thead><tbody>{maint}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Service notes</h3></div><table><thead><tr><th>Date</th><th>Ticket</th><th>Note</th></tr></thead><tbody>{note_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Equipment</h3></div><table><thead><tr><th>Type</th><th>Equipment</th><th>Asset</th><th>Location</th></tr></thead><tbody>{hw}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Software maintenance</h3></div><table><thead><tr><th>Date</th><th>Target</th><th>Status</th></tr></thead><tbody>{up}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Service incidents</h3></div><table><thead><tr><th>Date</th><th>Type</th><th>Summary</th></tr></thead><tbody>{inc}</tbody></table></div>
<div class="panel pad"><div class="muted">This customer report intentionally excludes management IPs, credentials, configuration exports, raw commands, internal technician notes, AI analysis, and security-audit evidence.</div></div>'''
        return page_func("Customer Service Report",body,user,"operations")

    @app.post("/customer-report/{router_id}/record")
    async def record(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        try:days=int(data.get("days","30"))
        except Exception:days=30
        days=days if days in {7,30,90,365} else 30
        end=_now(); start=end-timedelta(days=days)
        with core.db() as conn:
            conn.execute(
                """INSERT INTO customer_report_history(router_id,period_start,period_end,generated_at,generated_by,title)
                   VALUES(?,?,?,?,?,?)""",
                (router_id,start.isoformat(),end.isoformat(),end.isoformat(),user["email"],f"{days}-day service report"),
            )
        return RedirectResponse(f"/customer-report/{router_id}?days={days}",303)
