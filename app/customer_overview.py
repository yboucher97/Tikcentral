"""Customer-centric aggregation over existing router/site data."""

import html
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


UNASSIGNED="Unassigned"


def _customer_name(value):
    return (value or "").strip() or UNASSIGNED


def register(app,page_func):
    migrations.migrate()

    @app.get("/customers",response_class=HTMLResponse)
    def customers(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        with core.db() as conn:
            rows=conn.execute(
                """SELECT r.id,r.site_name,r.model,r.lifecycle_state,
                          COALESCE(NULLIF(TRIM(s.customer_name),''),?) customer_name,
                          s.site_code,s.circuit_type,
                          COALESCE(a.management_ok,0) management_ok,
                          (SELECT COUNT(*) FROM alert_queue q WHERE q.router_id=r.id AND q.status<>'resolved') open_alerts
                   FROM routers r
                   LEFT JOIN router_site_metadata s ON s.router_id=r.id
                   LEFT JOIN router_access_state a ON a.router_id=r.id
                   WHERE r.enabled=1
                   ORDER BY customer_name COLLATE NOCASE,r.site_name COLLATE NOCASE""",
                (UNASSIGNED,),
            ).fetchall()
        grouped={}
        for r in rows: grouped.setdefault(r["customer_name"],[]).append(r)
        cards=[]
        for name,sites in grouped.items():
            production=sum(1 for x in sites if (x["lifecycle_state"] or "production")!="retired")
            healthy=sum(1 for x in sites if x["management_ok"])
            alerts=sum(int(x["open_alerts"] or 0) for x in sites)
            cards.append(
                f'<div class="card"><h3>{html.escape(name)}</h3>'
                f'<div class="value">{production}</div><div class="muted">active site/router record(s)</div>'
                f'<div style="margin-top:8px">{healthy}/{production} management healthy · {alerts} open alert(s)</div>'
                f'<div style="margin-top:12px"><a href="/customer?name={quote(name,safe="")}"><button class="primary">Open customer</button></a></div></div>'
            )
        body=f'''<div class="panel pad"><h2>Customers / sites</h2>
<div class="muted">Aggregated from existing site metadata. Sites without a customer name automatically appear under <strong>{UNASSIGNED}</strong>.</div></div>
<div class="cards">{''.join(cards) or '<div class="card">No routers/sites yet.</div>'}</div>'''
        return page_func("Customers",body,user,"customers")

    @app.get("/customer",response_class=HTMLResponse)
    def customer(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        name=_customer_name(request.query_params.get("name",""))
        with core.db() as conn:
            sites=conn.execute(
                """SELECT r.id,r.site_name,r.model,r.routeros_version,r.lifecycle_state,r.enabled,
                          s.customer_name,s.site_code,s.address,s.contact_name,s.contact_phone,s.contact_email,
                          s.circuit_type,s.circuit_reference,s.install_date,
                          a.management_ok,o.classification outage_classification,o.summary outage_summary,
                          c.status capacity_status,c.summary capacity_summary,
                          (SELECT COUNT(*) FROM alert_queue q WHERE q.router_id=r.id AND q.status<>'resolved') open_alerts
                   FROM routers r
                   LEFT JOIN router_site_metadata s ON s.router_id=r.id
                   LEFT JOIN router_access_state a ON a.router_id=r.id
                   LEFT JOIN router_outage_assessment o ON o.router_id=r.id
                   LEFT JOIN router_capacity_forecast c ON c.router_id=r.id
                   WHERE r.enabled=1
                     AND COALESCE(NULLIF(TRIM(s.customer_name),''),?)=?
                   ORDER BY r.site_name COLLATE NOCASE""",
                (UNASSIGNED,name),
            ).fetchall()
            router_ids=[int(x["id"]) for x in sites]
            if router_ids:
                qs=",".join("?" for _ in router_ids)
                maintenance=conn.execute(
                    f"""SELECT m.*,r.site_name FROM router_maintenance_history m JOIN routers r ON r.id=m.router_id
                        WHERE m.router_id IN ({qs}) ORDER BY m.occurred_at DESC LIMIT 100""",router_ids
                ).fetchall()
                hardware=conn.execute(
                    f"""SELECT h.*,r.site_name FROM hardware_inventory h JOIN routers r ON r.id=h.router_id
                        WHERE h.router_id IN ({qs}) AND h.status<>'retired' ORDER BY r.site_name,h.category,h.model""",router_ids
                ).fetchall()
                reports=conn.execute(
                    f"""SELECT c.*,r.site_name FROM customer_report_history c JOIN routers r ON r.id=c.router_id
                        WHERE c.router_id IN ({qs}) ORDER BY c.generated_at DESC LIMIT 50""",router_ids
                ).fetchall()
                alerts=conn.execute(
                    f"""SELECT q.*,r.site_name FROM alert_queue q JOIN routers r ON r.id=q.router_id
                        WHERE q.router_id IN ({qs}) AND q.status<>'resolved'
                        ORDER BY CASE q.severity WHEN 'critical' THEN 0 ELSE 1 END,q.id DESC LIMIT 100""",router_ids
                ).fetchall()
            else:
                maintenance=hardware=reports=alerts=[]

        site_rows="".join(
            f'<tr><td><strong>{html.escape(x["site_name"])}</strong><div class="muted">{html.escape(x["site_code"] or "")}</div></td>'
            f'<td>{html.escape(x["address"] or "-")}</td><td>{html.escape(x["circuit_type"] or "-")}<div class="muted">{html.escape(x["circuit_reference"] or "")}</div></td>'
            f'<td>{"Healthy" if x["management_ok"] else "Degraded/unknown"}</td><td>{html.escape(x["outage_classification"] or "unknown")}</td>'
            f'<td>{int(x["open_alerts"] or 0)}</td><td><a href="/operations/{x["id"]}">Operations</a> · <a href="/customer-report/{x["id"]}">Report</a></td></tr>'
            for x in sites
        ) or '<tr><td colspan="7">No sites for this customer.</td></tr>'
        maint_rows="".join(
            f'<tr><td>{html.escape(x["occurred_at"])}</td><td>{html.escape(x["site_name"])}</td><td>{html.escape(x["work_type"])}</td><td>{html.escape(x["ticket_reference"] or "-")}</td><td>{html.escape(x["result"] or "")}</td></tr>'
            for x in maintenance
        ) or '<tr><td colspan="5">No maintenance history.</td></tr>'
        hw_rows="".join(
            f'<tr><td>{html.escape(x["site_name"])}</td><td>{html.escape(x["category"])}</td><td>{html.escape((x["manufacturer"]+" "+x["model"]).strip() or "-")}</td><td>{html.escape(x["asset_tag"] or "-")}</td><td>{html.escape(x["location"] or "-")}</td></tr>'
            for x in hardware
        ) or '<tr><td colspan="5">No active hardware inventory.</td></tr>'
        report_rows="".join(
            f'<tr><td>{html.escape(x["generated_at"])}</td><td>{html.escape(x["site_name"])}</td><td>{html.escape(x["title"] or "")}</td><td>{html.escape(x["generated_by"] or "")}</td></tr>'
            for x in reports
        ) or '<tr><td colspan="4">No recorded customer reports.</td></tr>'
        alert_rows="".join(
            f'<tr><td>{html.escape(x["severity"])}</td><td>{html.escape(x["site_name"])}</td><td>{html.escape(x["title"])}</td><td>{html.escape(x["status"])}</td><td>{html.escape(x["assigned_to"] or "-")}</td><td><a href="/alerts">Open queue</a></td></tr>'
            for x in alerts
        ) or '<tr><td colspan="6">No open alerts.</td></tr>'

        contact=next((x for x in sites if x["contact_name"] or x["contact_email"] or x["contact_phone"]),None)
        contact_text="No contact entered"
        if contact:
            contact_text=" · ".join(v for v in (contact["contact_name"],contact["contact_email"],contact["contact_phone"]) if v)
        body=f'''<div class="panel pad"><h2>{html.escape(name)}</h2>
<div>{len(sites)} site/router record(s) · {sum(int(x["open_alerts"] or 0) for x in sites)} open alert(s)</div>
<div class="muted">{html.escape(contact_text)}</div>
<div style="margin-top:10px"><a href="/customers"><button>All customers</button></a></div></div>
<div class="panel"><div class="pad"><h3>Sites / circuits</h3></div><table><thead><tr><th>Site</th><th>Address</th><th>Circuit</th><th>Management</th><th>Outage state</th><th>Alerts</th><th></th></tr></thead><tbody>{site_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Open alerts</h3></div><table><thead><tr><th>Level</th><th>Site</th><th>Issue</th><th>Status</th><th>Assigned</th><th></th></tr></thead><tbody>{alert_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Maintenance history</h3></div><table><thead><tr><th>Date</th><th>Site</th><th>Type</th><th>Ticket</th><th>Result</th></tr></thead><tbody>{maint_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Hardware</h3></div><table><thead><tr><th>Site</th><th>Type</th><th>Equipment</th><th>Asset</th><th>Location</th></tr></thead><tbody>{hw_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Generated reports</h3></div><table><thead><tr><th>Date</th><th>Site</th><th>Report</th><th>Generated by</th></tr></thead><tbody>{report_rows}</tbody></table></div>'''
        return page_func("Customer Overview",body,user,"customers")
