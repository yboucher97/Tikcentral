"""Editable customer/site metadata attached to each managed router."""

import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


FIELDS=(
    "customer_name","site_code","address","contact_name","contact_phone","contact_email",
    "circuit_type","circuit_reference","install_date","ticket_reference","support_notes"
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _router(router_id):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled FROM routers WHERE id=?",(router_id,)
        ).fetchone()


def get(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        return conn.execute("SELECT * FROM router_site_metadata WHERE router_id=?",(router_id,)).fetchone()


def register(app,page_func):
    migrations.migrate()

    @app.get("/site/{router_id}",response_class=HTMLResponse)
    def site_page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        router=_router(router_id)
        if not router: return RedirectResponse("/operations",303)
        row=get(router_id)
        def val(name):
            return html.escape(row[name] if row else "")
        csrf=core.csrf_token(request)
        body=f'''<div class="panel pad"><h2>Site / customer · {html.escape(router["site_name"])}</h2>
<div class="muted">{html.escape(router["model"] or "")} · <code>{html.escape(router["vpn_ip"])}</code></div></div>
<div class="panel pad"><form method="post" action="/site/{router_id}">
<input type="hidden" name="csrf" value="{csrf}">
<div class="cards">
<div><label>Customer<br><input name="customer_name" value="{val("customer_name")}" style="width:100%"></label></div>
<div><label>Site code<br><input name="site_code" value="{val("site_code")}" style="width:100%"></label></div>
<div><label>Address<br><input name="address" value="{val("address")}" style="width:100%"></label></div>
<div><label>Contact name<br><input name="contact_name" value="{val("contact_name")}" style="width:100%"></label></div>
<div><label>Contact phone<br><input name="contact_phone" value="{val("contact_phone")}" style="width:100%"></label></div>
<div><label>Contact email<br><input name="contact_email" value="{val("contact_email")}" style="width:100%"></label></div>
<div><label>Circuit type<br><input name="circuit_type" value="{val("circuit_type")}" placeholder="Bell fibre / cable / LTE / PPPoE..." style="width:100%"></label></div>
<div><label>Circuit / account reference<br><input name="circuit_reference" value="{val("circuit_reference")}" style="width:100%"></label></div>
<div><label>Circuit download Mbps<br><input type="number" min="0" step="0.1" name="circuit_down_mbps" value="{val("circuit_down_mbps")}" placeholder="e.g. 1000" style="width:100%"></label></div>
<div><label>Circuit upload Mbps<br><input type="number" min="0" step="0.1" name="circuit_up_mbps" value="{val("circuit_up_mbps")}" placeholder="e.g. 1000" style="width:100%"></label></div>
<div><label>Install date<br><input type="date" name="install_date" value="{val("install_date")}" style="width:100%"></label></div>
<div><label>Ticket / work order<br><input name="ticket_reference" value="{val("ticket_reference")}" style="width:100%"></label></div>
</div>
<div style="margin-top:14px"><label>Support / technician notes<br><textarea name="support_notes" style="width:100%;min-height:140px">{val("support_notes")}</textarea></label></div>
<div class="inline" style="margin-top:14px"><button class="primary">Save site information</button><a href="/operations/{router_id}"><button type="button">Back</button></a></div>
</form></div>'''
        return page_func("Site Metadata",body,user,"operations")

    @app.post("/site/{router_id}")
    async def save_site(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        router=_router(router_id)
        if not router: return RedirectResponse("/operations",303)
        values={f:str(data.get(f,"")).strip()[:4000 if f=="support_notes" else 300] for f in FIELDS}
        def speed(name):
            try:
                v=float(str(data.get(name,"")).strip())
                return v if v>0 else None
            except Exception:
                return None
        down_mbps=speed("circuit_down_mbps")
        up_mbps=speed("circuit_up_mbps")
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_site_metadata
                   (router_id,customer_name,site_code,address,contact_name,contact_phone,contact_email,
                    circuit_type,circuit_reference,circuit_down_mbps,circuit_up_mbps,install_date,ticket_reference,support_notes,updated_by,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(router_id) DO UPDATE SET
                     customer_name=excluded.customer_name,site_code=excluded.site_code,address=excluded.address,
                     contact_name=excluded.contact_name,contact_phone=excluded.contact_phone,
                     contact_email=excluded.contact_email,circuit_type=excluded.circuit_type,
                     circuit_reference=excluded.circuit_reference,circuit_down_mbps=excluded.circuit_down_mbps,
                     circuit_up_mbps=excluded.circuit_up_mbps,install_date=excluded.install_date,
                     ticket_reference=excluded.ticket_reference,support_notes=excluded.support_notes,
                     updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                (router_id,values["customer_name"],values["site_code"],values["address"],values["contact_name"],
                 values["contact_phone"],values["contact_email"],values["circuit_type"],values["circuit_reference"],
                 down_mbps,up_mbps,values["install_date"],values["ticket_reference"],values["support_notes"],user["email"],_now()),
            )
        return RedirectResponse(f"/site/{router_id}",303)
