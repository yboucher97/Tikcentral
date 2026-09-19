"""Structured site hardware inventory."""

import html
from datetime import datetime, timezone
from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from app import main as core, migrations


def _now(): return datetime.now(timezone.utc).isoformat()

CATEGORIES={"router","switch","access-point","lte-modem","ups","camera","access-control","other"}
STATUSES={"installed","spare","repair","retired"}


def register(app,page_func):
    migrations.migrate()

    @app.get("/hardware/{router_id}",response_class=HTMLResponse)
    def hardware_page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        with core.db() as conn:
            router=conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?",(router_id,)).fetchone()
            rows=conn.execute("SELECT * FROM hardware_inventory WHERE router_id=? ORDER BY status,category,id",(router_id,)).fetchall()
        if not router:return RedirectResponse("/operations",303)
        csrf=core.csrf_token(request)
        rendered="".join(
            f'<tr><td>{html.escape(x["category"])}</td><td><strong>{html.escape(x["manufacturer"])} {html.escape(x["model"])}</strong><div class="muted">{html.escape(x["serial"] or "-")}</div></td>'
            f'<td>{html.escape(x["asset_tag"] or "-")}</td><td>{html.escape(x["location"] or "-")}</td><td>{html.escape(x["installed_at"] or "-")}</td><td>{html.escape(x["warranty_until"] or "-")}</td><td>{html.escape(x["status"])}</td><td>{html.escape(x["notes"] or "")}</td>'
            f'<td><form method="post" action="/hardware/{router_id}/{x["id"]}/status" class="inline"><input type="hidden" name="csrf" value="{csrf}"><select name="status">'+''.join(f'<option value="{s}" {"selected" if x["status"]==s else ""}>{s}</option>' for s in ("installed","spare","repair","retired"))+f'</select><button>Update</button></form></td></tr>'
            for x in rows
        ) or '<tr><td colspan="9">No hardware inventory.</td></tr>'
        body=f'''<div class="panel pad"><h2>Hardware inventory · {html.escape(router["site_name"])}</h2>
<form method="post" action="/hardware/{router_id}"><input type="hidden" name="csrf" value="{csrf}">
<div class="cards">
<div><label>Category<br><select name="category"><option>router</option><option>switch</option><option>access-point</option><option>lte-modem</option><option>ups</option><option>camera</option><option>access-control</option><option>other</option></select></label></div>
<div><label>Manufacturer<br><input name="manufacturer" style="width:100%"></label></div><div><label>Model<br><input name="model" style="width:100%"></label></div>
<div><label>Serial<br><input name="serial" style="width:100%"></label></div><div><label>Asset tag<br><input name="asset_tag" style="width:100%"></label></div>
<div><label>Location<br><input name="location" style="width:100%"></label></div><div><label>Installed<br><input type="date" name="installed_at" style="width:100%"></label></div>
<div><label>Warranty until<br><input type="date" name="warranty_until" style="width:100%"></label></div><div><label>Status<br><select name="status"><option>installed</option><option>spare</option><option>repair</option><option>retired</option></select></label></div>
</div><div style="margin-top:10px"><label>Notes<br><textarea name="notes" style="width:100%"></textarea></label></div><button class="primary">Add hardware</button></form></div>
<div class="panel"><table><thead><tr><th>Category</th><th>Equipment</th><th>Asset</th><th>Location</th><th>Installed</th><th>Warranty</th><th>Status</th><th>Notes</th><th></th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Hardware Inventory",body,user,"operations")

    @app.post("/hardware/{router_id}")
    async def hardware_add(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        now=_now()
        vals=[str(data.get(k,"")).strip() for k in ("category","manufacturer","model","serial","asset_tag","location","installed_at","warranty_until","status","notes")]
        category,status=vals[0],vals[8]
        if category not in CATEGORIES or status not in STATUSES:
            raise HTTPException(status_code=400,detail="invalid hardware category or status")
        with core.db() as conn:
            if not conn.execute("SELECT 1 FROM routers WHERE id=?",(router_id,)).fetchone():
                raise HTTPException(status_code=404,detail="router not found")
            conn.execute(
                """INSERT INTO hardware_inventory(router_id,category,manufacturer,model,serial,asset_tag,location,installed_at,warranty_until,status,notes,created_by,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (router_id,*[x[:2000] for x in vals],user["email"],now,now),
            )
        return RedirectResponse(f"/hardware/{router_id}",303)

    @app.post("/hardware/{router_id}/{item_id}/status")
    async def hardware_status(router_id:int,item_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        status=str(data.get("status","installed"))
        if status not in {"installed","spare","repair","retired"}:
            status="installed"
        with core.db() as conn:
            conn.execute(
                "UPDATE hardware_inventory SET status=?,updated_at=? WHERE id=? AND router_id=?",
                (status,_now(),item_id,router_id),
            )
        return RedirectResponse(f"/hardware/{router_id}",303)
