"""Ownership/protection rules for RouterOS objects."""

import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


OWNERSHIP={"tikcentral-owned","opticable-managed","customer-owned","never-modify"}
TYPES={"firewall","interface","route","vlan","script","scheduler","user","service","other"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def list_rules(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        return conn.execute(
            "SELECT * FROM router_object_protection WHERE router_id=? ORDER BY protected DESC,object_type,selector,id",
            (router_id,),
        ).fetchall()


def protected_matches(router_id:int, text:str):
    hay=(text or "").lower()
    matches=[]
    for r in list_rules(router_id):
        if not r["protected"]:
            continue
        selector=(r["selector"] or "").strip()
        if selector and selector.lower() in hay:
            matches.append(r)
    return matches


def register(app,page_func):
    migrations.migrate()

    @app.get("/protection/{router_id}",response_class=HTMLResponse)
    def protection_page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        with core.db() as conn:
            router=conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?",(router_id,)).fetchone()
        if not router: return RedirectResponse("/operations",303)
        csrf=core.csrf_token(request)
        rows=list_rules(router_id)
        body_rows="".join(
            f'<tr><td>{html.escape(r["object_type"])}</td><td><code>{html.escape(r["selector"])}</code></td><td>{html.escape(r["ownership"])}</td>'
            f'<td>{"Protected" if r["protected"] else "Advisory"}</td><td>{html.escape(r["notes"] or "")}</td><td>'
            f'<form method="post" action="/protection/{router_id}/{r["id"]}/delete"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">Delete</button></form></td></tr>'
            for r in rows
        ) or '<tr><td colspan="6">No object ownership/protection rules.</td></tr>'
        body=f'''<div class="panel pad"><h2>Protected objects · {html.escape(router["site_name"])}</h2>
<div class="muted">Selectors are exact text fragments Tikcentral uses as a safety guard for manual RouterOS commands. Use comments, interface names, route labels, script names, users, or other stable identifiers.</div></div>
<div class="panel pad"><form method="post" action="/protection/{router_id}" class="inline">
<input type="hidden" name="csrf" value="{csrf}">
<select name="object_type">{''.join(f'<option>{x}</option>' for x in sorted(TYPES))}</select>
<input name="selector" placeholder="Stable selector, e.g. CUSTOMER-VLAN-20" required style="min-width:260px">
<select name="ownership">{''.join(f'<option>{x}</option>' for x in ["customer-owned","opticable-managed","tikcentral-owned","never-modify"])}</select>
<label><input type="checkbox" name="protected" value="1" checked> Protected</label>
<input name="notes" placeholder="Why this object is protected" style="min-width:260px">
<button class="primary">Add rule</button></form></div>
<div class="panel"><table><thead><tr><th>Type</th><th>Selector</th><th>Ownership</th><th>Mode</th><th>Notes</th><th></th></tr></thead><tbody>{body_rows}</tbody></table></div>'''
        return page_func("Protected Objects",body,user,"operations")

    @app.post("/protection/{router_id}")
    async def add_rule(router_id:int,request:Request):
        user=core.require_web_role(request,"admin")
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        object_type=str(data.get("object_type","other"))
        if object_type not in TYPES: object_type="other"
        ownership=str(data.get("ownership","customer-owned"))
        if ownership not in OWNERSHIP: ownership="customer-owned"
        selector=str(data.get("selector","")).strip()[:300]
        if not selector: return RedirectResponse(f"/protection/{router_id}",303)
        notes=str(data.get("notes","")).strip()[:1000]
        now=_now()
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_object_protection
                   (router_id,object_type,selector,ownership,protected,notes,created_by,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (router_id,object_type,selector,ownership,1 if data.get("protected")=="1" else 0,notes,user["email"],now,now),
            )
        return RedirectResponse(f"/protection/{router_id}",303)

    @app.post("/protection/{router_id}/{rule_id}/delete")
    async def delete_rule(router_id:int,rule_id:int,request:Request):
        user=core.require_web_role(request,"admin")
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        with core.db() as conn:
            conn.execute("DELETE FROM router_object_protection WHERE id=? AND router_id=?",(rule_id,router_id))
        return RedirectResponse(f"/protection/{router_id}",303)
