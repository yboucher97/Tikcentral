"""Router lifecycle state management."""

import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations


STATES=("new","commissioning","production","maintenance","retired")


def _now():
    return datetime.now(timezone.utc).isoformat()


def set_state(router_id:int,state:str,actor:str):
    migrations.migrate()
    if state not in STATES:
        raise ValueError("invalid lifecycle state")
    with core.db() as conn:
        router=conn.execute("SELECT id,site_name,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        if not router:
            raise ValueError("router not found")
        old=router["lifecycle_state"] or "production"
        conn.execute(
            "UPDATE routers SET lifecycle_state=?,lifecycle_updated_at=?,lifecycle_updated_by=? WHERE id=?",
            (state,_now(),actor,router_id),
        )
    if old != state:
        events.record(router_id,"lifecycle",f"Lifecycle changed: {old} → {state}",f"by={actor}","info")
    return state


def register(app,page_func):
    migrations.migrate()

    @app.get("/lifecycle",response_class=HTMLResponse)
    def lifecycle_index(request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        with core.db() as conn:
            rows=conn.execute(
                """SELECT id,site_name,model,vpn_ip,lifecycle_state,lifecycle_updated_at,lifecycle_updated_by
                   FROM routers ORDER BY site_name COLLATE NOCASE,id"""
            ).fetchall()
        body_rows="".join(
            f'<tr><td><strong>{html.escape(r["site_name"])}</strong><div class="muted">{html.escape(r["model"] or "")} · <code>{html.escape(r["vpn_ip"])}</code></div></td>'
            f'<td>{html.escape(r["lifecycle_state"] or "production")}</td><td>{html.escape(r["lifecycle_updated_at"] or "")}</td><td>{html.escape(r["lifecycle_updated_by"] or "")}</td>'
            f'<td><a href="/lifecycle/{r["id"]}">Change</a></td></tr>'
            for r in rows
        ) or '<tr><td colspan="5">No routers.</td></tr>'
        body=f'''<div class="panel pad"><h2>Router lifecycle</h2><div class="muted">Lifecycle state affects scheduling and attention. Retired routers are excluded from routine observability and Production alerts.</div></div>
<div class="panel"><table><thead><tr><th>Router</th><th>State</th><th>Updated</th><th>By</th><th></th></tr></thead><tbody>{body_rows}</tbody></table></div>'''
        return page_func("Lifecycle",body,user,"operations")

    @app.get("/lifecycle/{router_id}",response_class=HTMLResponse)
    def lifecycle_router(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model,vpn_ip,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        if not r: return RedirectResponse("/lifecycle",303)
        csrf=core.csrf_token(request)
        opts="".join(f'<option value="{x}" {"selected" if x==(r["lifecycle_state"] or "production") else ""}>{x.title()}</option>' for x in STATES)
        body=f'''<div class="panel pad"><h2>Lifecycle · {html.escape(r["site_name"])}</h2>
<form method="post" action="/lifecycle/{router_id}" class="inline"><input type="hidden" name="csrf" value="{csrf}">
<select name="state">{opts}</select><button class="primary">Save state</button><a href="/operations/{router_id}"><button type="button">Back</button></a></form></div>'''
        return page_func("Lifecycle",body,user,"operations")

    @app.post("/lifecycle/{router_id}")
    async def lifecycle_save(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        requested=str(data.get("state","production"))
        with core.db() as conn:
            current=conn.execute("SELECT lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        if requested=="retired" or (current and (current["lifecycle_state"] or "production")=="retired"):
            core.require_web_role(request,"admin")
        set_state(router_id,requested,user["email"])
        return RedirectResponse(f"/lifecycle/{router_id}",303)
