"""Factual hardware lifecycle intelligence for enrolled routers."""

import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


def _now(): return datetime.now(timezone.utc)


def _days_since(value):
    if not value:return 0
    try:return max(0,int((_now()-datetime.fromisoformat(value)).total_seconds()/86400))
    except Exception:return 0


def assess(router_id:int):
    migrations.migrate(); now=_now().isoformat()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,model,created_at,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        if not r:return None
        obs=conn.execute("SELECT * FROM router_model_capability_observations WHERE router_id=?",(router_id,)).fetchone()
        first_model=conn.execute("SELECT MIN(observed_at) t FROM router_model_capability_observations WHERE model=?",(r["model"] or (obs["model"] if obs else ""),)).fetchone()["t"]
        reboot_count=conn.execute("SELECT COUNT(*) c FROM router_events WHERE router_id=? AND category='reboot'",(router_id,)).fetchone()["c"]
        hw=conn.execute("""SELECT installed_at,warranty_until FROM hardware_inventory
                           WHERE router_id=? AND category='router' ORDER BY id DESC LIMIT 1""",(router_id,)).fetchone()
        existing=conn.execute("SELECT replacement_notes,notes_updated_by,notes_updated_at FROM router_hardware_lifecycle WHERE router_id=?",(router_id,)).fetchone()
    first_seen=r["created_at"] or (obs["observed_at"] if obs else "")
    installed=(hw["installed_at"] if hw else "") or ""
    warranty=(hw["warranty_until"] if hw else "") or ""
    observed_days=_days_since(first_seen)
    model_days=_days_since(first_model)
    mem=obs["total_memory_bytes"] if obs else None
    storage=obs["total_storage_bytes"] if obs else None
    summary=f"Observed {observed_days} day(s) · {reboot_count} recorded reboot(s)"
    if model_days:summary+=f" · model observed in fleet for {model_days} day(s)"
    with core.db() as conn:
        conn.execute("""INSERT INTO router_hardware_lifecycle
            (router_id,assessed_at,first_seen_at,observed_days,model_first_seen_at,model_observed_days,reboot_count,total_memory_bytes,total_storage_bytes,installed_at,warranty_until,lifecycle_state,replacement_notes,notes_updated_by,notes_updated_at,summary)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(router_id) DO UPDATE SET assessed_at=excluded.assessed_at,first_seen_at=excluded.first_seen_at,
            observed_days=excluded.observed_days,model_first_seen_at=excluded.model_first_seen_at,model_observed_days=excluded.model_observed_days,
            reboot_count=excluded.reboot_count,total_memory_bytes=excluded.total_memory_bytes,total_storage_bytes=excluded.total_storage_bytes,
            installed_at=excluded.installed_at,warranty_until=excluded.warranty_until,lifecycle_state=excluded.lifecycle_state,summary=excluded.summary""",
            (router_id,now,first_seen,observed_days,first_model or "",model_days,reboot_count,mem,storage,installed,warranty,r["lifecycle_state"] or "production",
             existing["replacement_notes"] if existing else "",existing["notes_updated_by"] if existing else "",existing["notes_updated_at"] if existing else "",summary))
    return summary


def assess_all():
    with core.db() as conn:ids=[x["id"] for x in conn.execute("SELECT id FROM routers WHERE enabled=1 AND COALESCE(lifecycle_state,'production')<>'retired'").fetchall()]
    for rid in ids:
        try:assess(rid)
        except Exception:pass
    return len(ids)


def _human_bytes(v):
    if v is None:return "—"
    v=float(v)
    for unit in ("B","KB","MB","GB","TB"):
        if v<1024 or unit=="TB":return f"{v:.1f} {unit}"
        v/=1024


def register(app,page_func):
    @app.get("/hardware-lifecycle",response_class=HTMLResponse)
    def fleet_page(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        assess_all()
        with core.db() as conn:
            rows=conn.execute("""SELECT r.site_name,r.model,h.* FROM router_hardware_lifecycle h JOIN routers r ON r.id=h.router_id
                                 ORDER BY h.observed_days DESC,r.site_name""").fetchall()
        rendered="".join(f'<tr><td><a href="/hardware-lifecycle/{x["router_id"]}"><strong>{html.escape(x["site_name"])}</strong></a></td><td>{html.escape(x["model"] or "-")}</td><td>{x["observed_days"]}</td><td>{x["model_observed_days"]}</td><td>{x["reboot_count"]}</td><td>{_human_bytes(x["total_memory_bytes"])}</td><td>{_human_bytes(x["total_storage_bytes"])}</td><td>{html.escape(x["lifecycle_state"])}</td></tr>' for x in rows) or '<tr><td colspan="8">No lifecycle observations yet.</td></tr>'
        body=f'''<div class="panel pad"><h2>Hardware lifecycle intelligence</h2><div class="muted">Factual fleet observations only. Model age means first observed in your Tikcentral fleet, not manufacturer release/EOL age.</div></div>
<div class="panel"><table><thead><tr><th>Site</th><th>Model</th><th>Router observed days</th><th>Model fleet days</th><th>Recorded reboots</th><th>Memory</th><th>Storage</th><th>Lifecycle</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Hardware Lifecycle",body,user,"hardware-lifecycle")

    @app.get("/hardware-lifecycle/{router_id}",response_class=HTMLResponse)
    def detail(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        assess(router_id)
        with core.db() as conn:
            r=conn.execute("SELECT site_name,model FROM routers WHERE id=?",(router_id,)).fetchone()
            h=conn.execute("SELECT * FROM router_hardware_lifecycle WHERE router_id=?",(router_id,)).fetchone()
        if not r or not h:return RedirectResponse("/operations",303)
        csrf=core.csrf_token(request)
        body=f'''<div class="panel pad"><h2>Hardware lifecycle · {html.escape(r["site_name"])}</h2><div>{html.escape(h["summary"])}</div>
<div class="muted">Model fleet age is based on first Tikcentral observation. It is not vendor EOL/EOS data.</div></div>
<div class="cards">
<div class="card"><h3>First seen</h3><div>{html.escape(h["first_seen_at"] or "-")}</div><div class="value">{h["observed_days"]} d</div></div>
<div class="card"><h3>Model first seen</h3><div>{html.escape(h["model_first_seen_at"] or "-")}</div><div class="value">{h["model_observed_days"]} d</div></div>
<div class="card"><h3>Recorded reboots</h3><div class="value">{h["reboot_count"]}</div></div>
<div class="card"><h3>Memory</h3><div class="value">{_human_bytes(h["total_memory_bytes"])}</div></div>
<div class="card"><h3>Storage</h3><div class="value">{_human_bytes(h["total_storage_bytes"])}</div></div>
<div class="card"><h3>Installed</h3><div>{html.escape(h["installed_at"] or "-")}</div><div class="muted">Warranty {html.escape(h["warranty_until"] or "-")}</div></div>
</div>
<div class="panel pad"><h3>Replacement notes</h3><form method="post" action="/hardware-lifecycle/{router_id}/notes"><input type="hidden" name="csrf" value="{csrf}"><textarea name="replacement_notes" style="width:100%;min-height:130px">{html.escape(h["replacement_notes"] or "")}</textarea><div class="muted">Operator-maintained notes only; Tikcentral does not automatically decide that hardware must be replaced.</div><button class="primary" style="margin-top:10px">Save notes</button></form></div>'''
        return page_func("Hardware Lifecycle",body,user,"hardware-lifecycle")

    @app.post("/hardware-lifecycle/{router_id}/notes")
    async def save_notes(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request);core.require_csrf(request,data.get("csrf",""))
        notes=str(data.get("replacement_notes",""))[:5000]
        assess(router_id)
        with core.db() as conn:
            conn.execute("UPDATE router_hardware_lifecycle SET replacement_notes=?,notes_updated_by=?,notes_updated_at=? WHERE router_id=?",
                         (notes,user["email"],_now().isoformat(),router_id))
        return RedirectResponse(f"/hardware-lifecycle/{router_id}",303)
