"""Inventory RouterOS scripts, scheduler jobs and Netwatch without storing script source."""

import hashlib
import html
import json
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, router_exec


COMMANDS={
    "script":"/system script print detail as-value without-paging",
    "scheduler":"/system scheduler print detail as-value without-paging",
    "netwatch":"/tool netwatch print detail as-value without-paging",
}


def _now(): return datetime.now(timezone.utc).isoformat()


def _parse(text):
    rows=[]
    for line in (text or "").splitlines():
        line=line.strip()
        if not line or "=" not in line: continue
        row={}
        for part in line.split(";"):
            if "=" in part:
                k,v=part.split("=",1); row[k.strip()]=v.strip().strip('"')
        if row: rows.append(row)
    return rows


def _managed(name,comment):
    h=f"{name} {comment}".lower()
    return 1 if ("tikcentral" in h or "opticable" in h) else 0


def collect(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired": return []

    captured=_now(); items=[]
    for typ,cmd in COMMANDS.items():
        try: rows=_parse(router_exec.read(r["vpn_ip"],cmd,timeout=40,label=f"Automation inventory: {typ}"))
        except Exception: rows=[]
        for x in rows:
            name=x.get("name") or x.get("host") or x.get("comment") or "(unnamed)"
            comment=x.get("comment","")
            enabled=0 if str(x.get("disabled","")).lower() in {"yes","true"} else 1
            schedule=x.get("interval") or x.get("start-time") or x.get("start-date") or ""
            target=x.get("host") or x.get("type") or x.get("policy") or ""
            metadata={k:v for k,v in x.items() if k not in {"source","on-event","up-script","down-script","test-script"}}
            fp=hashlib.sha256(json.dumps(metadata,sort_keys=True).encode()).hexdigest()
            items.append((typ,name,enabled,_managed(name,comment),schedule,target,json.dumps(metadata,ensure_ascii=False),fp))

    overall_fp=hashlib.sha256(json.dumps([(x[0],x[1],x[2],x[3],x[7]) for x in items],sort_keys=True).encode()).hexdigest()
    with core.db() as conn:
        prev=conn.execute(
            "SELECT captured_at FROM router_automation_inventory WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)
        ).fetchone()
        prev_fp=""
        if prev:
            prev_rows=conn.execute(
                "SELECT object_type,name,enabled,managed,fingerprint FROM router_automation_inventory WHERE router_id=? AND captured_at=? ORDER BY object_type,name",
                (router_id,prev["captured_at"]),
            ).fetchall()
            prev_fp=hashlib.sha256(json.dumps([tuple(x) for x in prev_rows],default=str,sort_keys=True).encode()).hexdigest()
        for x in items:
            conn.execute(
                """INSERT INTO router_automation_inventory(router_id,captured_at,object_type,name,enabled,managed,schedule,target,metadata,fingerprint)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",(router_id,captured,*x)
            )
        conn.execute(
            """DELETE FROM router_automation_inventory WHERE router_id=? AND id NOT IN
               (SELECT id FROM router_automation_inventory WHERE router_id=? ORDER BY id DESC LIMIT 12000)""",
            (router_id,router_id),
        )
    if prev and prev_fp and prev_fp != overall_fp:
        unmanaged=sum(1 for x in items if x[2] and not x[3])
        events.record(router_id,"automation-inventory","RouterOS automation inventory changed",
                      f"objects={len(items)} enabled_unmanaged={unmanaged}","warning" if unmanaged else "info")
    return items


def register(app,page_func):
    @app.get("/automation-inventory/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try: collect(router_id)
        except Exception: pass
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?",(router_id,)).fetchone()
            t=conn.execute("SELECT MAX(captured_at) t FROM router_automation_inventory WHERE router_id=?",(router_id,)).fetchone()["t"]
            rows=conn.execute(
                "SELECT * FROM router_automation_inventory WHERE router_id=? AND captured_at=? ORDER BY object_type,name",
                (router_id,t or ""),
            ).fetchall() if t else []
        if not r:return RedirectResponse("/operations",303)
        body_rows="".join(
            f'<tr><td>{html.escape(x["object_type"])}</td><td><strong>{html.escape(x["name"])}</strong></td><td>{"Enabled" if x["enabled"] else "Disabled"}</td><td>{"Managed" if x["managed"] else "Unmanaged"}</td><td>{html.escape(x["schedule"] or "-")}</td><td>{html.escape(x["target"] or "-")}</td></tr>'
            for x in rows
        ) or '<tr><td colspan="6">No scripts, scheduler jobs or Netwatch objects detected.</td></tr>'
        body=f'''<div class="panel pad"><h2>RouterOS automation · {html.escape(r["site_name"])}</h2>
<div class="muted">Inventory only. Script bodies and event scripts are intentionally not stored in Tikcentral.</div></div>
<div class="panel"><table><thead><tr><th>Type</th><th>Name</th><th>State</th><th>Ownership</th><th>Schedule</th><th>Target</th></tr></thead><tbody>{body_rows}</tbody></table></div>'''
        return page_func("Automation Inventory",body,user,"operations")
