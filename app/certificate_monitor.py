"""RouterOS certificate inventory and expiry monitoring."""

import html
import re
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, router_exec


COMMAND="/certificate print detail as-value without-paging"


def _now(): return datetime.now(timezone.utc)


def _parse_rows(text):
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


def _parse_dt(value):
    s=(value or "").strip()
    if not s:return None
    for fmt in ("%Y-%m-%d %H:%M:%S","%Y-%m-%dT%H:%M:%S","%b/%d/%Y %H:%M:%S","%b/%d/%Y"):
        try:return datetime.strptime(s,fmt).replace(tzinfo=timezone.utc)
        except Exception:pass
    try:return datetime.fromisoformat(s).replace(tzinfo=timezone.utc) if datetime.fromisoformat(s).tzinfo is None else datetime.fromisoformat(s)
    except Exception:return None


def collect(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired": return []
    raw=router_exec.read(r["vpn_ip"],COMMAND,timeout=40,label="Certificate inventory")
    rows=_parse_rows(raw); captured=_now().isoformat()
    with core.db() as conn:
        for x in rows:
            expires=x.get("invalid-after") or x.get("expires-after") or ""
            dt=_parse_dt(expires)
            days=int((dt-_now()).total_seconds()//86400) if dt else None
            status="unknown" if days is None else ("expired" if days<0 else ("critical" if days<=7 else ("warning" if days<=30 else "ok")))
            conn.execute(
                """INSERT INTO router_certificates(router_id,captured_at,name,common_name,issuer,fingerprint,key_usage,trusted,expires_at,days_remaining,status)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (router_id,captured,x.get("name",""),x.get("common-name",""),x.get("issuer",""),x.get("fingerprint",""),
                 x.get("key-usage",""),1 if str(x.get("trusted","")).lower() in {"yes","true"} else 0,expires,days,status),
            )
        conn.execute(
            """DELETE FROM router_certificates WHERE router_id=? AND id NOT IN
               (SELECT id FROM router_certificates WHERE router_id=? ORDER BY id DESC LIMIT 5000)""",(router_id,router_id))
    return rows


def register(app,page_func):
    migrations.migrate()
    @app.get("/certificates/{router_id}",response_class=HTMLResponse)
    def cert_page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try:collect(router_id)
        except Exception:pass
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?",(router_id,)).fetchone()
            latest_time=conn.execute("SELECT MAX(captured_at) t FROM router_certificates WHERE router_id=?",(router_id,)).fetchone()["t"]
            rows=conn.execute("SELECT * FROM router_certificates WHERE router_id=? AND captured_at=? ORDER BY days_remaining",(router_id,latest_time or "")).fetchall() if latest_time else []
        if not r:return RedirectResponse("/operations",303)
        rendered="".join(
            f'<tr><td><strong>{html.escape(x["name"] or "-")}</strong><div class="muted">{html.escape(x["common_name"] or "")}</div></td><td>{html.escape(x["issuer"] or "-")}</td><td>{html.escape(x["key_usage"] or "-")}</td><td>{html.escape(x["expires_at"] or "-")}</td><td>{x["days_remaining"] if x["days_remaining"] is not None else "—"}</td><td>{html.escape(x["status"])}</td></tr>'
            for x in rows
        ) or '<tr><td colspan="6">No certificates detected.</td></tr>'
        body=f'''<div class="panel pad"><h2>Certificates · {html.escape(r["site_name"])}</h2><div class="muted">RouterOS certificate inventory and expiry status. Warning ≤30 days, critical ≤7 days.</div></div>
<div class="panel"><table><thead><tr><th>Name</th><th>Issuer</th><th>Usage</th><th>Expires</th><th>Days</th><th>Status</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Certificates",body,user,"operations")
