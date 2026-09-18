"""Analyze public-IP churn from existing endpoint history."""

import html
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations


def _now(): return datetime.now(timezone.utc)


def assess(router_id:int):
    migrations.migrate(); now=_now()
    with core.db() as conn:
        rows=conn.execute(
            "SELECT public_ip,first_seen_at,last_seen_at FROM router_public_ip_history WHERE router_id=? ORDER BY first_seen_at,id",
            (router_id,),
        ).fetchall()
        r=conn.execute("SELECT id,site_name FROM routers WHERE id=?",(router_id,)).fetchone()
    if not r:return None
    if not rows:
        result={"current_ip":"","unique_ips_30d":0,"changes_7d":0,"changes_30d":0,"changes_90d":0,"avg_days_between_changes":None,"status":"unknown","summary":"No public-IP history yet"}
    else:
        changes=[]
        prev=None
        for x in rows:
            ip=x["public_ip"] or ""
            if prev is not None and ip!=prev["public_ip"]:
                try: changes.append(datetime.fromisoformat(x["first_seen_at"]))
                except Exception: pass
            prev=x
        def count(days): return sum(1 for d in changes if d>=now-timedelta(days=days))
        recent_ips=set()
        cutoff30=now-timedelta(days=30)
        for x in rows:
            try:
                if datetime.fromisoformat(x["last_seen_at"])>=cutoff30: recent_ips.add(x["public_ip"])
            except Exception: pass
        intervals=[]
        for a,b in zip(changes,changes[1:]):
            intervals.append((b-a).total_seconds()/86400)
        avg=(sum(intervals)/len(intervals)) if intervals else None
        c7,c30,c90=count(7),count(30),count(90)
        if c7>=3 or c30>=8: status="high_churn"
        elif c30>=3 or c90>=6: status="changing"
        else: status="stable"
        summary=f"{c30} public-IP change(s) in 30d · {len(recent_ips)} unique IP(s)"
        if avg is not None: summary+=f" · average {avg:.1f} days between recorded changes"
        result={"current_ip":rows[-1]["public_ip"] or "","unique_ips_30d":len(recent_ips),"changes_7d":c7,"changes_30d":c30,"changes_90d":c90,"avg_days_between_changes":avg,"status":status,"summary":summary}
    with core.db() as conn:
        prev=conn.execute("SELECT status FROM router_public_ip_analysis WHERE router_id=?",(router_id,)).fetchone()
        conn.execute(
            """INSERT INTO router_public_ip_analysis(router_id,assessed_at,current_ip,unique_ips_30d,changes_7d,changes_30d,changes_90d,avg_days_between_changes,status,summary)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET assessed_at=excluded.assessed_at,current_ip=excluded.current_ip,
               unique_ips_30d=excluded.unique_ips_30d,changes_7d=excluded.changes_7d,changes_30d=excluded.changes_30d,
               changes_90d=excluded.changes_90d,avg_days_between_changes=excluded.avg_days_between_changes,status=excluded.status,summary=excluded.summary""",
            (router_id,now.isoformat(),result["current_ip"],result["unique_ips_30d"],result["changes_7d"],result["changes_30d"],result["changes_90d"],result["avg_days_between_changes"],result["status"],result["summary"])
        )
    if prev and prev["status"]!=result["status"]:
        events.record(router_id,"public-ip",f"Public-IP churn: {prev['status']} → {result['status']}",result["summary"],"warning" if result["status"]=="high_churn" else "info")
    return result


def assess_all():
    with core.db() as conn: ids=[r["id"] for r in conn.execute("SELECT id FROM routers WHERE enabled=1 AND COALESCE(lifecycle_state,'production')<>'retired'").fetchall()]
    for rid in ids:
        try: assess(rid)
        except Exception: pass
    return len(ids)


def register(app,page_func):
    @app.get("/public-ip-analysis/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        assess(router_id)
        with core.db() as conn:
            r=conn.execute("SELECT site_name FROM routers WHERE id=?",(router_id,)).fetchone()
            a=conn.execute("SELECT * FROM router_public_ip_analysis WHERE router_id=?",(router_id,)).fetchone()
        if not r:return RedirectResponse("/operations",303)
        body=f'''<div class="panel pad"><h2>Public-IP change analysis · {html.escape(r["site_name"])}</h2>
<div><strong>{html.escape(a["status"] if a else "unknown")}</strong> · {html.escape(a["summary"] if a else "No data")}</div></div>
<div class="cards">
<div class="card"><h3>Current IP</h3><div>{html.escape(a["current_ip"] if a else "-")}</div></div>
<div class="card"><h3>Changes 7d</h3><div class="value">{a["changes_7d"] if a else 0}</div></div>
<div class="card"><h3>Changes 30d</h3><div class="value">{a["changes_30d"] if a else 0}</div></div>
<div class="card"><h3>Changes 90d</h3><div class="value">{a["changes_90d"] if a else 0}</div></div>
<div class="card"><h3>Unique IPs 30d</h3><div class="value">{a["unique_ips_30d"] if a else 0}</div></div>
</div>'''
        return page_func("Public-IP Analysis",body,user,"operations")
