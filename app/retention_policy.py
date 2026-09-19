"""Configurable retention policy with scheduled cleanup and rough storage impact."""

import html
import json
import os
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations, settings


POLICIES=[
    ("telemetry_days","Telemetry","router_telemetry","captured_at",""),
    ("traffic_days","Traffic history","router_traffic_history","captured_at",""),
    ("lte_days","LTE history","router_lte_history","captured_at",""),
    ("interface_days","Interface history","router_interface_history","captured_at",""),
    ("wan_days","WAN history","router_wan_history","captured_at",""),
    ("wan_probe_days","WAN probe history","router_wan_probe_history","captured_at",""),
    ("access_days","Management access history","router_access_history","checked_at",""),
    ("public_ip_days","Public IP / ISP history","router_public_ip_history","last_seen_at",""),
    ("public_ip_sighting_days","Public IP transition sightings","router_public_ip_sightings","observed_at",""),
    ("local_utilization_days","Local utilization estimates","router_local_utilization","captured_at",""),
    ("log_pattern_days","Router log patterns","router_log_patterns","captured_at",""),
    ("certificate_days","Certificate history","router_certificates","captured_at",""),
    ("automation_days","Automation inventory","router_automation_inventory","captured_at",""),
    ("topology_days","Topology history","router_topology_devices","captured_at",""),
    ("event_days","Router events","router_events","event_at",""),
    ("operator_audit_days","Operator audit","operator_audit_log","event_at",""),
    ("database_health_days","DB health history","database_health_history","checked_at",""),
    ("mtu_days","MTU diagnostics","router_mtu_history","captured_at",""),
    ("dns_health_days","DNS health history","router_dns_health","captured_at",""),
    ("wan_quality_days","WAN quality / bufferbloat","router_wan_quality","captured_at",""),
    ("pppoe_days","PPPoE history","router_pppoe_history","captured_at",""),
    ("isp_gateway_days","ISP gateway history","router_isp_gateway_history","captured_at",""),
    ("resolved_alert_days","Resolved alerts","alert_queue","resolved_at","status='resolved'"),
    ("snapshot_days","Configuration snapshots","router_snapshots","captured_at",""),
]


def _now():return datetime.now(timezone.utc)


def _human(value):
    value=float(value or 0)
    for unit in ("B","KB","MB","GB","TB"):
        if value<1024 or unit=="TB":return f"{value:.1f} {unit}"
        value/=1024


def _settings():
    migrations.migrate()
    with core.db() as conn:return conn.execute("SELECT * FROM retention_settings WHERE id=1").fetchone()


def _stats(conn,s):
    stats=[]; total_rows=0; eligible_rows=0
    now=_now()
    for key,label,table,ts,where in POLICIES:
        days=int(s[key] or 0)
        clause=f" WHERE {where}" if where else ""
        total=int(conn.execute(f"SELECT COUNT(*) FROM {table}{clause}").fetchone()[0])
        eligible=0
        if days>0:
            cutoff=(now-timedelta(days=days)).isoformat()
            condition=f"{where} AND datetime({ts})<datetime(?)" if where else f"datetime({ts})<datetime(?)"
            eligible=int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {condition}",(cutoff,)).fetchone()[0])
        stats.append((key,label,days,total,eligible))
        total_rows+=total; eligible_rows+=eligible
    db_bytes=0
    try:
        db_bytes=os.path.getsize(settings.DB_PATH)+os.path.getsize(settings.DB_PATH+"-wal")
    except OSError:
        try:db_bytes=os.path.getsize(settings.DB_PATH)
        except OSError:pass
    rough=(db_bytes*eligible_rows/total_rows) if total_rows and eligible_rows else 0
    return stats,rough


def cleanup(force=False):
    migrations.migrate(); now=_now()
    with core.db() as conn:
        last=conn.execute("SELECT ran_at FROM retention_cleanup_history ORDER BY id DESC LIMIT 1").fetchone()
        if last and not force:
            try:
                if (now-datetime.fromisoformat(last["ran_at"])).total_seconds()<20*3600:return 0
            except Exception:pass
        s=conn.execute("SELECT * FROM retention_settings WHERE id=1").fetchone()
        details={}; deleted_total=0
        for key,label,table,ts,where in POLICIES:
            days=int(s[key] or 0)
            if days<=0:
                details[key]={"days":0,"deleted":0}; continue
            cutoff=(now-timedelta(days=days)).isoformat()
            condition=f"{where} AND datetime({ts})<datetime(?)" if where else f"datetime({ts})<datetime(?)"
            cur=conn.execute(f"DELETE FROM {table} WHERE {condition}",(cutoff,))
            deleted=max(0,int(cur.rowcount or 0)); deleted_total+=deleted
            details[key]={"days":days,"deleted":deleted}
        conn.execute("INSERT INTO retention_cleanup_history(ran_at,deleted_rows,details) VALUES(?,?,?)",
                     (now.isoformat(),deleted_total,json.dumps(details,sort_keys=True)))
        conn.execute("DELETE FROM retention_cleanup_history WHERE id NOT IN (SELECT id FROM retention_cleanup_history ORDER BY id DESC LIMIT 365)")
    return deleted_total


def register(app,page_func):
    migrations.migrate()

    @app.get("/retention",response_class=HTMLResponse)
    def page(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        s=_settings()
        with core.db() as conn:
            stats,rough=_stats(conn,s)
            recent=conn.execute("SELECT * FROM retention_cleanup_history ORDER BY id DESC LIMIT 30").fetchall()
        csrf=core.csrf_token(request)
        rows="".join(
            f'<tr><td>{html.escape(label)}</td><td><input form="retention-form" type="number" min="0" max="3650" name="{key}" value="{days}" style="width:100px"></td><td>{total}</td><td>{eligible}</td></tr>'
            for key,label,days,total,eligible in stats
        )
        runs="".join(f'<tr><td>{html.escape(x["ran_at"])}</td><td>{x["deleted_rows"]}</td></tr>' for x in recent) or '<tr><td colspan="2">No cleanup runs yet.</td></tr>'
        body=f'''<div class="panel pad"><h2>Retention policy</h2>
<div class="muted">0 days means keep forever. Configuration snapshots default to forever. Cleanup runs at most once per day. Saving applies the new cleanup policy immediately.</div>
<div style="margin-top:8px"><strong>Currently eligible rows:</strong> {sum(x[4] for x in stats)} · <strong>rough possible DB reclaim:</strong> {_human(rough)}</div>
<div class="muted">The reclaim estimate is intentionally rough because SQLite pages are shared and VACUUM is not run automatically.</div></div>
<form id="retention-form" method="post" action="/retention"><input type="hidden" name="csrf" value="{csrf}"></form>
<div class="panel"><table><thead><tr><th>Data</th><th>Keep days</th><th>Current rows</th><th>Eligible now</th></tr></thead><tbody>{rows}</tbody></table>
<div class="pad"><button form="retention-form" class="primary" onclick="return confirm('Save this retention policy and immediately delete data older than the selected limits?')">Save retention policy</button></div></div>
<div class="panel"><div class="pad"><h3>Cleanup history</h3></div><table><thead><tr><th>Run</th><th>Deleted rows</th></tr></thead><tbody>{runs}</tbody></table></div>'''
        return page_func("Retention Policy",body,user,"retention")

    @app.post("/retention")
    async def save(request:Request):
        user=core.require_web_role(request,"admin")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        values=[]
        for key,label,_,_,_ in POLICIES:
            raw=data.get(key)
            if raw is None:
                raise HTTPException(status_code=400,detail=f"missing retention value for {label}")
            try:
                v=int(raw)
            except (TypeError,ValueError):
                raise HTTPException(status_code=400,detail=f"invalid retention value for {label}")
            if not 0 <= v <= 3650:
                raise HTTPException(status_code=400,detail=f"retention for {label} must be between 0 and 3650 days")
            values.append(v)
        now=_now().isoformat()
        with core.db() as conn:
            conn.execute(
                "UPDATE retention_settings SET "+",".join(f"{x[0]}=?" for x in POLICIES)+",updated_by=?,updated_at=? WHERE id=1",
                (*values,user["email"],now),
            )
        cleanup(force=True)
        return RedirectResponse("/retention",303)
