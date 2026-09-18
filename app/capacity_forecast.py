"""Evidence-based capacity trend projection from retained observability."""

import html
import json
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, resource_monitor


HORIZON_DAYS=30


def _now(): return datetime.now(timezone.utc)


def _slope_per_day(points):
    vals=[]
    for ts,value in points:
        if value is None: continue
        try: vals.append((datetime.fromisoformat(ts).timestamp()/86400.0,float(value)))
        except Exception: continue
    if len(vals)<3:return None
    x0=vals[0][0]
    xs=[x-x0 for x,_ in vals]; ys=[y for _,y in vals]
    mx=sum(xs)/len(xs); my=sum(ys)/len(ys)
    den=sum((x-mx)**2 for x in xs)
    if den<=0:return None
    return sum((x-mx)*(y-my) for x,y in zip(xs,ys))/den


def assess(router_id:int):
    migrations.migrate()
    cutoff=(_now()-timedelta(days=14)).isoformat()
    with core.db() as conn:
        r=conn.execute("SELECT id,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired": return None
        telem=conn.execute(
            "SELECT captured_at,cpu_load,free_memory,total_memory FROM router_telemetry WHERE router_id=? AND captured_at>=? ORDER BY captured_at",
            (router_id,cutoff)).fetchall()
        traffic=conn.execute(
            "SELECT captured_at,rx_bps,tx_bps FROM router_traffic_history WHERE router_id=? AND captured_at>=? AND rx_bps IS NOT NULL ORDER BY captured_at",
            (router_id,cutoff)).fetchall()
        iface=conn.execute(
            "SELECT captured_at,rx_errors,tx_errors,rx_drops,tx_drops FROM router_interface_history WHERE router_id=? AND captured_at>=? ORDER BY captured_at",
            (router_id,cutoff)).fetchall()
        lte=conn.execute(
            "SELECT captured_at,rsrp FROM router_lte_history WHERE router_id=? AND captured_at>=? AND rsrp IS NOT NULL ORDER BY captured_at",
            (router_id,cutoff)).fetchall()
        previous=conn.execute("SELECT status,summary FROM router_capacity_forecast WHERE router_id=?",(router_id,)).fetchone()

    cpu_pts=[(x["captured_at"],x["cpu_load"]) for x in telem]
    mem_pts=[]
    for x in telem:
        free=resource_monitor._memory_bytes(x["free_memory"]); total=resource_monitor._memory_bytes(x["total_memory"])
        mem_pts.append((x["captured_at"],(free*100/total) if free is not None and total else None))
    traffic_pts=[(x["captured_at"],float(x["rx_bps"] or 0)+float(x["tx_bps"] or 0)) for x in traffic]
    err_pts=[(x["captured_at"],sum(int(x[k] or 0) for k in ("rx_errors","tx_errors","rx_drops","tx_drops"))) for x in iface]
    lte_pts=[(x["captured_at"],x["rsrp"]) for x in lte]

    cpu_s=_slope_per_day(cpu_pts); mem_s=_slope_per_day(mem_pts); tr_s=_slope_per_day(traffic_pts)
    err_s=_slope_per_day(err_pts); lte_s=_slope_per_day(lte_pts)
    details={"window_days":14,"horizon_days":HORIZON_DAYS,"signals":[]}
    status="ok"
    warnings=[]

    if len(cpu_pts)>=3 and cpu_s is not None:
        current=float(cpu_pts[-1][1] or 0); projected=current+cpu_s*HORIZON_DAYS
        details["signals"].append({"metric":"cpu","current":current,"trend_per_day":cpu_s,"projected_30d":projected})
        if cpu_s>0 and projected>=80:
            warnings.append(f"CPU trend could reach {projected:.0f}% within {HORIZON_DAYS} days")

    valid_mem=[x for x in mem_pts if x[1] is not None]
    if len(valid_mem)>=3 and mem_s is not None:
        current=valid_mem[-1][1]; projected=current+mem_s*HORIZON_DAYS
        details["signals"].append({"metric":"free_memory_percent","current":current,"trend_per_day":mem_s,"projected_30d":projected})
        if mem_s<0 and projected<=15:
            warnings.append(f"Free-memory trend could fall to {projected:.1f}% within {HORIZON_DAYS} days")

    if len(traffic_pts)>=3 and tr_s is not None:
        current=traffic_pts[-1][1]; projected=max(0,current+tr_s*HORIZON_DAYS)
        details["signals"].append({"metric":"traffic_bps","current":current,"trend_per_day":tr_s,"projected_30d":projected})

    if len(err_pts)>=3 and err_s is not None:
        details["signals"].append({"metric":"interface_error_counter","trend_per_day":err_s})
        if err_s>10:
            warnings.append(f"Interface error/drop counters are increasing by about {err_s:.0f}/day")

    if len(lte_pts)>=3 and lte_s is not None:
        current=float(lte_pts[-1][1]); projected=current+lte_s*HORIZON_DAYS
        details["signals"].append({"metric":"lte_rsrp","current":current,"trend_per_day":lte_s,"projected_30d":projected})
        if lte_s<0 and projected<=-110:
            warnings.append(f"LTE RSRP trend could reach {projected:.0f} dBm within {HORIZON_DAYS} days")

    sample_families=sum(1 for pts in (cpu_pts,valid_mem,traffic_pts,err_pts,lte_pts) if len(pts)>=3)
    if sample_families<2:
        status="insufficient_data"; summary="Not enough retained history for a useful trend projection"
    elif warnings:
        status="warning"; summary="; ".join(warnings)
    else:
        status="ok"; summary="No 30-day capacity threshold crossing detected from current trends"

    assessed=_now().isoformat()
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_capacity_forecast
               (router_id,assessed_at,status,cpu_trend_per_day,memory_free_trend_per_day,traffic_trend_per_day,
                interface_error_trend_per_day,lte_rsrp_trend_per_day,horizon_days,summary,details_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET assessed_at=excluded.assessed_at,status=excluded.status,
                cpu_trend_per_day=excluded.cpu_trend_per_day,memory_free_trend_per_day=excluded.memory_free_trend_per_day,
                traffic_trend_per_day=excluded.traffic_trend_per_day,interface_error_trend_per_day=excluded.interface_error_trend_per_day,
                lte_rsrp_trend_per_day=excluded.lte_rsrp_trend_per_day,horizon_days=excluded.horizon_days,
                summary=excluded.summary,details_json=excluded.details_json""",
            (router_id,assessed,status,cpu_s,mem_s,tr_s,err_s,lte_s,HORIZON_DAYS,summary,json.dumps(details)),
        )
    if previous and previous["status"] != status:
        events.record(router_id,"capacity",f"Capacity trend status: {previous['status']} → {status}",summary,
                      "warning" if status=="warning" else "info")
    return {"status":status,"summary":summary,"details":details}


def register(app,page_func):
    @app.get("/capacity/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try: assess(router_id)
        except Exception: pass
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model FROM routers WHERE id=?",(router_id,)).fetchone()
            f=conn.execute("SELECT * FROM router_capacity_forecast WHERE router_id=?",(router_id,)).fetchone()
        if not r:return RedirectResponse("/operations",303)
        details=json.loads(f["details_json"]) if f and f["details_json"] else {"signals":[]}
        rows="".join(
            f'<tr><td>{html.escape(str(x.get("metric","")))}</td><td>{html.escape(str(round(x.get("current",0),2)) if "current" in x else "—")}</td><td>{html.escape(str(round(x.get("trend_per_day",0),2)))}</td><td>{html.escape(str(round(x.get("projected_30d",0),2)) if "projected_30d" in x else "—")}</td></tr>'
            for x in details.get("signals",[])
        ) or '<tr><td colspan="4">Insufficient trend data.</td></tr>'
        body=f'''<div class="panel pad"><h2>Capacity trends · {html.escape(r["site_name"])}</h2>
<div><strong>{html.escape(f["status"] if f else "not assessed")}</strong> · {html.escape(f["summary"] if f else "")}</div>
<div class="muted">Trend projection only; this is not a failure-date prediction. Current horizon: {HORIZON_DAYS} days.</div></div>
<div class="panel"><table><thead><tr><th>Metric</th><th>Current</th><th>Trend/day</th><th>Projected 30d</th></tr></thead><tbody>{rows}</tbody></table></div>'''
        return page_func("Capacity Trends",body,user,"operations")
