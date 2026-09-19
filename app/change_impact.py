"""Measure observable before/after impact around Tikcentral change transactions."""

import html
import json
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations, semantic_config


BEFORE_MINUTES=30
AFTER_MINUTES=30
MIN_AFTER_MINUTES=10


def _now():
    return datetime.now(timezone.utc)


def _avg(values):
    vals=[float(x) for x in values if x is not None]
    return sum(vals)/len(vals) if vals else None


def _pct_true(values):
    vals=[int(x) for x in values if x is not None]
    return (sum(1 for x in vals if x)*100/len(vals)) if vals else None


def _window_metrics(conn,router_id,start,end):
    probes=conn.execute(
        """SELECT target1_avg_ms,target2_avg_ms,target1_loss,target2_loss,classification
           FROM router_wan_probe_history WHERE router_id=? AND captured_at>=? AND captured_at<=?""",
        (router_id,start,end),
    ).fetchall()
    lat=[];loss=[];healthy=[]
    for p in probes:
        lat.extend(v for v in (p["target1_avg_ms"],p["target2_avg_ms"]) if v is not None)
        loss.extend(v for v in (p["target1_loss"],p["target2_loss"]) if v is not None)
        healthy.append(1 if p["classification"]=="healthy" else 0)
    access=conn.execute(
        "SELECT management_ok FROM router_access_history WHERE router_id=? AND checked_at>=? AND checked_at<=?",
        (router_id,start,end),
    ).fetchall()
    telemetry=conn.execute(
        "SELECT cpu_load FROM router_telemetry WHERE router_id=? AND captured_at>=? AND captured_at<=?",
        (router_id,start,end),
    ).fetchall()
    quality=conn.execute(
        """SELECT rx_utilization_percent,tx_utilization_percent,latency_increase_ms,saturation,bufferbloat_status,status
           FROM router_wan_quality WHERE router_id=? AND captured_at>=? AND captured_at<=?""",
        (router_id,start,end),
    ).fetchall()
    return {
        "samples":{
            "wan_probe":len(probes),
            "access":len(access),
            "telemetry":len(telemetry),
            "wan_quality":len(quality),
        },
        "latency_ms":_avg(lat),
        "loss_percent":_avg(loss),
        "healthy_probe_percent":_pct_true(healthy),
        "management_ok_percent":_pct_true([x["management_ok"] for x in access]),
        "cpu_percent":_avg([x["cpu_load"] for x in telemetry]),
        "wan_rx_util_percent":_avg([x["rx_utilization_percent"] for x in quality]),
        "wan_tx_util_percent":_avg([x["tx_utilization_percent"] for x in quality]),
        "wan_latency_increase_ms":_avg([x["latency_increase_ms"] for x in quality]),
        "saturated_percent":_pct_true([x["saturation"] for x in quality]),
    }


def _delta(a,b):
    if a is None or b is None:return None
    return float(b)-float(a)


def assess(transaction_id:int,force=False):
    migrations.migrate()
    with core.db() as conn:
        tx=conn.execute("SELECT * FROM change_transactions WHERE id=?",(transaction_id,)).fetchone()
        existing=conn.execute("SELECT * FROM change_impact_analysis WHERE transaction_id=?",(transaction_id,)).fetchone()
    if not tx or tx["status"] not in {"succeeded","failed"} or not tx["finished_at"]:
        return None
    try:
        created=datetime.fromisoformat(tx["created_at"])
        finished=datetime.fromisoformat(tx["finished_at"])
    except Exception:
        return None
    now=_now()
    if existing and existing["status"]!="pending" and not force:
        return dict(existing)
    before_start=(created-timedelta(minutes=BEFORE_MINUTES)).isoformat()
    before_end=created.isoformat()
    after_start=finished.isoformat()
    after_end=min(now,finished+timedelta(minutes=AFTER_MINUTES)).isoformat()
    after_age=(now-finished).total_seconds()/60

    with core.db() as conn:
        before=_window_metrics(conn,int(tx["router_id"]),before_start,before_end)
        after=_window_metrics(conn,int(tx["router_id"]),after_start,after_end)
        snaps=conn.execute(
            """SELECT source_kind,content,captured_at FROM router_snapshots
               WHERE router_id=? AND source_id=? AND source_kind IN ('transaction_pre','transaction_post')
               ORDER BY id""",(tx["router_id"],transaction_id)
        ).fetchall()
    pre=next((x for x in snaps if x["source_kind"]=="transaction_pre"),None)
    post=next((x for x in reversed(snaps) if x["source_kind"]=="transaction_post"),None)
    semantic=semantic_config.compare(pre["content"],post["content"]) if pre and post else []

    deltas={
        "latency_ms":_delta(before["latency_ms"],after["latency_ms"]),
        "loss_percent":_delta(before["loss_percent"],after["loss_percent"]),
        "healthy_probe_percent":_delta(before["healthy_probe_percent"],after["healthy_probe_percent"]),
        "management_ok_percent":_delta(before["management_ok_percent"],after["management_ok_percent"]),
        "cpu_percent":_delta(before["cpu_percent"],after["cpu_percent"]),
        "wan_rx_util_percent":_delta(before["wan_rx_util_percent"],after["wan_rx_util_percent"]),
        "wan_tx_util_percent":_delta(before["wan_tx_util_percent"],after["wan_tx_util_percent"]),
        "wan_latency_increase_ms":_delta(before["wan_latency_increase_ms"],after["wan_latency_increase_ms"]),
    }
    evidence_count=sum(before["samples"].values())+sum(after["samples"].values())
    if after_age<MIN_AFTER_MINUTES:
        status="pending"
        summary=f"Waiting for at least {MIN_AFTER_MINUTES} minutes of post-change observations"
    elif evidence_count<4:
        status="insufficient_data"
        summary="Not enough before/after telemetry to measure change impact"
    else:
        negative=0;positive=0;notes=[]
        if deltas["management_ok_percent"] is not None:
            if deltas["management_ok_percent"]<=-20:negative+=2;notes.append(f"management availability {deltas['management_ok_percent']:+.1f} points")
            elif deltas["management_ok_percent"]>=20:positive+=2;notes.append(f"management availability {deltas['management_ok_percent']:+.1f} points")
        if deltas["healthy_probe_percent"] is not None:
            if deltas["healthy_probe_percent"]<=-25:negative+=2;notes.append(f"healthy WAN probes {deltas['healthy_probe_percent']:+.1f} points")
            elif deltas["healthy_probe_percent"]>=25:positive+=2;notes.append(f"healthy WAN probes {deltas['healthy_probe_percent']:+.1f} points")
        if deltas["latency_ms"] is not None:
            if deltas["latency_ms"]>=50:negative+=1;notes.append(f"latency {deltas['latency_ms']:+.1f} ms")
            elif deltas["latency_ms"]<=-50:positive+=1;notes.append(f"latency {deltas['latency_ms']:+.1f} ms")
        if deltas["loss_percent"] is not None:
            if deltas["loss_percent"]>=10:negative+=1;notes.append(f"packet loss {deltas['loss_percent']:+.1f} points")
            elif deltas["loss_percent"]<=-10:positive+=1;notes.append(f"packet loss {deltas['loss_percent']:+.1f} points")
        if deltas["cpu_percent"] is not None:
            if deltas["cpu_percent"]>=25:negative+=1;notes.append(f"CPU {deltas['cpu_percent']:+.1f} points")
            elif deltas["cpu_percent"]<=-25:positive+=1;notes.append(f"CPU {deltas['cpu_percent']:+.1f} points")
        if negative>positive and negative>=2:
            status="degraded"
        elif positive>negative and positive>=2:
            status="improved"
        else:
            status="no_material_change"
        summary=f"{status.replace('_',' ')} across measured before/after signals"
        if notes:summary+=" · "+"; ".join(notes)

    impact={
        "transaction":{"id":transaction_id,"kind":tx["kind"],"status":tx["status"],"created_at":tx["created_at"],"finished_at":tx["finished_at"]},
        "before":before,
        "after":after,
        "delta":deltas,
        "semantic_config_changes":semantic[:100],
        "caution":"Temporal correlation only; this does not prove that the change caused the measured difference.",
    }
    with core.db() as conn:
        conn.execute(
            """INSERT INTO change_impact_analysis
               (transaction_id,router_id,assessed_at,window_before_minutes,window_after_minutes,status,impact_json,summary)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(transaction_id) DO UPDATE SET assessed_at=excluded.assessed_at,status=excluded.status,
                 impact_json=excluded.impact_json,summary=excluded.summary""",
            (transaction_id,tx["router_id"],now.isoformat(),BEFORE_MINUTES,AFTER_MINUTES,status,json.dumps(impact),summary),
        )
    return {"status":status,"summary":summary,"impact":impact}


def assess_recent():
    migrations.migrate()
    cutoff=(_now()-timedelta(days=7)).isoformat()
    with core.db() as conn:
        rows=conn.execute(
            """SELECT t.id FROM change_transactions t
               LEFT JOIN change_impact_analysis i ON i.transaction_id=t.id
               WHERE t.finished_at>=? AND t.status IN ('succeeded','failed')
                 AND (i.transaction_id IS NULL OR i.status='pending')
               ORDER BY t.id DESC LIMIT 50""",(cutoff,)
        ).fetchall()
    for x in rows:
        try:assess(int(x["id"]))
        except Exception:pass
    return len(rows)


def register(app,page_func):
    @app.get("/change-impact/{transaction_id}",response_class=HTMLResponse)
    def page(transaction_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        result=assess(transaction_id,force=True)
        with core.db() as conn:
            tx=conn.execute("""SELECT t.*,r.site_name FROM change_transactions t JOIN routers r ON r.id=t.router_id WHERE t.id=?""",(transaction_id,)).fetchone()
            row=conn.execute("SELECT * FROM change_impact_analysis WHERE transaction_id=?",(transaction_id,)).fetchone()
        if not tx:return RedirectResponse("/reliability",303)
        impact=json.loads(row["impact_json"] or "{}") if row else {}
        before=impact.get("before",{});after=impact.get("after",{});delta=impact.get("delta",{})
        metrics=[
            ("WAN latency ms","latency_ms"),("Packet loss %","loss_percent"),("Healthy WAN probes %","healthy_probe_percent"),
            ("Management OK %","management_ok_percent"),("CPU %","cpu_percent"),("WAN RX utilization %","wan_rx_util_percent"),
            ("WAN TX utilization %","wan_tx_util_percent"),("WAN latency increase ms","wan_latency_increase_ms"),
        ]
        def fmt(v):return "—" if v is None else f"{float(v):.1f}"
        rows="".join(f'<tr><td>{html.escape(label)}</td><td>{fmt(before.get(key))}</td><td>{fmt(after.get(key))}</td><td>{fmt(delta.get(key))}</td></tr>' for label,key in metrics)
        semantic=impact.get("semantic_config_changes",[])
        sem_rows="".join(f'<tr><td>{html.escape(x.get("area",""))}</td><td>{html.escape(x.get("action",""))}</td><td>{html.escape(x.get("detail",""))}</td></tr>' for x in semantic) or '<tr><td colspan="3">No attributed semantic snapshot comparison available.</td></tr>'
        body=f'''<div class="panel pad"><h2>Change impact · transaction #{transaction_id}</h2>
<div><strong>{html.escape(row["status"] if row else "unknown")}</strong> · {html.escape(row["summary"] if row else "No analysis")}</div>
<div class="muted">{html.escape(tx["site_name"])} · {html.escape(tx["kind"])} · temporal before/after correlation only; this does not prove causation.</div></div>
<div class="panel"><table><thead><tr><th>Metric</th><th>Before</th><th>After</th><th>Δ after-before</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Attributed semantic configuration changes</h3></div><table><thead><tr><th>Area</th><th>Action</th><th>Detail</th></tr></thead><tbody>{sem_rows}</tbody></table></div>'''
        return page_func("Change Impact",body,user,"changes")
