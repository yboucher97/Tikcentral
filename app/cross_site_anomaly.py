"""Cross-site anomaly correlation for WAN/DNS/gateway failures."""

import html
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations


WINDOW_MINUTES=20
MIN_PROVIDER_ROUTERS=2
MIN_FLEET_ROUTERS=3


def _now():
    return datetime.now(timezone.utc)


def _provider(conn,router_id):
    row=conn.execute(
        "SELECT isp,organization,asn FROM router_public_ip_history WHERE router_id=? ORDER BY last_seen_at DESC,id DESC LIMIT 1",
        (router_id,),
    ).fetchone()
    if not row:
        return ""
    return (row["isp"] or row["organization"] or row["asn"] or "").strip()


def scan():
    migrations.migrate()
    now=_now()
    cutoff=(now-timedelta(minutes=WINDOW_MINUTES)).isoformat()
    with core.db() as conn:
        routers=conn.execute(
            """SELECT r.id,r.site_name,
               (SELECT classification FROM router_wan_probe_history w WHERE w.router_id=r.id ORDER BY w.id DESC LIMIT 1) classification,
               (SELECT captured_at FROM router_wan_probe_history w WHERE w.router_id=r.id ORDER BY w.id DESC LIMIT 1) probe_at,
               (SELECT status FROM router_wan_quality q WHERE q.router_id=r.id ORDER BY q.id DESC LIMIT 1) quality_status,
               (SELECT captured_at FROM router_wan_quality q WHERE q.router_id=r.id ORDER BY q.id DESC LIMIT 1) quality_at,
               (SELECT reachable FROM router_isp_gateway_history g WHERE g.router_id=r.id ORDER BY g.id DESC LIMIT 1) gateway_reachable,
               (SELECT captured_at FROM router_isp_gateway_history g WHERE g.router_id=r.id ORDER BY g.id DESC LIMIT 1) gateway_at
               FROM routers r
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance')"""
        ).fetchall()
        bad=[]
        for r in routers:
            recent_probe=bool(r["probe_at"] and r["probe_at"]>=cutoff)
            recent_quality=bool(r["quality_at"] and r["quality_at"]>=cutoff)
            recent_gateway=bool(r["gateway_at"] and r["gateway_at"]>=cutoff)
            probe_bad=recent_probe and r["classification"] in {"site_or_upstream","upstream","dns","partial","degraded_quality"}
            quality_bad=recent_quality and r["quality_status"] in {"warning","saturated"}
            gateway_bad=recent_gateway and r["gateway_reachable"]==0
            if probe_bad or quality_bad or gateway_bad:
                bad.append({
                    "id":int(r["id"]),
                    "site_name":r["site_name"],
                    "provider":_provider(conn,int(r["id"])) or "Unknown provider",
                    "probe":r["classification"] or "",
                    "quality":r["quality_status"] or "",
                    "gateway_bad":bool(gateway_bad),
                })

        grouped=defaultdict(list)
        for x in bad:
            grouped[x["provider"]].append(x)

        candidates={}
        for provider,items in grouped.items():
            if len(items)>=MIN_PROVIDER_ROUTERS:
                key=f"provider:{provider.lower()}:network"
                candidates[key]={
                    "provider":provider,
                    "kind":"provider-network",
                    "items":items,
                    "summary":f"{len(items)} sites on {provider} show correlated network degradation within {WINDOW_MINUTES} minutes",
                }
        providers={x["provider"] for x in bad}
        if len(bad)>=MIN_FLEET_ROUTERS and len(providers)>=2:
            key="fleet:multi-provider:network"
            candidates[key]={
                "provider":"Multiple providers",
                "kind":"multi-provider",
                "items":bad,
                "summary":f"{len(bad)} sites across {len(providers)} providers show concurrent degradation within {WINDOW_MINUTES} minutes",
            }

        active=conn.execute("SELECT * FROM fleet_cross_site_anomalies WHERE status='active'").fetchall()
        active_by_key={x["anomaly_key"]:x for x in active}
        for key,data in candidates.items():
            ids=sorted({x["id"] for x in data["items"]})
            if key in active_by_key:
                conn.execute(
                    """UPDATE fleet_cross_site_anomalies SET detected_at=?,provider=?,kind=?,router_count=?,router_ids_json=?,summary=?
                       WHERE id=?""",
                    (now.isoformat(),data["provider"],data["kind"],len(ids),json.dumps(ids),data["summary"],active_by_key[key]["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO fleet_cross_site_anomalies
                       (detected_at,anomaly_key,provider,kind,router_count,router_ids_json,status,summary)
                       VALUES(?,?,?,?,?,?,'active',?)""",
                    (now.isoformat(),key,data["provider"],data["kind"],len(ids),json.dumps(ids),data["summary"]),
                )
                events.record(None,"cross-site",data["summary"],json.dumps(data["items"])[:3500],"warning")

        for key,row in active_by_key.items():
            if key not in candidates:
                conn.execute(
                    "DELETE FROM fleet_cross_site_anomalies WHERE anomaly_key=? AND status='resolved'",
                    (key,),
                )
                conn.execute(
                    "UPDATE fleet_cross_site_anomalies SET status='resolved',resolved_at=? WHERE id=?",
                    (now.isoformat(),row["id"]),
                )
                events.record(None,"cross-site",f"Cross-site anomaly resolved: {row['summary']}","","info")
    return len(candidates)


def register(app,page_func):
    @app.get("/cross-site-anomalies",response_class=HTMLResponse)
    def page(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        scan()
        with core.db() as conn:
            rows=conn.execute("SELECT * FROM fleet_cross_site_anomalies ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,id DESC LIMIT 200").fetchall()
            names={int(r["id"]):r["site_name"] for r in conn.execute("SELECT id,site_name FROM routers").fetchall()}
        rendered=[]
        for x in rows:
            try:ids=json.loads(x["router_ids_json"] or "[]")
            except Exception:ids=[]
            sites=" · ".join(f'<a href="/operations/{rid}">{html.escape(names.get(int(rid),str(rid)))}</a>' for rid in ids)
            rendered.append(
                f'<tr><td>{html.escape(x["status"])}</td><td>{html.escape(x["kind"])}</td><td>{html.escape(x["provider"] or "-")}</td>'
                f'<td>{x["router_count"]}</td><td>{html.escape(x["summary"])}</td><td>{sites}</td><td>{html.escape(x["detected_at"])}</td></tr>'
            )
        body=f'''<div class="panel pad"><h2>Cross-site anomaly detection</h2>
<div class="muted">Correlates recent WAN probe, WAN quality and ISP-gateway degradation. Provider anomalies require at least {MIN_PROVIDER_ROUTERS} affected sites; multi-provider anomalies require at least {MIN_FLEET_ROUTERS} affected sites across 2+ providers.</div></div>
<div class="panel"><table><thead><tr><th>Status</th><th>Type</th><th>Provider</th><th>Sites</th><th>Summary</th><th>Affected</th><th>Detected</th></tr></thead><tbody>{''.join(rendered) or '<tr><td colspan="7">No correlated anomalies recorded.</td></tr>'}</tbody></table></div>'''
        return page_func("Cross-Site Anomalies",body,user,"cross-site-anomalies")
