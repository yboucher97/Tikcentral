"""Conservative outage-domain classification from Guardian, WAN and ISP evidence."""

from datetime import datetime, timedelta, timezone

from app import events, main as core, migrations


def _now():
    return datetime.now(timezone.utc).isoformat()


def _recent(row_time: str, minutes: int = 20):
    if not row_time:
        return False
    try:
        return datetime.fromisoformat(row_time) >= datetime.now(timezone.utc)-timedelta(minutes=minutes)
    except Exception:
        return False


def assess_all():
    migrations.migrate()
    with core.db() as conn:
        routers=conn.execute(
            """SELECT r.id,r.site_name,a.checked_at,a.wg_online,a.management_ok,a.last_error
               FROM routers r LEFT JOIN router_access_state a ON a.router_id=r.id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired' ORDER BY r.id"""
        ).fetchall()
        evidence={}
        for r in routers:
            rid=int(r["id"])
            wan=conn.execute(
                "SELECT * FROM router_wan_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(rid,)
            ).fetchone()
            ip=conn.execute(
                "SELECT * FROM router_public_ip_history WHERE router_id=? ORDER BY last_seen_at DESC,id DESC LIMIT 1",(rid,)
            ).fetchone()
            probe=conn.execute(
                "SELECT * FROM router_wan_probe_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(rid,)
            ).fetchone()
            evidence[rid]=(wan,ip,probe)

    degraded=[r for r in routers if r["management_ok"] is not None and not r["management_ok"] and _recent(r["checked_at"],30)]
    degraded_ids={int(r["id"]) for r in degraded}
    same_isp_counts={}
    for r in degraded:
        _,ip,_=evidence[int(r["id"])]
        isp=(ip["isp"] if ip else "") or ""
        if isp:
            same_isp_counts[isp]=same_isp_counts.get(isp,0)+1

    distinct_isps={((evidence[int(r["id"])][1]["isp"] if evidence[int(r["id"])][1] else "") or "") for r in degraded}
    distinct_isps.discard("")
    multi_isps=len(distinct_isps)>=2 and len(degraded)>=2

    results=[]
    for r in routers:
        rid=int(r["id"])
        wan,ip,probe=evidence[rid]
        isp=(ip["isp"] if ip else "") or ""
        previous=None
        with core.db() as conn:
            previous=conn.execute("SELECT classification FROM router_outage_assessment WHERE router_id=?",(rid,)).fetchone()

        if r["management_ok"] is None or not r["checked_at"]:
            classification="unknown"
            confidence="low"
            summary="Outage domain not yet assessed"
            detail="No recent Guardian management sample is available yet."
        elif rid not in degraded_ids:
            classification="healthy"
            confidence="high"
            summary="No active management outage detected"
            detail="Guardian management path is healthy or no recent degradation is active."
        else:
            wan_bad=bool(wan and _recent(wan["captured_at"],60) and (
                (wan["active_default_routes"] or 0)==0 or
                wan["internet_ping"] in {0,None} or
                wan["dns_ok"]==0
            ))
            probe_recent=bool(probe and _recent(probe["captured_at"],30))
            probe_class=(probe["classification"] if probe_recent else "") or ""
            probe_site_bad=probe_class in {"site_or_upstream","upstream"}
            probe_dns_bad=probe_class=="dns"
            same_isp=same_isp_counts.get(isp,0)>=2 if isp else False
            if multi_isps:
                classification="possible_control_plane"
                confidence="medium"
                summary="Possible Tikcentral/VPS or shared management-path outage"
                detail=f"{len(degraded)} recently degraded routers span multiple detected ISPs."
            elif same_isp:
                classification="likely_isp"
                confidence="medium"
                summary=f"Likely shared ISP issue: {isp}"
                detail=f"{same_isp_counts.get(isp,0)} recently degraded routers share ISP {isp}."
            elif probe_site_bad:
                classification="site_wan"
                confidence="high"
                summary="Likely site WAN / Internet failure"
                detail=f'Multi-target WAN probe={probe_class}; {probe["summary"]}; ISP={isp or "-"}'
            elif probe_dns_bad:
                classification="site_wan"
                confidence="high"
                summary="Likely site DNS failure"
                detail=f'Multi-target WAN probe confirmed IP reachability while DNS failed; ISP={isp or "-"}'
            elif wan_bad:
                classification="site_wan"
                confidence="medium"
                summary="Likely site WAN / Internet failure"
                detail=f'Latest WAN sample: routes={wan["active_default_routes"]}; ping={wan["internet_ping"]}; dns={wan["dns_ok"]}; ISP={isp or "-"}'
            elif r["wg_online"]==0:
                classification="management_path"
                confidence="low"
                summary="Management tunnel lost; WAN cause not confirmed"
                detail=f'Guardian lost WireGuard while latest WAN evidence did not clearly confirm Internet failure. ISP={isp or "-"}'
            else:
                classification="router_management"
                confidence="medium"
                summary="Router management services degraded"
                detail=f'WireGuard remains visible but one or more management services are unavailable. {r["last_error"] or ""}'
        assessed=_now()
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_outage_assessment(router_id,assessed_at,classification,confidence,summary,evidence)
                   VALUES(?,?,?,?,?,?)
                   ON CONFLICT(router_id) DO UPDATE SET assessed_at=excluded.assessed_at,
                     classification=excluded.classification,confidence=excluded.confidence,
                     summary=excluded.summary,evidence=excluded.evidence""",
                (rid,assessed,classification,confidence,summary,detail),
            )
        if not previous or previous["classification"] != classification:
            if classification not in {"healthy","unknown"}:
                events.record(rid,"outage_classification",summary,detail,"warning")
            elif previous and previous["classification"] not in {"healthy","unknown"} and classification == "healthy":
                events.record(rid,"outage_classification","Outage-domain assessment cleared",
                              f'previous={previous["classification"]}; Guardian management path recovered',"info")
        results.append((rid,classification))
    return results
