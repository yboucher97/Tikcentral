"""Router timeline, pre-failure correlation, and incident builder."""

import html
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import ai_analysis, main as core, migrations


def _router(router_id):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _window(router_id: int, start: str, end: str):
    items = []
    with core.db() as conn:
        for r in conn.execute(
            "SELECT event_at,severity,category,summary,details FROM router_events WHERE router_id=? AND event_at>=? AND event_at<=?",
            (router_id,start,end),
        ).fetchall():
            items.append((r["event_at"], r["severity"], r["category"], r["summary"], r["details"] or ""))
        for r in conn.execute(
            "SELECT created_at,status,kind,actor,target,error_code,error_message FROM router_jobs WHERE router_id=? AND created_at>=? AND created_at<=?",
            (router_id,start,end),
        ).fetchall():
            items.append((r["created_at"], "info" if r["status"]=="succeeded" else "warning", "job",
                          f'{r["kind"]} · {r["status"]}', f'actor={r["actor"]} target={r["target"] or "-"} {r["error_code"] or ""} {r["error_message"] or ""}'))
        for r in conn.execute(
            "SELECT checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok FROM router_access_history WHERE router_id=? AND checked_at>=? AND checked_at<=? ORDER BY id",
            (router_id,start,end),
        ).fetchall():
            if not r["management_ok"]:
                detail = f'WG={r["wg_online"]} SSH={r["ssh_open"]} WinBox={r["winbox_open"]} API={r["api_open"]}'
                items.append((r["checked_at"], "warning", "guardian", "Management access degraded", detail))
        for r in conn.execute(
            "SELECT captured_at,active_default_routes,dhcp_bound,pppoe_running,internet_ping,dns_ok FROM router_wan_history WHERE router_id=? AND captured_at>=? AND captured_at<=?",
            (router_id,start,end),
        ).fetchall():
            if not r["active_default_routes"] or not r["internet_ping"] or r["dns_ok"] != 1:
                items.append((r["captured_at"], "warning", "wan", "WAN health issue",
                              f'routes={r["active_default_routes"]} dhcp={r["dhcp_bound"]} pppoe={r["pppoe_running"]} ping={r["internet_ping"]} dns={r["dns_ok"]}'))
        for r in conn.execute(
            "SELECT captured_at,source_kind,source_actor FROM router_snapshots WHERE router_id=? AND captured_at>=? AND captured_at<=?",
            (router_id,start,end),
        ).fetchall():
            items.append((r["captured_at"], "info", "config", "Configuration snapshot captured",
                          f'source={r["source_kind"] or "-"} actor={r["source_actor"] or "-"}'))
        for r in conn.execute(
            "SELECT first_seen_at,last_seen_at,metric,last_value,active FROM router_resource_alerts WHERE router_id=? AND last_seen_at>=? AND first_seen_at<=?",
            (router_id,start,end),
        ).fetchall():
            items.append((r["last_seen_at"], "warning", "resource", f'Resource anomaly: {r["metric"]}', r["last_value"] or ""))
        for r in conn.execute(
            "SELECT first_seen_at,public_ip,isp,organization,asn FROM router_public_ip_history WHERE router_id=? AND first_seen_at>=? AND first_seen_at<=?",
            (router_id,start,end),
        ).fetchall():
            items.append((r["first_seen_at"], "info", "public-ip", f'Public IP {r["public_ip"]}',
                          f'ISP={r["isp"] or "-"} ASN={r["asn"] or "-"} Org={r["organization"] or "-"}'))
        for r in conn.execute(
            "SELECT created_at,finished_at,status,kind,actor,error_code,error_detail FROM change_transactions WHERE router_id=? AND created_at>=? AND created_at<=?",
            (router_id,start,end),
        ).fetchall():
            items.append((r["created_at"], "info" if r["status"]=="succeeded" else "warning", "change",
                          f'{r["kind"]} · {r["status"]}', f'actor={r["actor"] or "-"} {r["error_code"] or ""} {r["error_detail"] or ""}'))
        for r in conn.execute(
            "SELECT created_at,finished_at,status,requested_by,focus_start,focus_end,focus_note FROM router_ai_analyses WHERE router_id=? AND created_at>=? AND created_at<=?",
            (router_id,start,end),
        ).fetchall():
            items.append((r["created_at"], "info", "ai", f'AI analysis · {r["status"]}',
                          f'by={r["requested_by"] or "-"} focus={r["focus_start"] or "-"}→{r["focus_end"] or "-"} {r["focus_note"] or ""}'))
        lte_rows = conn.execute(
            """SELECT captured_at,interface,operator,access_technology,band,ca_band,cell_id,enb_id,
                      phy_cell_id,rsrp,rsrq,sinr,rssi
               FROM router_lte_history WHERE router_id=? AND captured_at>=? AND captured_at<=?
               ORDER BY id""",
            (router_id,start,end),
        ).fetchall()
        previous_lte = None
        for r in lte_rows:
            changed = previous_lte is None or any(
                r[k] != previous_lte[k] for k in ("band","ca_band","cell_id","operator","access_technology")
            )
            weak = (r["rsrp"] is not None and float(r["rsrp"]) <= -110) or (r["sinr"] is not None and float(r["sinr"]) < 0)
            if changed or weak:
                sev = "warning" if weak else "info"
                summary = "LTE signal weak" if weak else "LTE serving cell / band changed"
                detail = f'if={r["interface"]} operator={r["operator"] or "-"} access={r["access_technology"] or "-"} band={r["band"] or "-"} CA={r["ca_band"] or "-"} cell={r["cell_id"] or "-"} RSRP={r["rsrp"]} RSRQ={r["rsrq"]} SINR={r["sinr"]}'
                items.append((r["captured_at"], sev, "lte", summary, detail))
            previous_lte = r
        interface_rows = conn.execute(
            """SELECT * FROM router_interface_history WHERE router_id=? AND captured_at>=? AND captured_at<=?
               ORDER BY name,captured_at,id""",
            (router_id,start,end),
        ).fetchall()
        prev_by_name = {}
        for r in interface_rows:
            p = prev_by_name.get(r["name"])
            changed_state = p is not None and r["running"] != p["running"]
            err_delta = 0
            for key in ("rx_errors","tx_errors","rx_drops","tx_drops"):
                if p is not None and r[key] is not None and p[key] is not None:
                    err_delta += max(0,int(r[key])-int(p[key]))
            link_delta = 0
            if p is not None and r["link_downs"] is not None and p["link_downs"] is not None:
                link_delta = max(0,int(r["link_downs"])-int(p["link_downs"]))
            if changed_state or err_delta or link_delta:
                sev = "warning" if (r["running"]==0 or err_delta or link_delta) else "info"
                summary = f'Interface {r["name"]} {"up" if r["running"] else "down"}' if changed_state else f'Interface {r["name"]} counters changed'
                detail = f'errors/drops Δ={err_delta}; link-downs Δ={link_delta}; rate={r["rate"] or "-"}; duplex={r["full_duplex"]}; PoE={r["poe_out"] or "-"}'
                items.append((r["captured_at"],sev,"interface",summary,detail))
            prev_by_name[r["name"]] = r
        outage = conn.execute("SELECT * FROM router_outage_assessment WHERE router_id=?", (router_id,)).fetchone()
        if outage and outage["classification"] != "healthy":
            items.append((outage["assessed_at"],"warning","outage-domain",outage["summary"],
                          f'classification={outage["classification"]}; confidence={outage["confidence"]}; {outage["evidence"]}'))
        like_path = f"%/{router_id}%"
        for r in conn.execute(
            "SELECT event_at,actor,action,path,status_code,details FROM operator_audit_log WHERE event_at>=? AND event_at<=? AND path LIKE ?",
            (start,end,like_path),
        ).fetchall():
            items.append((r["event_at"], "info", "operator", r["action"],
                          f'actor={r["actor"] or "-"} path={r["path"]} status={r["status_code"] or "-"} {r["details"] or ""}'))
    return sorted(items, key=lambda x:x[0], reverse=True)


def _render(items):
    if not items:
        return '<div class="panel pad muted">No evidence in this window.</div>'
    rows = "".join(
        f'<tr><td>{html.escape(ts)}</td><td>{html.escape(sev)}</td><td>{html.escape(cat)}</td><td><strong>{html.escape(summary)}</strong><div class="muted">{html.escape(detail)}</div></td></tr>'
        for ts,sev,cat,summary,detail in items
    )
    return f'<div class="panel"><table><thead><tr><th>Time</th><th>Level</th><th>Source</th><th>Event</th></tr></thead><tbody>{rows}</tbody></table></div>'


def register(app, page_func):
    migrations.migrate()

    @app.get("/timeline/{router_id}", response_class=HTMLResponse)
    def timeline(router_id:int, request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        router=_router(router_id)
        if not router: return RedirectResponse("/routers",303)
        hours=int(request.query_params.get("hours","24") or 24)
        hours=hours if hours in {6,24,72,168,720} else 24
        end=datetime.now(timezone.utc)
        start=end-timedelta(hours=hours)
        links=" ".join(f'<a href="/timeline/{router_id}?hours={h}"><button>{label}</button></a>' for h,label in [(6,"6h"),(24,"24h"),(72,"3d"),(168,"7d"),(720,"30d")])
        body=f'<div class="panel pad"><h2>Router timeline · {html.escape(router["site_name"])}</h2><div class="muted">Unified Guardian, WAN/ISP classification, interface health, LTE, reboot, resource, jobs, config and public-IP/ISP history.</div><div class="inline" style="margin-top:12px">{links}<a href="/timeline/{router_id}/before"><button>What changed before failure?</button></a><a href="/incidents/{router_id}"><button class="primary">Build incident</button></a></div></div>'+_render(_window(router_id,start.isoformat(),end.isoformat()))
        return page_func("Router Timeline",body,user,"operations")

    @app.get("/timeline/{router_id}/before", response_class=HTMLResponse)
    def before_failure(router_id:int, request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        router=_router(router_id)
        if not router: return RedirectResponse("/routers",303)
        at=request.query_params.get("at","")
        with core.db() as conn:
            if not at:
                row=conn.execute(
                    """SELECT event_at,summary FROM router_events WHERE router_id=? AND
                       (severity IN ('warning','critical') OR category IN ('reboot','access'))
                       ORDER BY id DESC LIMIT 1""",(router_id,)
                ).fetchone()
                at=row["event_at"] if row else datetime.now(timezone.utc).isoformat()
                failure=row["summary"] if row else "Current time"
            else: failure="Selected failure time"
        try: end=datetime.fromisoformat(at)
        except Exception: end=datetime.now(timezone.utc)
        start=end-timedelta(hours=6)
        body=f'<div class="panel pad"><h2>What changed before failure? · {html.escape(router["site_name"])}</h2><div><strong>{html.escape(failure)}</strong> · {html.escape(end.isoformat())}</div><div class="muted">Showing the six hours immediately before the selected failure/degradation point.</div><div style="margin-top:12px"><a href="/timeline/{router_id}"><button>Back to timeline</button></a><a href="/incidents/{router_id}?start={html.escape(start.isoformat())}&end={html.escape(end.isoformat())}"><button class="primary">Open as incident</button></a></div></div>'+_render(_window(router_id,start.isoformat(),end.isoformat()))
        return page_func("Before Failure",body,user,"operations")

    @app.get("/incidents/{router_id}", response_class=HTMLResponse)
    def incident(router_id:int, request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        router=_router(router_id)
        if not router: return RedirectResponse("/routers",303)
        end=request.query_params.get("end") or datetime.now(timezone.utc).isoformat()
        start=request.query_params.get("start") or (datetime.now(timezone.utc)-timedelta(hours=2)).isoformat()
        csrf=core.csrf_token(request)
        body=f'''<div class="panel pad"><h2>Incident builder · {html.escape(router["site_name"])}</h2>
<form method="get" action="/incidents/{router_id}" class="inline"><input name="start" value="{html.escape(start)}" style="min-width:290px"><input name="end" value="{html.escape(end)}" style="min-width:290px"><button>Build window</button></form>
<form method="post" action="/incidents/{router_id}/analyze" class="inline" style="margin-top:12px"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="start" value="{html.escape(start)}"><input type="hidden" name="end" value="{html.escape(end)}"><input name="note" maxlength="500" placeholder="Incident symptom / note"><button class="primary">Analyze this incident with AI</button></form></div>'''+_render(_window(router_id,start,end))
        return page_func("Incident Builder",body,user,"operations")

    @app.post("/incidents/{router_id}/analyze")
    async def incident_ai(router_id:int, request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        actor=user["email"]
        ai_analysis.queue_analysis(router_id,actor,data.get("start",""),data.get("end",""),data.get("note","")[:500])
        return RedirectResponse(f"/ai/{router_id}",303)
