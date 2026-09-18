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
            "SELECT checked_at,management_ok,last_error FROM router_access_history WHERE router_id=? AND checked_at>=? AND checked_at<=? ORDER BY id",
            (router_id,start,end),
        ).fetchall():
            if not r["management_ok"]:
                items.append((r["checked_at"], "warning", "guardian", "Management access degraded", r["last_error"] or ""))
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
        body=f'<div class="panel pad"><h2>Router timeline · {html.escape(router["site_name"])}</h2><div class="muted">Unified Guardian, WAN, reboot, resource, jobs, config and public-IP/ISP history.</div><div class="inline" style="margin-top:12px">{links}<a href="/timeline/{router_id}/before"><button>What changed before failure?</button></a><a href="/incidents/{router_id}"><button class="primary">Build incident</button></a></div></div>'+_render(_window(router_id,start.isoformat(),end.isoformat()))
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
