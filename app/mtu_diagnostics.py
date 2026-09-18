"""Read-only path MTU diagnostics using IPv4 DF pings."""

import html
import json
import re
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, router_exec


STANDARD_TARGET="1.1.1.1"
PAYLOADS=(1472,1464,1452,1440,1420,1400,1360,1300)
IP_ICMP_OVERHEAD=28
AUTO_INTERVAL_HOURS=20


def _now():return datetime.now(timezone.utc)


def _parse_ping(text):
    low=(text or "").lower()
    m=re.search(r"packet-loss\s*[:=]\s*([0-9.]+)%",low)
    if m:return float(m.group(1))<100
    return ("time=" in low or "ttl=" in low) and "timeout" not in low


def _ping(ip,target,size):
    cmd=f"/ping address={target} count=2 interval=300ms size={int(size)} do-not-fragment=yes"
    try:
        out=router_exec.read(ip,cmd,timeout=15,label=f"MTU probe {target} size {size}")
        return _parse_ping(out),router_exec.sanitize(out,500)
    except Exception as exc:
        return False,str(exc)[:300]


def collect(router_id:int,force=False,target=STANDARD_TARGET):
    migrations.migrate(); now=_now()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        last=conn.execute("SELECT * FROM router_mtu_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired":return None
    if last and not force:
        try:
            if (now-datetime.fromisoformat(last["captured_at"])).total_seconds()<AUTO_INTERVAL_HOURS*3600:
                return dict(last)
        except Exception:pass

    results=[]; largest=None
    for size in PAYLOADS:
        ok,evidence=_ping(r["vpn_ip"],target,size)
        results.append({"payload":size,"estimated_mtu":size+IP_ICMP_OVERHEAD,"ok":bool(ok),"evidence":evidence})
        if ok and largest is None:
            largest=size
            break

    if largest is None:
        status="warning"; mtu=None; mss=None
        summary=f"No DF probe succeeded down to {PAYLOADS[-1]+IP_ICMP_OVERHEAD} byte estimated path MTU"
    else:
        mtu=largest+IP_ICMP_OVERHEAD
        mss=max(536,mtu-40)
        if mtu>=1500:
            status="ok"; summary=f"Path MTU supports 1500 bytes toward {target}"
        elif mtu>=1492:
            status="ok"; summary=f"Estimated path MTU {mtu} bytes; consistent with PPPoE-sized paths"
        elif mtu>=1450:
            status="warning"; summary=f"Reduced path MTU detected: approximately {mtu} bytes toward {target}"
        else:
            status="warning"; summary=f"Significantly reduced path MTU detected: approximately {mtu} bytes toward {target}"

    with core.db() as conn:
        prev=conn.execute("SELECT status,estimated_path_mtu FROM router_mtu_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
        conn.execute(
            """INSERT INTO router_mtu_history
               (router_id,captured_at,target,largest_payload,estimated_path_mtu,recommended_tcp_mss,status,summary,results_json)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (router_id,now.isoformat(),target,largest,mtu,mss,status,summary,json.dumps(results)),
        )
        conn.execute(
            """DELETE FROM router_mtu_history WHERE router_id=? AND id NOT IN
               (SELECT id FROM router_mtu_history WHERE router_id=? ORDER BY id DESC LIMIT 365)""",(router_id,router_id))
    changed=prev and (prev["status"]!=status or prev["estimated_path_mtu"]!=mtu)
    if changed:
        events.record(router_id,"mtu",f"Path MTU changed: {prev['estimated_path_mtu'] or '?'} → {mtu or '?'}",summary,
                      "warning" if status=="warning" else "info")
    return {"status":status,"summary":summary,"estimated_path_mtu":mtu,"recommended_tcp_mss":mss}


def register(app,page_func):
    @app.get("/mtu/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model FROM routers WHERE id=?",(router_id,)).fetchone()
            latest=conn.execute("SELECT * FROM router_mtu_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
        if not r:return RedirectResponse("/operations",303)
        csrf=core.csrf_token(request)
        results=json.loads(latest["results_json"]) if latest and latest["results_json"] else []
        rows="".join(
            f'<tr><td>{x["payload"]}</td><td>{x["estimated_mtu"]}</td><td>{"PASS" if x["ok"] else "FAIL"}</td></tr>'
            for x in results
        ) or '<tr><td colspan="3">No MTU diagnostic has run yet.</td></tr>'
        body=f'''<div class="panel pad"><h2>MTU / MSS diagnostics · {html.escape(r["site_name"])}</h2>
<div><strong>{html.escape(latest["status"] if latest else "not tested")}</strong> · {html.escape(latest["summary"] if latest else "Run the diagnostic to establish path MTU.")}</div>
<div class="muted">Read-only DF ping test toward {STANDARD_TARGET}. Tikcentral does not change interface MTU or firewall MSS-clamp rules. The TCP MSS value is informational only.</div>
<form method="post" action="/mtu/{router_id}/run" style="margin-top:12px"><input type="hidden" name="csrf" value="{csrf}"><button class="primary">Run MTU diagnostic now</button></form></div>
<div class="cards">
<div class="card"><h3>Estimated path MTU</h3><div class="value">{latest["estimated_path_mtu"] if latest and latest["estimated_path_mtu"] else "—"}</div></div>
<div class="card"><h3>Informational TCP MSS</h3><div class="value">{latest["recommended_tcp_mss"] if latest and latest["recommended_tcp_mss"] else "—"}</div></div>
<div class="card"><h3>Target</h3><div>{html.escape(latest["target"] if latest else STANDARD_TARGET)}</div></div>
</div>
<div class="panel"><table><thead><tr><th>ICMP payload</th><th>Estimated IPv4 MTU</th><th>DF result</th></tr></thead><tbody>{rows}</tbody></table></div>'''
        return page_func("MTU Diagnostics",body,user,"operations")

    @app.post("/mtu/{router_id}/run")
    async def run(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        collect(router_id,force=True)
        return RedirectResponse(f"/mtu/{router_id}",303)
