"""Router clock, timezone and NTP health monitoring."""

import html
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, router_exec, settings


COMMAND=':put "TC_CLOCK"; /system clock print; :put "TC_NTP"; /system ntp client print; :put "TC_NTP_SERVERS"; /system ntp client servers print without-paging'
DRIFT_WARN_SECONDS=120
DRIFT_CRITICAL_SECONDS=600


def _now(): return datetime.now(timezone.utc)


def _kv(text):
    out={}
    for line in (text or "").splitlines():
        if ":" not in line: continue
        k,v=line.split(":",1)
        out[k.strip().lower().replace(" ","-")]=v.strip()
    return out


def _sections(text):
    parts={"clock":"","ntp":"","servers":""}
    current=None
    for line in (text or "").splitlines():
        marker=line.strip()
        if marker=="TC_CLOCK": current="clock"; continue
        if marker=="TC_NTP": current="ntp"; continue
        if marker=="TC_NTP_SERVERS": current="servers"; continue
        if current: parts[current]+=line+"\n"
    return parts


def _parse_router_time(clock):
    date=(clock.get("date") or "").strip()
    tm=(clock.get("time") or "").strip()
    tzname=(clock.get("time-zone-name") or clock.get("timezone") or "").strip()
    if not date or not tm:return None
    parsed=None
    for fmt in ("%Y-%m-%d %H:%M:%S","%b/%d/%Y %H:%M:%S","%b/%d/%y %H:%M:%S","%m/%d/%Y %H:%M:%S"):
        try:
            parsed=datetime.strptime(f"{date} {tm}",fmt)
            break
        except Exception:
            pass
    if parsed is None:return None
    try:
        zone=ZoneInfo(tzname) if tzname else ZoneInfo(settings.TIMEZONE)
    except Exception:
        zone=ZoneInfo(settings.TIMEZONE)
    return parsed.replace(tzinfo=zone).astimezone(timezone.utc)


def collect(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired":return None

    checked=_now()
    try:
        raw=router_exec.read(r["vpn_ip"],COMMAND,timeout=35,label="Time/NTP health")
        sections=_sections(raw)
        clock=_kv(sections["clock"])
        ntp=_kv(sections["ntp"])
        servers_text=router_exec.sanitize(sections["servers"],2000).strip()
        router_dt=_parse_router_time(clock)
        drift=abs((checked-router_dt).total_seconds()) if router_dt else None
        tzname=(clock.get("time-zone-name") or clock.get("timezone") or "").strip()
        offset=(clock.get("gmt-offset") or clock.get("utc-offset") or "").strip()
        enabled_text=(ntp.get("enabled") or "").lower()
        enabled=1 if enabled_text in {"yes","true"} else (0 if enabled_text in {"no","false"} else None)
        ntp_status=(ntp.get("status") or ntp.get("state") or "").strip()
        server_summary=(ntp.get("servers") or ntp.get("server") or "").strip()
        if not server_summary and servers_text:
            server_summary="configured"

        findings=[]
        if drift is None:
            findings.append(("warning","Router clock could not be parsed"))
        elif drift>DRIFT_CRITICAL_SECONDS:
            findings.append(("critical",f"Router clock drift is {drift:.0f} seconds"))
        elif drift>DRIFT_WARN_SECONDS:
            findings.append(("warning",f"Router clock drift is {drift:.0f} seconds"))

        if enabled==0:
            findings.append(("warning","NTP client is disabled"))
        elif enabled==1 and ntp_status and "synchron" not in ntp_status.lower():
            findings.append(("warning",f"NTP is enabled but status is {ntp_status}"))

        if tzname and tzname != settings.TIMEZONE:
            findings.append(("warning",f"Router timezone is {tzname}; Tikcentral standard is {settings.TIMEZONE}"))

        if any(x[0]=="critical" for x in findings):status="critical"
        elif findings:status="warning"
        elif drift is not None and enabled!=0:status="ok"
        else:status="unknown"
        summary="; ".join(x[1] for x in findings) if findings else "Clock/NTP health is within the standard"
        details={
            "expected_timezone":settings.TIMEZONE,
            "drift_warn_seconds":DRIFT_WARN_SECONDS,
            "drift_critical_seconds":DRIFT_CRITICAL_SECONDS,
            "router_time_utc":router_dt.isoformat() if router_dt else "",
        }
    except Exception as exc:
        status="unknown"; summary=f"Time/NTP probe unavailable: {str(exc)[:220]}"
        tzname=offset=ntp_status=server_summary=servers_text=""
        enabled=None; drift=None; router_dt=None
        details={"error":str(exc)[:500]}

    with core.db() as conn:
        prev=conn.execute("SELECT status FROM router_time_health WHERE router_id=?",(router_id,)).fetchone()
        conn.execute(
            """INSERT INTO router_time_health
               (router_id,checked_at,status,router_time,timezone_name,utc_offset,ntp_enabled,ntp_status,ntp_servers,drift_seconds,summary,details_json)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET checked_at=excluded.checked_at,status=excluded.status,
                 router_time=excluded.router_time,timezone_name=excluded.timezone_name,utc_offset=excluded.utc_offset,
                 ntp_enabled=excluded.ntp_enabled,ntp_status=excluded.ntp_status,ntp_servers=excluded.ntp_servers,
                 drift_seconds=excluded.drift_seconds,summary=excluded.summary,details_json=excluded.details_json""",
            (router_id,checked.isoformat(),status,router_dt.isoformat() if router_dt else "",tzname,offset,enabled,ntp_status,
             server_summary or servers_text,drift,summary,json.dumps(details)),
        )
    if prev and prev["status"]!=status:
        events.record(router_id,"time-health",f"Time/NTP health: {prev['status']} → {status}",summary,
                      "critical" if status=="critical" else ("warning" if status=="warning" else "info"))
    return {"status":status,"summary":summary,"drift_seconds":drift}


def register(app,page_func):
    @app.get("/time-health/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try:collect(router_id)
        except Exception:pass
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model FROM routers WHERE id=?",(router_id,)).fetchone()
            h=conn.execute("SELECT * FROM router_time_health WHERE router_id=?",(router_id,)).fetchone()
        if not r:return RedirectResponse("/operations",303)
        body=f'''<div class="panel pad"><h2>Time / NTP health · {html.escape(r["site_name"])}</h2>
<div><strong>{html.escape(h["status"] if h else "unknown")}</strong> · {html.escape(h["summary"] if h else "No check yet")}</div>
<div class="muted">Standard: timezone {html.escape(settings.TIMEZONE)}, warning at >{DRIFT_WARN_SECONDS}s clock drift, critical at >{DRIFT_CRITICAL_SECONDS}s. Read-only; Tikcentral does not change the router clock or NTP configuration.</div></div>
<div class="cards">
<div class="card"><h3>Router time</h3><div>{html.escape(h["router_time"] if h else "-")}</div></div>
<div class="card"><h3>Timezone</h3><div>{html.escape(h["timezone_name"] if h else "-")}</div><div class="muted">{html.escape(h["utc_offset"] if h else "")}</div></div>
<div class="card"><h3>Clock drift</h3><div class="value">{f'{h["drift_seconds"]:.0f}s' if h and h["drift_seconds"] is not None else "—"}</div></div>
<div class="card"><h3>NTP</h3><div>{html.escape(h["ntp_status"] if h else "-")}</div><div class="muted">{html.escape(h["ntp_servers"] if h else "")}</div></div>
</div>'''
        return page_func("Time Health",body,user,"operations")
