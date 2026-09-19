"""Multi-target WAN probing with a standard fallback profile."""

import html
import ipaddress
import json
import re
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, router_exec


STANDARD={
    "profile":"standard",
    "targets":["1.1.1.1","8.8.8.8"],
    "dns_name":"cloudflare.com",
    "latency_warn_ms":150.0,
    "packet_loss_warn_percent":20.0,
}


def _now(): return datetime.now(timezone.utc).isoformat()


_HOST_RE=re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _safe_target(value: str) -> str:
    raw=(value or "").strip()
    if not raw:
        raise ValueError("probe target is empty")
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        pass
    if _HOST_RE.fullmatch(raw):
        return raw
    raise ValueError("probe target must be a valid IP address or hostname")


def get_config(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        row=conn.execute("SELECT * FROM router_wan_probe_config WHERE router_id=?",(router_id,)).fetchone()
    if not row:
        return dict(STANDARD)
    try: targets=json.loads(row["targets_json"] or "[]")
    except Exception: targets=[]
    return {
        "profile":row["profile"] or "standard",
        "targets":targets or list(STANDARD["targets"]),
        "dns_name":row["dns_name"] or STANDARD["dns_name"],
        "latency_warn_ms":row["latency_warn_ms"] if row["latency_warn_ms"] is not None else STANDARD["latency_warn_ms"],
        "packet_loss_warn_percent":row["packet_loss_warn_percent"] if row["packet_loss_warn_percent"] is not None else STANDARD["packet_loss_warn_percent"],
    }


def _parse_ping(text):
    loss=None; avg=None
    m=re.search(r"packet-loss\s*[:=]\s*([0-9.]+)%",text or "",re.I)
    if m: loss=float(m.group(1))
    m=re.search(r"avg-rtt\s*[:=]\s*([0-9.]+)ms",text or "",re.I)
    if not m:
        m=re.search(r"avg\s*[:=]\s*([0-9.]+)ms",text or "",re.I)
    if m: avg=float(m.group(1))
    ok=(loss is not None and loss<100) or ("time=" in (text or "").lower())
    return ok,loss,avg


def _default_gateway(ip):
    cmd=':foreach r in=[/ip route find where dst-address="0.0.0.0/0" active=yes] do={ :put [/ip route get $r gateway]; :break }'
    try:
        out=router_exec.read(ip,cmd,timeout=20,label="WAN probe gateway")
        return (out or "").strip().splitlines()[-1].strip()
    except Exception:return ""


def _ping(ip,target):
    if not target:return None,None,None
    try:
        out=router_exec.read(ip,f"/ping address={target} count=4 interval=500ms",timeout=20,label=f"WAN probe {target}")
        return _parse_ping(out)
    except Exception:return False,None,None


def collect(router_id:int):
    migrations.migrate(); cfg=get_config(router_id)
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired": return None
    gateway=_default_gateway(r["vpn_ip"])
    gok,_,_= _ping(r["vpn_ip"],gateway) if gateway else (None,None,None)
    targets=(cfg["targets"]+["",""])[:2]
    p1=_ping(r["vpn_ip"],targets[0]); p2=_ping(r["vpn_ip"],targets[1])
    try:
        dns_name=_safe_target(str(cfg["dns_name"]))
        dnsout=router_exec.read(r["vpn_ip"],f':do {{ :put ("resolved=" . [:resolve "{dns_name}"]) }} on-error={{ :put "resolved=FAILED" }}',timeout=20,label="WAN DNS probe")
        dns_ok="FAILED" not in dnsout and "resolved=" in dnsout
    except Exception:dns_ok=False

    successes=sum(1 for x in (p1[0],p2[0]) if x)
    losses=[v for v in (p1[1],p2[1]) if v is not None]
    latencies=[v for v in (p1[2],p2[2]) if v is not None]
    quality_bad=(losses and max(losses)>=float(cfg["packet_loss_warn_percent"])) or (latencies and max(latencies)>=float(cfg["latency_warn_ms"]))
    if gok is False and successes==0 and not dns_ok:
        classification="site_or_upstream"; summary="Gateway and external Internet probes failed"
    elif gok and successes==0:
        classification="upstream"; summary="Gateway reachable but both external probe targets failed"
    elif successes>0 and not dns_ok:
        classification="dns"; summary="Internet IP reachability works but DNS resolution failed"
    elif successes==1:
        classification="partial"; summary="One Internet probe target failed while another succeeded"
    elif successes==2 and dns_ok and quality_bad:
        classification="degraded_quality"
        summary=f'Internet reachable but quality exceeds standard threshold (loss ≥ {cfg["packet_loss_warn_percent"]}% or latency ≥ {cfg["latency_warn_ms"]} ms)'
    elif successes==2 and dns_ok:
        classification="healthy"; summary="Gateway/Internet/DNS probing is healthy" if gok is not False else "Internet/DNS healthy; gateway probe unavailable or failed"
    else:
        classification="unknown"; summary="WAN probe result is incomplete"

    checked=_now()
    with core.db() as conn:
        prev=conn.execute("SELECT classification FROM router_wan_probe_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
        conn.execute(
            """INSERT INTO router_wan_probe_history
               (router_id,captured_at,profile,gateway,gateway_ok,target1,target1_ok,target1_loss,target1_avg_ms,
                target2,target2_ok,target2_loss,target2_avg_ms,dns_name,dns_ok,classification,summary)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (router_id,checked,cfg["profile"],gateway,gok,targets[0],p1[0],p1[1],p1[2],targets[1],p2[0],p2[1],p2[2],cfg["dns_name"],dns_ok,classification,summary),
        )
        conn.execute(
            """DELETE FROM router_wan_probe_history WHERE router_id=? AND id NOT IN
               (SELECT id FROM router_wan_probe_history WHERE router_id=? ORDER BY id DESC LIMIT 10000)""",(router_id,router_id))
    if prev and prev["classification"] != classification:
        events.record(router_id,"wan-probe",f"WAN probe: {prev['classification']} → {classification}",summary,
                      "warning" if classification not in {"healthy","unknown"} else "info")
    return {"classification":classification,"summary":summary}


def register(app,page_func):
    @app.get("/wan-probe/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try: collect(router_id)
        except Exception: pass
        cfg=get_config(router_id)
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name FROM routers WHERE id=?",(router_id,)).fetchone()
            latest=conn.execute("SELECT * FROM router_wan_probe_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
        if not r:return RedirectResponse("/operations",303)
        csrf=core.csrf_token(request)
        status="No probe yet" if not latest else f'{latest["classification"]} · {latest["summary"]}'
        body=f'''<div class="panel pad"><h2>WAN probing · {html.escape(r["site_name"])}</h2>
<div><strong>{html.escape(status)}</strong></div>
<div class="muted">When no site-specific information exists, Tikcentral automatically uses the Standard profile: gateway + 1.1.1.1 + 8.8.8.8 + DNS resolve of cloudflare.com.</div></div>
<div class="panel pad"><form method="post" action="/wan-probe/{router_id}">
<input type="hidden" name="csrf" value="{csrf}">
<div class="cards"><div><label>Profile<br><select name="profile"><option value="standard">standard</option><option value="custom" {"selected" if cfg["profile"]=="custom" else ""}>custom</option></select></label></div>
<div><label>Target 1<br><input name="target1" value="{html.escape(cfg["targets"][0])}"></label></div>
<div><label>Target 2<br><input name="target2" value="{html.escape(cfg["targets"][1])}"></label></div>
<div><label>DNS name<br><input name="dns_name" value="{html.escape(cfg["dns_name"])}"></label></div></div>
<div style="margin-top:10px"><label>Latency warning ms <input name="latency_warn_ms" value="{cfg["latency_warn_ms"]}"></label>
<label> Packet loss warning % <input name="loss_warn" value="{cfg["packet_loss_warn_percent"]}"></label></div>
<button class="primary">Save probe profile</button></form></div>'''
        return page_func("WAN Probe",body,user,"operations")

    @app.post("/wan-probe/{router_id}")
    async def save(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        profile="custom" if data.get("profile")=="custom" else "standard"
        if profile=="standard":
            cfg=dict(STANDARD)
        else:
            try:
                target1=_safe_target(str(data.get("target1","")).strip() or STANDARD["targets"][0])
                target2=_safe_target(str(data.get("target2","")).strip() or STANDARD["targets"][1])
                dns_name=_safe_target(str(data.get("dns_name","")).strip() or STANDARD["dns_name"])
                latency=float(data.get("latency_warn_ms") or STANDARD["latency_warn_ms"])
                loss=float(data.get("loss_warn") or STANDARD["packet_loss_warn_percent"])
            except (TypeError,ValueError) as exc:
                raise HTTPException(status_code=400,detail=str(exc) or "invalid WAN probe configuration")
            if not (1 <= latency <= 60000):
                raise HTTPException(status_code=400,detail="latency warning must be between 1 and 60000 ms")
            if not (0 <= loss <= 100):
                raise HTTPException(status_code=400,detail="packet loss warning must be between 0 and 100 percent")
            cfg={
                "profile":"custom",
                "targets":[target1,target2],
                "dns_name":dns_name,
                "latency_warn_ms":latency,
                "packet_loss_warn_percent":loss,
            }
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_wan_probe_config(router_id,profile,targets_json,dns_name,latency_warn_ms,packet_loss_warn_percent,updated_by,updated_at)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(router_id) DO UPDATE SET profile=excluded.profile,targets_json=excluded.targets_json,dns_name=excluded.dns_name,
                     latency_warn_ms=excluded.latency_warn_ms,packet_loss_warn_percent=excluded.packet_loss_warn_percent,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                (router_id,cfg["profile"],json.dumps(cfg["targets"]),cfg["dns_name"],cfg["latency_warn_ms"],cfg["packet_loss_warn_percent"],user["email"],_now()),
            )
        return RedirectResponse(f"/wan-probe/{router_id}",303)
