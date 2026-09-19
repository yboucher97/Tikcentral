"""Coordinated DNS, interface negotiation, WAN saturation/bufferbloat, PPPoE and ISP-gateway intelligence."""

import hashlib
import html
import json
import re
import statistics
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, router_exec, wan_probe


MIN_REFRESH_SECONDS=600
DNS_TEST_NAME="cloudflare.com"
SATURATION_PERCENT=85.0
BUFFERBLOAT_WARN_MS=50.0
BUFFERBLOAT_CRITICAL_MS=100.0


def _now():
    return datetime.now(timezone.utc)


def _iso():
    return _now().isoformat()


def _parse_kv_print(text):
    out={}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        k,v=line.split(":",1)
        out[k.strip().lower().replace(" ","-")]=v.strip()
    return out


def _parse_as_value_rows(text):
    rows=[]
    for raw in (text or "").splitlines():
        line=raw.strip()
        if not line:
            continue
        row={}
        for part in line.split(";"):
            if "=" not in part:
                continue
            k,v=part.split("=",1)
            row[k.strip()]=v.strip().strip('"')
        if row:
            rows.append(row)
    return rows


def _bool(v):
    s=str(v or "").strip().lower()
    if s in {"yes","true","1","running","up"}:
        return 1
    if s in {"no","false","0","down"}:
        return 0
    return None


def _int(v):
    try:
        return int(float(str(v).strip()))
    except Exception:
        return None


def _rate_bps(value):
    s=(value or "").strip().lower().replace(" ","")
    m=re.search(r"([0-9.]+)([kmgt]?)bps",s)
    if not m:
        m=re.search(r"([0-9.]+)([kmgt]?)",s)
    if not m:
        return None
    mult={"":1,"k":1e3,"m":1e6,"g":1e9,"t":1e12}.get(m.group(2),1)
    try:
        return float(m.group(1))*mult
    except Exception:
        return None


def _router(router_id):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _gateway_state(ip):
    cmd=':foreach r in=[/ip route find where dst-address="0.0.0.0/0" active=yes] do={ :put ("gateway=" . [/ip route get $r gateway]); :put ("immediate=" . [/ip route get $r immediate-gw]); :break }'
    try:
        out=router_exec.read(ip,cmd,timeout=20,label="ISP gateway discovery")
    except Exception:
        return "",""
    gateway=""; immediate=""
    for line in out.splitlines():
        line=line.strip()
        if line.startswith("gateway="):
            gateway=line.split("=",1)[1].strip()
        elif line.startswith("immediate="):
            immediate=line.split("=",1)[1].strip()
    interface=""
    if "%" in immediate:
        interface=immediate.rsplit("%",1)[1].strip()
    elif gateway and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}",gateway):
        interface=gateway
    return gateway,interface


def _ping(ip,target,count=4):
    if not target:
        return None,None,None
    try:
        out=router_exec.read(ip,f"/ping address={target} count={int(count)} interval=400ms",timeout=20,label=f"Quality ping {target}")
        return wan_probe._parse_ping(out)
    except Exception:
        return None,None,None


def _resolver_list(ip):
    try:
        text=router_exec.read(ip,"/ip dns print",timeout=20,label="DNS configuration")
    except Exception:
        return []
    kv=_parse_kv_print(text)
    values=[]
    for key in ("servers","dynamic-servers"):
        raw=kv.get(key,"")
        for item in re.split(r"[,\s]+",raw):
            item=item.strip()
            if item and item not in values:
                values.append(item)
    return values[:4]


def _dns_collect(router, captured):
    resolvers=_resolver_list(router["vpn_ip"])
    if not resolvers:
        resolvers=["1.1.1.1","8.8.8.8"]
        source="standard-fallback"
    else:
        source="configured"
    results=[]
    for resolver in resolvers:
        ping_ok,_,lat=_ping(router["vpn_ip"],resolver,3)
        try:
            out=router_exec.read(
                router["vpn_ip"],
                f':do {{ :put ("resolved=" . [:resolve "{DNS_TEST_NAME}" server={resolver}]) }} on-error={{ :put "resolved=FAILED" }}',
                timeout=15,
                label=f"DNS resolve via {resolver}",
            )
            resolve_ok="resolved=" in out and "FAILED" not in out
        except Exception:
            resolve_ok=None
        ok=True if resolve_ok is True else (False if resolve_ok is False else ping_ok)
        summary=f"{resolver}: {'resolve ok' if resolve_ok else ('resolve failed' if resolve_ok is False else 'resolve unconfirmed')}"
        if lat is not None:
            summary+=f" · resolver reachability {lat:.1f} ms"
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_dns_health(router_id,captured_at,resolver,test_name,ok,latency_ms,source,summary)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (router["id"],captured,resolver,DNS_TEST_NAME,ok,lat,source,summary),
            )
        results.append({"resolver":resolver,"ok":ok,"latency_ms":lat,"source":source,"summary":summary})
    if results and all(x["ok"] is False for x in results):
        events.record(router["id"],"dns-health","All DNS resolver checks failed","; ".join(x["summary"] for x in results),"warning")
    return results


def _negotiation_collect(router, captured):
    with core.db() as conn:
        times=conn.execute(
            "SELECT DISTINCT captured_at FROM router_interface_history WHERE router_id=? ORDER BY captured_at DESC LIMIT 2",
            (router["id"],),
        ).fetchall()
        if not times:
            return []
        latest_time=times[0]["captured_at"]
        previous_time=times[1]["captured_at"] if len(times)>1 else ""
        latest=conn.execute(
            """SELECT * FROM router_interface_history WHERE router_id=? AND captured_at=?
               AND (LOWER(interface_type) LIKE '%ether%' OR LOWER(name) LIKE 'ether%' OR LOWER(name) LIKE 'sfp%' OR LOWER(name) LIKE 'combo%')""",
            (router["id"],latest_time),
        ).fetchall()
        previous={x["name"]:x for x in conn.execute(
            "SELECT * FROM router_interface_history WHERE router_id=? AND captured_at=?",
            (router["id"],previous_time),
        ).fetchall()} if previous_time else {}
        cutoff=(datetime.now(timezone.utc)-timedelta(hours=24)).isoformat()
        hist=conn.execute(
            """SELECT name,MIN(link_downs) min_downs,MAX(link_downs) max_downs
               FROM router_interface_history WHERE router_id=? AND captured_at>=? GROUP BY name""",
            (router["id"],cutoff),
        ).fetchall()
        flap_map={x["name"]:max(0,int(x["max_downs"] or 0)-int(x["min_downs"] or 0)) for x in hist}
    results=[]
    for cur in latest:
        prev=previous.get(cur["name"])
        current_rate=cur["rate"] or ""
        previous_rate=prev["rate"] if prev else ""
        current_bps=_rate_bps(current_rate)
        previous_bps=_rate_bps(previous_rate)
        changed=bool(prev and (
            current_rate!=previous_rate or
            cur["full_duplex"]!=prev["full_duplex"] or
            (cur["auto_negotiation"] or "")!=(prev["auto_negotiation"] or "")
        ))
        downgrade=bool(prev and current_bps and previous_bps and current_bps<previous_bps)
        half_duplex=cur["full_duplex"]==0 and cur["running"]==1
        flaps=flap_map.get(cur["name"],0)
        if downgrade or half_duplex or flaps>=3:
            status="warning"
        elif cur["running"]==1:
            status="ok"
        else:
            status="unknown"
        pieces=[f"{cur['name']}: {current_rate or 'rate unknown'}"]
        if downgrade:
            pieces.append(f"downgraded from {previous_rate}")
        if half_duplex:
            pieces.append("half duplex")
        if flaps:
            pieces.append(f"{flaps} link-down increment(s) in 24h")
        summary=" · ".join(pieces)
        with core.db() as conn:
            old=conn.execute(
                "SELECT status,current_rate,current_full_duplex FROM router_interface_negotiation WHERE router_id=? AND interface=?",
                (router["id"],cur["name"]),
            ).fetchone()
            conn.execute(
                """INSERT INTO router_interface_negotiation
                   (router_id,interface,checked_at,current_rate,current_full_duplex,current_auto_negotiation,
                    previous_rate,previous_full_duplex,previous_auto_negotiation,changed,downgrade,flaps_24h,status,summary)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(router_id,interface) DO UPDATE SET checked_at=excluded.checked_at,
                     current_rate=excluded.current_rate,current_full_duplex=excluded.current_full_duplex,
                     current_auto_negotiation=excluded.current_auto_negotiation,previous_rate=excluded.previous_rate,
                     previous_full_duplex=excluded.previous_full_duplex,previous_auto_negotiation=excluded.previous_auto_negotiation,
                     changed=excluded.changed,downgrade=excluded.downgrade,flaps_24h=excluded.flaps_24h,
                     status=excluded.status,summary=excluded.summary""",
                (router["id"],cur["name"],captured,current_rate,cur["full_duplex"],cur["auto_negotiation"] or "",
                 previous_rate,prev["full_duplex"] if prev else None,prev["auto_negotiation"] if prev else "",
                 1 if changed else 0,1 if downgrade else 0,flaps,status,summary),
            )
        if old and old["status"]!="warning" and status=="warning":
            events.record(router["id"],"interface-negotiation",f"Interface negotiation warning: {cur['name']}",summary,"warning")
        results.append({"interface":cur["name"],"status":status,"summary":summary})
    return results


def _pppoe_collect(router,captured):
    try:
        out=router_exec.read(router["vpn_ip"],"/interface pppoe-client print detail as-value without-paging",timeout=25,label="PPPoE intelligence")
        rows=_parse_as_value_rows(out)
    except Exception:
        rows=[]
    results=[]
    for x in rows:
        name=x.get("name","")
        if not name:
            continue
        running=_bool(x.get("running"))
        disabled=_bool(x.get("disabled"))
        uptime=x.get("uptime","")
        service=x.get("service-name","")
        ac=x.get("ac-name","") or x.get("ac","")
        local=x.get("local-address","")
        remote=x.get("remote-address","")
        mtu=_int(x.get("mtu") or x.get("max-mtu"))
        mru=_int(x.get("mru") or x.get("max-mru"))
        status="up" if running else ("disabled" if disabled else "down")
        fingerprint=hashlib.sha256(json.dumps([name,running,ac,local,remote,mtu,mru],sort_keys=True).encode()).hexdigest()
        summary=f"{name}: {status}"
        if ac:summary+=f" · AC {ac}"
        if local:summary+=f" · IP {local}"
        if mtu or mru:summary+=f" · MTU/MRU {mtu or '-'} / {mru or '-'}"
        with core.db() as conn:
            prev=conn.execute(
                "SELECT * FROM router_pppoe_history WHERE router_id=? AND interface=? ORDER BY id DESC LIMIT 1",
                (router["id"],name),
            ).fetchone()
            conn.execute(
                """INSERT INTO router_pppoe_history
                   (router_id,captured_at,interface,running,disabled,uptime,service_name,ac_name,local_address,remote_address,mtu,mru,status,fingerprint,summary)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (router["id"],captured,name,running,disabled,uptime,service,ac,local,remote,mtu,mru,status,fingerprint,summary),
            )
        if prev and prev["fingerprint"]!=fingerprint:
            detail=f"before={prev['summary']}; after={summary}"
            sev="warning" if running==0 or (prev["ac_name"] and ac and prev["ac_name"]!=ac) else "info"
            events.record(router["id"],"pppoe","PPPoE session characteristics changed",detail,sev)
        results.append({"interface":name,"status":status,"summary":summary})
    return results


def _gateway_collect(router,captured):
    gateway,interface=_gateway_state(router["vpn_ip"])
    reachable=None; latency=None; mac=""
    if gateway and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}",gateway):
        reachable,_,latency=_ping(router["vpn_ip"],gateway,3)
        try:
            arp=router_exec.read(
                router["vpn_ip"],
                f'/ip arp print detail as-value without-paging where address="{gateway}"',
                timeout=15,
                label="ISP gateway ARP",
            )
            rows=_parse_as_value_rows(arp)
            if rows:
                mac=rows[0].get("mac-address","")
        except Exception:
            pass
    with core.db() as conn:
        prev=conn.execute(
            "SELECT * FROM router_isp_gateway_history WHERE router_id=? ORDER BY id DESC LIMIT 1",
            (router["id"],),
        ).fetchone()
        changed=bool(prev and (prev["gateway"]!=gateway or prev["mac_address"]!=mac or prev["interface"]!=interface))
        summary=f"Gateway {gateway or 'unknown'}"
        if interface:summary+=f" via {interface}"
        if reachable is not None:summary+=f" · {'reachable' if reachable else 'unreachable'}"
        if latency is not None:summary+=f" · {latency:.1f} ms"
        if mac:summary+=f" · MAC {mac}"
        conn.execute(
            """INSERT INTO router_isp_gateway_history
               (router_id,captured_at,gateway,interface,reachable,latency_ms,mac_address,changed,summary)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (router["id"],captured,gateway,interface,reachable,latency,mac,1 if changed else 0,summary),
        )
    if prev and changed:
        events.record(router["id"],"isp-gateway","ISP gateway characteristics changed",f"before={prev['summary']}; after={summary}","warning")
    return {"gateway":gateway,"interface":interface,"reachable":reachable,"latency_ms":latency,"mac_address":mac,"summary":summary}


def _wan_quality_collect(router,captured,gateway):
    wan_if=gateway.get("interface","")
    with core.db() as conn:
        meta=conn.execute("SELECT circuit_down_mbps,circuit_up_mbps FROM router_site_metadata WHERE router_id=?",(router["id"],)).fetchone()
        traffic=None
        if wan_if:
            traffic=conn.execute(
                "SELECT * FROM router_traffic_history WHERE router_id=? AND interface=? ORDER BY id DESC LIMIT 1",
                (router["id"],wan_if),
            ).fetchone()
        if not traffic:
            candidates=conn.execute(
                "SELECT * FROM router_traffic_history WHERE router_id=? ORDER BY id DESC LIMIT 30",
                (router["id"],),
            ).fetchall()
            traffic=next((x for x in candidates if x["interface"] and x["interface"].lower().startswith(("pppoe","lte"))),None)
            if traffic and not wan_if:
                wan_if=traffic["interface"]
        iface=conn.execute(
            "SELECT rate FROM router_interface_history WHERE router_id=? AND name=? ORDER BY id DESC LIMIT 1",
            (router["id"],wan_if),
        ).fetchone() if wan_if else None
        probes=conn.execute(
            """SELECT target1_avg_ms,target2_avg_ms,classification FROM router_wan_probe_history
               WHERE router_id=? AND captured_at>=? ORDER BY id DESC LIMIT 100""",
            (router["id"],(datetime.now(timezone.utc)-timedelta(days=7)).isoformat()),
        ).fetchall()

    down_capacity=(float(meta["circuit_down_mbps"])*1e6) if meta and meta["circuit_down_mbps"] else None
    up_capacity=(float(meta["circuit_up_mbps"])*1e6) if meta and meta["circuit_up_mbps"] else None
    capacity_source="site-metadata" if down_capacity or up_capacity else "unknown"
    link_rate=_rate_bps(iface["rate"]) if iface else None
    if not down_capacity and link_rate:
        down_capacity=link_rate; capacity_source="negotiated-link"
    if not up_capacity and link_rate:
        up_capacity=link_rate; capacity_source="negotiated-link"

    rx=float(traffic["rx_bps"] or 0) if traffic else None
    tx=float(traffic["tx_bps"] or 0) if traffic else None
    rx_pct=(rx*100/down_capacity) if rx is not None and down_capacity else None
    tx_pct=(tx*100/up_capacity) if tx is not None and up_capacity else None
    saturation=bool((rx_pct is not None and rx_pct>=SATURATION_PERCENT) or (tx_pct is not None and tx_pct>=SATURATION_PERCENT))

    latency_samples=[]
    latest_latency=None
    for idx,p in enumerate(probes):
        vals=[float(v) for v in (p["target1_avg_ms"],p["target2_avg_ms"]) if v is not None]
        if vals:
            avg=sum(vals)/len(vals)
            latency_samples.append(avg)
            if idx==0:
                latest_latency=avg
    idle_latency=None
    if latency_samples:
        ordered=sorted(latency_samples)
        low=ordered[:max(1,len(ordered)//4)]
        idle_latency=statistics.median(low)
    increase=(latest_latency-idle_latency) if latest_latency is not None and idle_latency is not None else None
    if saturation and increase is not None:
        ratio=(latest_latency/idle_latency) if idle_latency and idle_latency>0 else None
        if increase>=BUFFERBLOAT_CRITICAL_MS or (ratio is not None and ratio>=3):
            bloat="severe"
        elif increase>=BUFFERBLOAT_WARN_MS or (ratio is not None and ratio>=2):
            bloat="warning"
        else:
            bloat="not_observed_under_load"
    elif saturation:
        bloat="unknown"
    else:
        bloat="not_tested_under_load"

    if saturation and bloat in {"severe","warning"}:
        status="warning"
    elif saturation:
        status="saturated"
    elif traffic:
        status="ok"
    else:
        status="unknown"
    summary=f"WAN {wan_if or 'interface unknown'}"
    if rx_pct is not None or tx_pct is not None:
        summary+=f" · RX {rx_pct:.1f}%" if rx_pct is not None else ""
        summary+=f" · TX {tx_pct:.1f}%" if tx_pct is not None else ""
    if capacity_source!="unknown":
        summary+=f" · capacity source {capacity_source}"
    if increase is not None:
        summary+=f" · latency +{increase:.1f} ms vs low-load baseline"
    summary+=f" · bufferbloat {bloat}"

    with core.db() as conn:
        prev=conn.execute("SELECT status,bufferbloat_status FROM router_wan_quality WHERE router_id=? ORDER BY id DESC LIMIT 1",(router["id"],)).fetchone()
        conn.execute(
            """INSERT INTO router_wan_quality
               (router_id,captured_at,wan_interface,capacity_source,down_capacity_bps,up_capacity_bps,rx_bps,tx_bps,
                rx_utilization_percent,tx_utilization_percent,idle_latency_ms,observed_latency_ms,latency_increase_ms,
                saturation,bufferbloat_status,status,summary)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (router["id"],captured,wan_if,capacity_source,down_capacity,up_capacity,rx,tx,rx_pct,tx_pct,
             idle_latency,latest_latency,increase,1 if saturation else 0,bloat,status,summary),
        )
    if prev and prev["status"]!=status and status in {"warning","saturated"}:
        events.record(router["id"],"wan-quality",f"WAN quality state: {prev['status']} → {status}",summary,"warning")
    return {"status":status,"bufferbloat_status":bloat,"summary":summary}


def collect(router_id:int,force=False):
    migrations.migrate()
    router=_router(router_id)
    if not router or not router["enabled"] or (router["lifecycle_state"] or "production")=="retired":
        return None
    with core.db() as conn:
        last=conn.execute(
            "SELECT captured_at FROM router_wan_quality WHERE router_id=? ORDER BY id DESC LIMIT 1",
            (router_id,),
        ).fetchone()
    if last and not force:
        try:
            if (_now()-datetime.fromisoformat(last["captured_at"])).total_seconds()<MIN_REFRESH_SECONDS:
                return {"status":"cached"}
        except Exception:
            pass
    captured=_iso()
    dns=_dns_collect(router,captured)
    negotiation=_negotiation_collect(router,captured)
    pppoe=_pppoe_collect(router,captured)
    gateway=_gateway_collect(router,captured)
    wan=_wan_quality_collect(router,captured,gateway)
    return {"dns":dns,"negotiation":negotiation,"pppoe":pppoe,"gateway":gateway,"wan":wan}


def register(app,page_func):
    @app.get("/network-quality/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try:collect(router_id)
        except Exception:pass
        with core.db() as conn:
            r=conn.execute("SELECT site_name FROM routers WHERE id=?",(router_id,)).fetchone()
            dns_t=conn.execute("SELECT MAX(captured_at) t FROM router_dns_health WHERE router_id=?",(router_id,)).fetchone()["t"]
            dns=conn.execute("SELECT * FROM router_dns_health WHERE router_id=? AND captured_at=? ORDER BY resolver",(router_id,dns_t or "")).fetchall() if dns_t else []
            neg=conn.execute("SELECT * FROM router_interface_negotiation WHERE router_id=? ORDER BY interface",(router_id,)).fetchall()
            wan=conn.execute("SELECT * FROM router_wan_quality WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
            pppoe_t=conn.execute("SELECT MAX(captured_at) t FROM router_pppoe_history WHERE router_id=?",(router_id,)).fetchone()["t"]
            pppoe=conn.execute("SELECT * FROM router_pppoe_history WHERE router_id=? AND captured_at=? ORDER BY interface",(router_id,pppoe_t or "")).fetchall() if pppoe_t else []
            gw=conn.execute("SELECT * FROM router_isp_gateway_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
        if not r:return RedirectResponse("/operations",303)
        csrf=core.csrf_token(request)
        dns_rows="".join(f'<tr><td>{html.escape(x["resolver"])}</td><td>{"OK" if x["ok"] else ("FAIL" if x["ok"] is not None else "UNKNOWN")}</td><td>{f"{x["latency_ms"]:.1f} ms" if x["latency_ms"] is not None else "—"}</td><td>{html.escape(x["source"])}</td><td>{html.escape(x["summary"])}</td></tr>' for x in dns) or '<tr><td colspan="5">No DNS sample.</td></tr>'
        neg_rows="".join(f'<tr><td>{html.escape(x["interface"])}</td><td>{html.escape(x["current_rate"] or "-")}</td><td>{"full" if x["current_full_duplex"] else ("half" if x["current_full_duplex"] is not None else "—")}</td><td>{x["flaps_24h"]}</td><td>{html.escape(x["status"])}</td><td>{html.escape(x["summary"])}</td></tr>' for x in neg) or '<tr><td colspan="6">No negotiation sample.</td></tr>'
        pppoe_rows="".join(f'<tr><td>{html.escape(x["interface"])}</td><td>{html.escape(x["status"])}</td><td>{html.escape(x["uptime"] or "-")}</td><td>{html.escape(x["ac_name"] or "-")}</td><td>{html.escape(x["local_address"] or "-")}</td><td>{x["mtu"] or "—"} / {x["mru"] or "—"}</td></tr>' for x in pppoe) or '<tr><td colspan="6">No PPPoE client observed.</td></tr>'
        wan_status=wan["summary"] if wan else "No WAN quality sample."
        gateway_status=gw["summary"] if gw else "No ISP gateway sample."
        body=f'''<div class="panel pad"><h2>Network quality · {html.escape(r["site_name"])}</h2>
<div><strong>{html.escape(wan_status)}</strong></div><div class="muted">WAN saturation uses configured circuit speed when available; negotiated link rate is only a lower-confidence fallback. Bufferbloat is only assessed when high utilization is actually observed.</div>
<form method="post" action="/network-quality/{router_id}/run" style="margin-top:12px"><input type="hidden" name="csrf" value="{csrf}"><button class="primary">Run quality diagnostics now</button></form></div>
<div class="panel pad"><h3>ISP gateway</h3><div>{html.escape(gateway_status)}</div></div>
<div class="panel"><div class="pad"><h3>DNS resolver health / reachability latency</h3></div><table><thead><tr><th>Resolver</th><th>Resolution</th><th>Reachability RTT</th><th>Source</th><th>Summary</th></tr></thead><tbody>{dns_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Interface negotiation</h3></div><table><thead><tr><th>Interface</th><th>Rate</th><th>Duplex</th><th>Link-down Δ 24h</th><th>Status</th><th>Summary</th></tr></thead><tbody>{neg_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>PPPoE</h3></div><table><thead><tr><th>Interface</th><th>Status</th><th>Uptime</th><th>AC</th><th>Assigned IP</th><th>MTU / MRU</th></tr></thead><tbody>{pppoe_rows}</tbody></table></div>'''
        return page_func("Network Quality",body,user,"operations")

    @app.post("/network-quality/{router_id}/run")
    async def run(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request);core.require_csrf(request,data.get("csrf",""))
        collect(router_id,force=True)
        return RedirectResponse(f"/network-quality/{router_id}",303)
