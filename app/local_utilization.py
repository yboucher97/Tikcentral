"""Estimate LAN-side traffic using known WAN and topology-facing interfaces."""

import html, re
from datetime import datetime, timedelta, timezone
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from app import main as core, migrations, router_exec


def _now(): return datetime.now(timezone.utc).isoformat()

def _rate_bps(value):
    s=(value or "").strip().lower().replace(" ","")
    m=re.search(r"([0-9.]+)([kmgt]?)bps",s)
    if not m:return None
    mult={"":1,"k":1e3,"m":1e6,"g":1e9,"t":1e12}.get(m.group(2),1)
    try:return float(m.group(1))*mult
    except Exception:return None

def _wan_interfaces(ip):
    names=set()
    try:
        out=router_exec.read(ip,'/ip route print detail as-value without-paging where dst-address=0.0.0.0/0 active=yes',timeout=20,label="WAN interface inference")
        for line in out.splitlines():
            for part in line.split(";"):
                if part.startswith("immediate-gw=") or part.startswith("gateway="):
                    value=part.split("=",1)[1]
                    if "%" in value:names.add(value.rsplit("%",1)[1].strip())
                    elif value.startswith("pppoe") or value.startswith("lte"):names.add(value.strip())
    except Exception: pass
    return names

def collect(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        t=conn.execute("SELECT MAX(captured_at) t FROM router_traffic_history WHERE router_id=?",(router_id,)).fetchone()["t"]
        traffic=conn.execute("SELECT interface,rx_bps,tx_bps FROM router_traffic_history WHERE router_id=? AND captured_at=?",(router_id,t or "")).fetchall() if t else []
        topo_t=conn.execute("SELECT MAX(captured_at) t FROM router_topology_devices WHERE router_id=?",(router_id,)).fetchone()["t"]
        topo=conn.execute("SELECT DISTINCT local_interface FROM router_topology_devices WHERE router_id=? AND captured_at=? AND local_interface<>''",(router_id,topo_t or "")).fetchall() if topo_t else []
        iface_t=conn.execute("SELECT MAX(captured_at) t FROM router_interface_history WHERE router_id=?",(router_id,)).fetchone()["t"]
        iface_rows=conn.execute("SELECT name,interface_type,rate FROM router_interface_history WHERE router_id=? AND captured_at=?",(router_id,iface_t or "")).fetchall() if iface_t else []
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired":return None
    wan=_wan_interfaces(r["vpn_ip"])
    traffic_names={x["interface"] for x in traffic if x["interface"]}
    topo_if={x["local_interface"] for x in topo if x["local_interface"] and x["local_interface"] in traffic_names}
    if topo_if:
        lan=topo_if; confidence="high"
    else:
        bridges={x["name"] for x in iface_rows if (x["interface_type"] or "").lower()=="bridge" or "bridge" in (x["name"] or "").lower()}
        bridges={x for x in bridges if x not in wan and not x.startswith(("opticable-wg","wireguard","lo"))}
        if bridges:
            lan=bridges; confidence="medium"
        else:
            candidates={x["interface"] for x in traffic if x["interface"] and not x["interface"].startswith(("opticable-wg","wireguard","lo"))}
            physical={x for x in candidates if x.lower().startswith(("ether","sfp","combo"))}
            lan={x for x in (physical or candidates) if x not in wan}
            confidence="medium" if wan else "low"
    selected=[x for x in traffic if x["interface"] in lan]
    rx=sum(float(x["rx_bps"] or 0) for x in selected); tx=sum(float(x["tx_bps"] or 0) for x in selected); total=rx+tx
    rates={x["name"]:_rate_bps(x["rate"]) for x in iface_rows if x["name"] in lan}
    known_rates=[v for v in rates.values() if v]
    capacity=sum(known_rates) if known_rates and len(known_rates)==len(lan) else None
    utilization=(max(rx,tx)*100/capacity) if capacity and capacity>0 else None
    summary=f"Estimated local traffic {total/1e6:.2f} Mbps across {len(lan)} interface(s) · confidence {confidence}"
    if utilization is not None: summary+=f" · approx {utilization:.1f}% of observed link capacity"
    with core.db() as conn:
        conn.execute("""INSERT INTO router_local_utilization(router_id,captured_at,confidence,wan_interfaces,lan_interfaces,estimated_rx_bps,estimated_tx_bps,estimated_total_bps,summary,estimated_capacity_bps,utilization_percent)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(router_id,_now(),confidence,",".join(sorted(wan)),",".join(sorted(lan)),rx,tx,total,summary,capacity,utilization))
        conn.execute("""DELETE FROM router_local_utilization WHERE router_id=? AND id NOT IN
                        (SELECT id FROM router_local_utilization WHERE router_id=? ORDER BY id DESC LIMIT 10000)""",(router_id,router_id))
    return {"confidence":confidence,"estimated_total_bps":total,"estimated_capacity_bps":capacity,"utilization_percent":utilization,"summary":summary}

def register(app,page_func):
    @app.get("/local-utilization/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try: collect(router_id)
        except Exception: pass
        with core.db() as conn:
            r=conn.execute("SELECT site_name FROM routers WHERE id=?",(router_id,)).fetchone()
            x=conn.execute("SELECT * FROM router_local_utilization WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
            cutoff=(datetime.now(timezone.utc)-timedelta(hours=24)).isoformat()
            hist=conn.execute("SELECT estimated_total_bps FROM router_local_utilization WHERE router_id=? AND captured_at>=? ORDER BY id",(router_id,cutoff)).fetchall()
        vals=[float(v["estimated_total_bps"] or 0) for v in hist]
        avg24=sum(vals)/len(vals) if vals else 0
        peak24=max(vals) if vals else 0
        if not r:return RedirectResponse("/operations",303)
        body=f'''<div class="panel pad"><h2>Local network utilization · {html.escape(r["site_name"])}</h2>
<div><strong>{html.escape(x["confidence"] if x else "unknown")} confidence</strong> · {html.escape(x["summary"] if x else "No estimate yet")}</div>
<div class="muted">This is an estimate, not accounting-grade traffic measurement. Topology-facing interfaces are preferred; otherwise Tikcentral excludes inferred WAN/management interfaces.</div></div>
<div class="cards"><div class="card"><h3>Estimated RX</h3><div class="value">{((x["estimated_rx_bps"] or 0)/1e6 if x else 0):.2f} Mbps</div></div>
<div class="card"><h3>Estimated TX</h3><div class="value">{((x["estimated_tx_bps"] or 0)/1e6 if x else 0):.2f} Mbps</div></div>
<div class="card"><h3>LAN interfaces</h3><div>{html.escape(x["lan_interfaces"] if x else "-")}</div></div>
<div class="card"><h3>WAN excluded</h3><div>{html.escape(x["wan_interfaces"] if x else "-")}</div></div>
<div class="card"><h3>24h average</h3><div class="value">{avg24/1e6:.2f} Mbps</div></div>
<div class="card"><h3>24h peak</h3><div class="value">{peak24/1e6:.2f} Mbps</div></div>
<div class="card"><h3>Estimated utilization</h3><div class="value">{f'{x["utilization_percent"]:.1f}%' if x and x["utilization_percent"] is not None else "—"}</div><div class="muted">Only when all selected links expose negotiated rate</div></div></div>'''
        return page_func("Local Utilization",body,user,"operations")
