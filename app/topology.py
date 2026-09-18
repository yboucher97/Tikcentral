"""Site topology view: MikroTik router plus external UniFi/Omada infrastructure."""

import hashlib
import html
import json
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations, router_exec


NEIGHBOR_COMMAND="/ip neighbor print detail as-value without-paging"


def _now(): return datetime.now(timezone.utc).isoformat()


def _parse(text):
    rows=[]
    for line in (text or "").splitlines():
        line=line.strip()
        if not line or "=" not in line: continue
        row={}
        for part in line.split(";"):
            if "=" in part:
                k,v=part.split("=",1); row[k.strip()]=v.strip().strip('"')
        if row: rows.append(row)
    return rows


def _vendor(row):
    text=" ".join(str(row.get(k,"")) for k in ("identity","platform","board","software-id","system-description")).lower()
    if "ubiquiti" in text or "unifi" in text: return "Ubiquiti / UniFi"
    if "tp-link" in text or "tplink" in text or "omada" in text: return "TP-Link / Omada"
    return ""


def _type(row,vendor):
    text=(" ".join(str(row.get(k,"")) for k in ("identity","platform","board","system-description"))).lower()
    if any(x in text for x in ("access point","wireless","u6 ","u7 ","eap","ap ")): return "access-point"
    if any(x in text for x in ("switch","usw","sg2","sg3","tl-sg","sx3")): return "switch"
    if vendor: return "network-device"
    return "unknown"


def collect(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        inventory=conn.execute(
            """SELECT id,category,manufacturer,model,asset_tag,location,status
               FROM hardware_inventory WHERE router_id=? AND status<>'retired'
               ORDER BY category,model,id""",(router_id,)).fetchall()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired": return []

    captured=_now(); items=[]
    try:
        neighbors=_parse(router_exec.read(r["vpn_ip"],NEIGHBOR_COMMAND,timeout=35,label="Topology neighbors"))
    except Exception:
        neighbors=[]

    for x in neighbors:
        vendor=_vendor(x); dtype=_type(x,vendor)
        name=x.get("identity") or x.get("system-description") or x.get("address") or "(neighbor)"
        ip=x.get("address") or x.get("ipv4-address") or ""
        mac=x.get("mac-address") or ""
        iface=x.get("interface") or ""
        # We only present external switching/AP topology; MikroTik is the router itself.
        if "mikrotik" in (" ".join(str(v) for v in x.values())).lower():
            continue
        fp=hashlib.sha256(json.dumps([name,ip,mac,iface,vendor,dtype],sort_keys=True).encode()).hexdigest()
        items.append(("neighbor",dtype,vendor,name,ip,mac,iface,"high" if vendor else "medium",None,fp))

    for x in inventory:
        cat=(x["category"] or "other").lower()
        if cat not in {"switch","ap","access-point","wireless","other"}: continue
        vendor=x["manufacturer"] or ""
        name=(" ".join(v for v in (vendor,x["model"],x["asset_tag"]) if v)).strip() or f"Inventory #{x['id']}"
        dtype="switch" if cat=="switch" else ("access-point" if cat in {"ap","access-point","wireless"} else "network-device")
        # Avoid duplicating an observed neighbor with an obvious same model/name.
        if any((x["model"] or "").lower() and (x["model"] or "").lower() in it[3].lower() for it in items):
            continue
        fp=hashlib.sha256(json.dumps([name,x["location"],dtype,vendor],sort_keys=True).encode()).hexdigest()
        items.append(("inventory",dtype,vendor,name,"","","","inventory",x["id"],fp))

    with core.db() as conn:
        for it in items:
            conn.execute(
                """INSERT INTO router_topology_devices
                   (router_id,captured_at,source,device_type,vendor,name,ip_address,mac_address,local_interface,confidence,inventory_id,fingerprint)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (router_id,captured,*it),
            )
        conn.execute(
            """DELETE FROM router_topology_devices WHERE router_id=? AND id NOT IN
               (SELECT id FROM router_topology_devices WHERE router_id=? ORDER BY id DESC LIMIT 8000)""",
            (router_id,router_id),
        )
    return items


def register(app,page_func):
    @app.get("/topology/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try: collect(router_id)
        except Exception: pass
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?",(router_id,)).fetchone()
            t=conn.execute("SELECT MAX(captured_at) t FROM router_topology_devices WHERE router_id=?",(router_id,)).fetchone()["t"]
            rows=conn.execute(
                "SELECT * FROM router_topology_devices WHERE router_id=? AND captured_at=? ORDER BY device_type,vendor,name",
                (router_id,t or ""),
            ).fetchall() if t else []
        if not r:return RedirectResponse("/operations",303)
        rendered="".join(
            f'<tr><td>{html.escape(x["device_type"])}</td><td>{html.escape(x["vendor"] or "-")}</td><td><strong>{html.escape(x["name"])}</strong></td>'
            f'<td>{html.escape(x["ip_address"] or "-")}</td><td>{html.escape(x["local_interface"] or "-")}</td><td>{html.escape(x["source"])}</td><td>{html.escape(x["confidence"])}</td></tr>'
            for x in rows
        ) or '<tr><td colspan="7">No external switch/AP topology evidence yet.</td></tr>'
        body=f'''<div class="panel pad"><h2>Site topology · {html.escape(r["site_name"])}</h2>
<div><strong>MikroTik router:</strong> {html.escape(r["model"] or "Router")} · <code>{html.escape(r["vpn_ip"])}</code></div>
<div class="muted">Tikcentral treats MikroTik as the router/gateway only. UniFi/Omada switches and APs are shown from neighbor evidence and hardware inventory; Tikcentral does not manage them from this page.</div></div>
<div class="panel"><table><thead><tr><th>Type</th><th>Vendor</th><th>Device</th><th>IP</th><th>Router interface</th><th>Source</th><th>Confidence</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Site Topology",body,user,"operations")
