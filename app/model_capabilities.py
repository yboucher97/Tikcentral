"""Build a model capability catalog from observed enrolled MikroTik routers."""

import html, re
from datetime import datetime, timezone
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from app import main as core, migrations, router_exec, resource_monitor

def _now(): return datetime.now(timezone.utc).isoformat()
def _field(text,name):
    m=re.search(rf"(?mi)^\s*{re.escape(name)}:\s*(.+?)\s*$",text or "")
    return m.group(1).strip() if m else ""
def _count(lines,pred): return sum(1 for x in lines if pred(x.lower()))

def collect(router_id:int):
    migrations.migrate()
    with core.db() as conn:r=conn.execute("SELECT id,site_name,model,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired":return None
    resource=router_exec.read(r["vpn_ip"],"/system resource print without-paging",timeout=25,label="Model capability resource")
    try: rb=router_exec.read(r["vpn_ip"],"/system routerboard print without-paging",timeout=20,label="Model capability board")
    except Exception: rb=""
    interfaces=router_exec.read(r["vpn_ip"],"/interface print detail as-value without-paging",timeout=30,label="Model capability interfaces")
    lines=[x for x in interfaces.splitlines() if "name=" in x]
    model=r["model"] or _field(rb,"model") or _field(resource,"board-name") or "Unknown"
    arch=_field(resource,"architecture-name"); cpu=_field(resource,"cpu")
    try:cpu_count=int(_field(resource,"cpu-count") or 0) or None
    except Exception:cpu_count=None
    mem=resource_monitor._memory_bytes(_field(resource,"total-memory"))
    storage=resource_monitor._memory_bytes(_field(resource,"total-hdd-space") or _field(resource,"total-storage"))
    ethernet=_count(lines,lambda s:"type=ether" in s or "name=ether" in s)
    sfp=_count(lines,lambda s:"sfp" in s)
    lte=_count(lines,lambda s:"type=lte" in s or "name=lte" in s)
    wifi=_count(lines,lambda s:any(k in s for k in ("type=wifi","type=wlan","name=wlan","name=wifi")))
    wg=_count(lines,lambda s:"type=wireguard" in s or "wireguard" in s)
    now=_now()
    with core.db() as conn:
        conn.execute("""INSERT INTO router_model_capability_observations(router_id,observed_at,model,architecture,cpu,cpu_count,total_memory_bytes,total_storage_bytes,ethernet_ports,sfp_ports,lte_interfaces,wifi_interfaces,wireguard_interfaces)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(router_id) DO UPDATE SET observed_at=excluded.observed_at,model=excluded.model,architecture=excluded.architecture,cpu=excluded.cpu,cpu_count=excluded.cpu_count,total_memory_bytes=excluded.total_memory_bytes,total_storage_bytes=excluded.total_storage_bytes,ethernet_ports=excluded.ethernet_ports,sfp_ports=excluded.sfp_ports,lte_interfaces=excluded.lte_interfaces,wifi_interfaces=excluded.wifi_interfaces,wireguard_interfaces=excluded.wireguard_interfaces""",
                     (router_id,now,model,arch,cpu,cpu_count,mem,storage,ethernet,sfp,lte,wifi,wg))
        rows=conn.execute("SELECT * FROM router_model_capability_observations WHERE model=?",(model,)).fetchall()
        def mx(k): return max((x[k] or 0) for x in rows) if rows else 0
        conn.execute("""INSERT INTO router_model_capability_catalog(model,updated_at,observed_routers,architecture,cpu,max_cpu_count,max_memory_bytes,max_storage_bytes,max_ethernet_ports,max_sfp_ports,max_lte_interfaces,max_wifi_interfaces,wireguard_observed)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(model) DO UPDATE SET updated_at=excluded.updated_at,observed_routers=excluded.observed_routers,architecture=excluded.architecture,cpu=excluded.cpu,max_cpu_count=excluded.max_cpu_count,max_memory_bytes=excluded.max_memory_bytes,max_storage_bytes=excluded.max_storage_bytes,max_ethernet_ports=excluded.max_ethernet_ports,max_sfp_ports=excluded.max_sfp_ports,max_lte_interfaces=excluded.max_lte_interfaces,max_wifi_interfaces=excluded.max_wifi_interfaces,wireguard_observed=excluded.wireguard_observed""",
                     (model,now,len(rows),arch,cpu,mx("cpu_count"),mx("total_memory_bytes"),mx("total_storage_bytes"),mx("ethernet_ports"),mx("sfp_ports"),mx("lte_interfaces"),mx("wifi_interfaces"),1 if mx("wireguard_interfaces") else 0))
    return model

def register(app,page_func):
    @app.get("/model-capabilities",response_class=HTMLResponse)
    def page(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        with core.db() as conn: rows=conn.execute("SELECT * FROM router_model_capability_catalog ORDER BY model").fetchall()
        def gb(v): return f"{(v or 0)/1024/1024:.0f} MB" if v else "—"
        rendered="".join(f'<tr><td><strong>{html.escape(x["model"])}</strong></td><td>{x["observed_routers"]}</td><td>{html.escape(x["architecture"] or "-")}</td><td>{html.escape(x["cpu"] or "-")} / {x["max_cpu_count"] or "—"}</td><td>{gb(x["max_memory_bytes"])}</td><td>{gb(x["max_storage_bytes"])}</td><td>{x["max_ethernet_ports"]}</td><td>{x["max_sfp_ports"]}</td><td>{x["max_lte_interfaces"]}</td><td>{x["max_wifi_interfaces"]}</td></tr>' for x in rows) or '<tr><td colspan="10">No capability observations yet.</td></tr>'
        body=f'''<div class="panel pad"><h2>Router model capability database</h2><div class="muted">Learned from enrolled MikroTik routers actually observed by Tikcentral; no external model database is assumed.</div></div>
<div class="panel"><table><thead><tr><th>Model</th><th>Observed</th><th>Architecture</th><th>CPU / cores</th><th>Memory</th><th>Storage</th><th>Ethernet</th><th>SFP</th><th>LTE</th><th>Wi-Fi</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Model Capabilities",body,user,"operations")
