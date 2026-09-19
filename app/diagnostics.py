"""Safe read-only diagnostic command templates for technicians."""

import html

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, router_exec


TEMPLATES={
    "resource":("System resources","/system resource print"),
    "interfaces":("Interface status","/interface print stats-detail without-paging"),
    "routes":("Routing table","/ip route print detail without-paging"),
    "arp":("ARP table","/ip arp print detail without-paging"),
    "dhcp":("DHCP clients / leases","/ip dhcp-client print detail without-paging; /ip dhcp-server lease print detail without-paging"),
    "dns":("DNS status / test",':put ("servers=" . [/ip dns get servers]); :put ("dynamic=" . [/ip dns get dynamic-servers]); :do { :put ("resolve=" . [:resolve "cloudflare.com"]) } on-error={ :put "resolve=FAILED" }'),
    "ping":("Internet ping","/ping address=1.1.1.1 count=5 interval=500ms"),
    "traceroute":("Internet traceroute","/tool traceroute address=1.1.1.1 count=1"),
    "lte":("LTE monitor",':foreach i in=[/interface/lte find] do={ /interface/lte/monitor $i once }'),
    "logs":("Recent logs","/log print without-paging"),
}


def register(app,page_func):
    @app.get("/diagnostics/{router_id}",response_class=HTMLResponse)
    def diagnostics_page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        with core.db() as conn:
            router=conn.execute("SELECT id,site_name,model,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        if not router or not router["enabled"] or (router["lifecycle_state"] or "production")=="retired": return RedirectResponse("/operations",303)
        csrf=core.csrf_token(request)
        buttons="".join(
            f'<form method="post" action="/diagnostics/{router_id}" style="display:inline-block;margin:4px"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="template" value="{k}"><button>{html.escape(v[0])}</button></form>'
            for k,v in TEMPLATES.items()
        )
        body=f'''<div class="panel pad"><h2>Safe diagnostics · {html.escape(router["site_name"])}</h2>
<div class="muted">Predefined read-only RouterOS commands. Viewer accounts cannot run them. Technician and Admin accounts can.</div><div style="margin-top:12px">{buttons}</div></div>'''
        return page_func("Safe Diagnostics",body,user,"operations")

    @app.post("/diagnostics/{router_id}",response_class=HTMLResponse)
    async def diagnostics_run(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request)
        core.require_csrf(request,data.get("csrf",""))
        key=str(data.get("template",""))
        if key not in TEMPLATES: return RedirectResponse(f"/diagnostics/{router_id}",303)
        with core.db() as conn:
            router=conn.execute("SELECT id,site_name,model,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
        if not router or not router["enabled"] or (router["lifecycle_state"] or "production")=="retired": return RedirectResponse("/operations",303)
        label,command=TEMPLATES[key]
        try:
            output=router_exec.read(router["vpn_ip"],command,timeout=60,label=f"Diagnostic: {label}")
        except Exception as exc:
            output=str(exc)
        csrf=core.csrf_token(request)
        body=f'''<div class="panel pad"><h2>{html.escape(label)} · {html.escape(router["site_name"])}</h2>
<div class="muted">Read-only template executed over the management tunnel.</div>
<pre style="white-space:pre-wrap;max-height:70vh;overflow:auto">{html.escape(router_exec.sanitize(output,50000))}</pre>
<div><a href="/diagnostics/{router_id}"><button>Back to diagnostics</button></a></div></div>'''
        return page_func("Safe Diagnostics",body,user,"operations")
