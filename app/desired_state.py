"""Human-readable desired-state intent with a safe standard fallback profile."""

import html
import json
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, router_exec


STANDARD_INTENT={
    "management_services_restricted": True,
    "default_route_required": True,
    "dns_required": True,
    "wireguard_required": True,
    "minimum_active_default_routes": 1,
}


def _now(): return datetime.now(timezone.utc).isoformat()


def get_intent(router_id:int):
    with core.db() as conn:
        row=conn.execute("SELECT * FROM router_desired_state WHERE router_id=?",(router_id,)).fetchone()
    if not row:return "standard",dict(STANDARD_INTENT)
    try:intent=json.loads(row["intent_json"] or "{}")
    except Exception:intent={}
    merged=dict(STANDARD_INTENT); merged.update(intent)
    return row["profile"] or "standard",merged


def check(router_id:int):
    migrations.migrate(); profile,intent=get_intent(router_id)
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired": return None

    commands={
        "services":"/ip service print detail as-value without-paging",
        "routes":"/ip route print detail as-value without-paging where dst-address=0.0.0.0/0",
        "dns":"/ip dns print",
        "wg":"/interface wireguard print detail as-value without-paging",
    }
    raw={}
    for k,cmd in commands.items():
        try: raw[k]=router_exec.read(r["vpn_ip"],cmd,timeout=30,label=f"Desired state: {k}")
        except Exception as exc: raw[k]=f"ERROR: {exc}"

    details=[]
    def add(name,status,evidence): details.append({"name":name,"status":status,"evidence":evidence})

    if intent.get("management_services_restricted"):
        exposed=[]
        for line in raw["services"].splitlines():
            low=line.lower()
            if any(f"name={x}" in low for x in ("ssh","winbox","api")) and "disabled=true" not in low and "disabled=yes" not in low:
                if "address=" not in low or "address=0.0.0.0/0" in low or "address=::/0" in low:
                    exposed.append(line[:180])
        add("Management services restricted","fail" if exposed else "pass","; ".join(exposed) if exposed else "SSH/WinBox/API restrictions present or services disabled")

    if intent.get("default_route_required"):
        active=sum(1 for line in raw["routes"].splitlines() if "active=true" in line.lower() or "active=yes" in line.lower())
        minimum=int(intent.get("minimum_active_default_routes",1))
        add("Active default route","pass" if active>=minimum else "fail",f"active={active} required={minimum}")

    if intent.get("dns_required"):
        dns_ok="servers:" in raw["dns"].lower() or "dynamic-servers:" in raw["dns"].lower()
        add("DNS configured","pass" if dns_ok else "warning","RouterOS DNS settings readable" if dns_ok else "DNS settings not confirmed")

    if intent.get("wireguard_required"):
        wg_ok=("name=opticable-wg" in raw["wg"].lower()) or ("tikcentral" in raw["wg"].lower())
        add("Tikcentral WireGuard interface","pass" if wg_ok else "fail","Expected management WireGuard interface")

    failed=sum(1 for x in details if x["status"]=="fail"); warnings=sum(1 for x in details if x["status"]=="warning"); passed=sum(1 for x in details if x["status"]=="pass")
    status="fail" if failed else ("warning" if warnings else "pass")
    checked=_now()
    with core.db() as conn:
        prev=conn.execute("SELECT status FROM router_desired_state_status WHERE router_id=?",(router_id,)).fetchone()
        conn.execute(
            """INSERT INTO router_desired_state_status(router_id,checked_at,profile,status,passed,warnings,failed,details_json)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET checked_at=excluded.checked_at,profile=excluded.profile,status=excluded.status,
                 passed=excluded.passed,warnings=excluded.warnings,failed=excluded.failed,details_json=excluded.details_json""",
            (router_id,checked,profile,status,passed,warnings,failed,json.dumps(details)),
        )
    if prev and prev["status"] != status:
        events.record(router_id,"desired-state",f"Desired state: {prev['status']} → {status}",f"{failed} fail / {warnings} warning / {passed} pass","warning" if status!="pass" else "info")
    return {"status":status,"details":details}


def register(app,page_func):
    @app.get("/desired-state/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try: check(router_id)
        except Exception: pass
        profile,intent=get_intent(router_id)
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name FROM routers WHERE id=?",(router_id,)).fetchone()
            st=conn.execute("SELECT * FROM router_desired_state_status WHERE router_id=?",(router_id,)).fetchone()
        if not r:return RedirectResponse("/operations",303)
        details=json.loads(st["details_json"]) if st and st["details_json"] else []
        rows="".join(f'<tr><td>{html.escape(x["status"])}</td><td>{html.escape(x["name"])}</td><td>{html.escape(x["evidence"])}</td></tr>' for x in details) or '<tr><td colspan="3">No check yet.</td></tr>'
        csrf=core.csrf_token(request)
        body=f'''<div class="panel pad"><h2>Desired state · {html.escape(r["site_name"])}</h2>
<div><strong>Profile:</strong> {html.escape(profile)} · status {html.escape(st["status"] if st else "unknown")}</div>
<div class="muted">If no custom intent exists, Tikcentral uses the Standard baseline automatically. This is an audit only; it does not change RouterOS configuration.</div></div>
<div class="panel"><table><thead><tr><th>Status</th><th>Intent</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></div>
<div class="panel pad"><form method="post" action="/desired-state/{router_id}"><input type="hidden" name="csrf" value="{csrf}">
<label>Profile <select name="profile"><option value="standard">standard</option><option value="custom" {"selected" if profile=="custom" else ""}>custom</option></select></label>
<label><input type="checkbox" name="management_services_restricted" value="1" {"checked" if intent.get("management_services_restricted") else ""}> Management services restricted</label>
<label><input type="checkbox" name="default_route_required" value="1" {"checked" if intent.get("default_route_required") else ""}> Default route required</label>
<label><input type="checkbox" name="dns_required" value="1" {"checked" if intent.get("dns_required") else ""}> DNS required</label>
<label><input type="checkbox" name="wireguard_required" value="1" {"checked" if intent.get("wireguard_required") else ""}> Tikcentral WireGuard required</label>
<label>Minimum active default routes <input type="number" min="1" max="4" name="minimum_active_default_routes" value="{int(intent.get("minimum_active_default_routes",1))}"></label>
<button class="primary">Save desired state</button></form></div>'''
        return page_func("Desired State",body,user,"operations")

    @app.post("/desired-state/{router_id}")
    async def save(router_id:int,request:Request):
        user=core.require_web_role(request,"technician")
        data=await core.form_data(request); core.require_csrf(request,data.get("csrf",""))
        profile="custom" if data.get("profile")=="custom" else "standard"
        if profile=="standard":
            intent=dict(STANDARD_INTENT)
        else:
            intent={
                "management_services_restricted":data.get("management_services_restricted")=="1",
                "default_route_required":data.get("default_route_required")=="1",
                "dns_required":data.get("dns_required")=="1",
                "wireguard_required":data.get("wireguard_required")=="1",
                "minimum_active_default_routes":max(1,min(4,int(data.get("minimum_active_default_routes") or 1))),
            }
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_desired_state(router_id,profile,intent_json,updated_by,updated_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(router_id) DO UPDATE SET profile=excluded.profile,intent_json=excluded.intent_json,updated_by=excluded.updated_by,updated_at=excluded.updated_at""",
                (router_id,profile,json.dumps(intent),user["email"],_now()),
            )
        return RedirectResponse(f"/desired-state/{router_id}",303)
