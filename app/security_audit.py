"""Read-only RouterOS service exposure and security-surface audit."""

import hashlib
import html
import json
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, router_exec


COMMANDS=(
    ("services","/ip service print detail as-value without-paging"),
    ("mac_server","/tool mac-server print"),
    ("mac_winbox","/tool mac-server mac-winbox print"),
    ("neighbor","/ip neighbor discovery-settings print"),
    ("bandwidth","/tool bandwidth-server print"),
    ("socks","/ip socks print"),
    ("proxy","/ip proxy print"),
    ("snmp","/snmp print"),
)

SAFE_SERVICE_NAMES={"ssh","winbox","api"}
MANAGED_ADDRESS_HINTS=("10.250.","127.0.0.1","::1")


def _now(): return datetime.now(timezone.utc).isoformat()


def _parse_rows(text):
    rows=[]
    for line in (text or "").splitlines():
        line=line.strip()
        if not line or "=" not in line: continue
        row={}
        for part in line.split(";"):
            if "=" not in part: continue
            k,v=part.split("=",1)
            row[k.strip()]=v.strip().strip('"')
        if row: rows.append(row)
    return rows


def _kv(text):
    out={}
    for line in (text or "").splitlines():
        if ":" in line:
            k,v=line.split(":",1); out[k.strip().lower().replace(" ","-")]=v.strip()
    return out


def _yes(value):
    return str(value or "").strip().lower() in {"yes","true","enabled"}


def collect(router_id:int):
    migrations.migrate()
    with core.db() as conn:
        r=conn.execute("SELECT id,site_name,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",(router_id,)).fetchone()
    if not r or not r["enabled"] or (r["lifecycle_state"] or "production")=="retired": return None

    raw={}
    for key,cmd in COMMANDS:
        try: raw[key]=router_exec.read(r["vpn_ip"],cmd,timeout=30,label=f"Security audit: {key}")
        except Exception as exc: raw[key]=f"ERROR: {exc}"

    findings=[]
    def add(title,status,evidence):
        findings.append({"title":title,"status":status,"evidence":evidence})

    services=_parse_rows(raw["services"])
    for s in services:
        name=s.get("name","")
        disabled=_yes(s.get("disabled"))
        address=(s.get("address") or "").strip()
        if disabled:
            add(f"IP service {name} disabled","pass",f"address={address or '-'}")
            continue
        restricted=bool(address) and address not in {"0.0.0.0/0","::/0"}
        managed_hint=any(x in address for x in MANAGED_ADDRESS_HINTS)
        if name in SAFE_SERVICE_NAMES and restricted and managed_hint:
            add(f"IP service {name} restricted","pass",f"address={address}")
        elif not restricted:
            add(f"IP service {name} enabled without address restriction","critical",f"port={s.get('port','-')} address={address or 'any'}")
        else:
            add(f"IP service {name} enabled with non-Tikcentral restriction","warning",f"address={address}")

    for key,label in (("mac_server","MAC server"),("mac_winbox","MAC WinBox")):
        kv=_kv(raw[key]); allowed=kv.get("allowed-interface-list","")
        if allowed.lower() in {"none","!none"}:
            add(f"{label} disabled/restricted","pass",f"allowed-interface-list={allowed}")
        else:
            add(f"{label} review","warning",f"allowed-interface-list={allowed or 'unknown'}")

    kv=_kv(raw["neighbor"]); discover=kv.get("discover-interface-list","")
    add("Neighbor discovery interface scope","pass" if discover.lower() in {"none","!none"} else "warning",f"discover-interface-list={discover or 'unknown'}")

    kv=_kv(raw["bandwidth"]); enabled=_yes(kv.get("enabled"))
    add("Bandwidth server","warning" if enabled else "pass",f"enabled={kv.get('enabled','unknown')}")

    for key,label in (("socks","SOCKS proxy"),("proxy","Web proxy"),("snmp","SNMP")):
        kv=_kv(raw[key]); enabled=_yes(kv.get("enabled"))
        add(label,"warning" if enabled else "pass",f"enabled={kv.get('enabled','unknown')}")

    critical=sum(1 for x in findings if x["status"]=="critical")
    warning=sum(1 for x in findings if x["status"]=="warning")
    passed=sum(1 for x in findings if x["status"]=="pass")
    status="critical" if critical else ("warning" if warning else "pass")
    fp=hashlib.sha256(json.dumps(findings,sort_keys=True).encode()).hexdigest()
    checked=_now()
    with core.db() as conn:
        prev=conn.execute("SELECT status,fingerprint FROM router_security_audit WHERE router_id=?",(router_id,)).fetchone()
        conn.execute(
            """INSERT INTO router_security_audit(router_id,checked_at,status,critical_count,warning_count,passed_count,details_json,fingerprint)
               VALUES(?,?,?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET checked_at=excluded.checked_at,status=excluded.status,
                 critical_count=excluded.critical_count,warning_count=excluded.warning_count,passed_count=excluded.passed_count,
                 details_json=excluded.details_json,fingerprint=excluded.fingerprint""",
            (router_id,checked,status,critical,warning,passed,json.dumps(findings,ensure_ascii=False),fp),
        )
    if prev and prev["fingerprint"] != fp:
        events.record(router_id,"security-audit",f"Security exposure audit changed: {prev['status']} → {status}",
                      f"critical={critical}; warning={warning}; pass={passed}",
                      "critical" if critical else ("warning" if warning else "info"))
    return {"status":status,"critical":critical,"warning":warning,"passed":passed,"findings":findings}


def register(app,page_func):
    @app.get("/security-audit/{router_id}",response_class=HTMLResponse)
    def page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        try: collect(router_id)
        except Exception: pass
        with core.db() as conn:
            r=conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?",(router_id,)).fetchone()
            a=conn.execute("SELECT * FROM router_security_audit WHERE router_id=?",(router_id,)).fetchone()
        if not r:return RedirectResponse("/operations",303)
        details=json.loads(a["details_json"]) if a and a["details_json"] else []
        rows="".join(
            f'<tr><td>{html.escape(x["status"])}</td><td><strong>{html.escape(x["title"])}</strong></td><td>{html.escape(x["evidence"])}</td></tr>'
            for x in details
        ) or '<tr><td colspan="3">No audit data.</td></tr>'
        body=f'''<div class="panel pad"><h2>Security exposure · {html.escape(r["site_name"])}</h2>
<div class="muted">Read-only audit. Tikcentral reports enabled/reachable management surfaces but does not disable services automatically.</div></div>
<div class="panel"><table><thead><tr><th>Status</th><th>Check</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></div>'''
        return page_func("Security Exposure",body,user,"operations")
