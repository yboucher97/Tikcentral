"""Continuous golden-policy compliance for enrolled RouterOS devices."""

import html
import json
import re
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, router_exec


POLICY_COMMAND = r'''
:put ("TC|wg|" . [/interface/wireguard print count-only where name="opticable-wg"]);
:put ("TC|wg_peer|" . [/interface/wireguard/peers print count-only where interface="opticable-wg"]);
:put ("TC|wg_addr|" . [/ip/address print count-only where interface="opticable-wg"]);
:put ("TC|tikcentral_user|" . [/user print count-only where name="tikcentral" disabled=no]);
:put ("TC|tikcentral_key|" . [/user/ssh-keys print count-only where user="tikcentral"]);
:put ("TC|ssh|" . [/ip/service print count-only where name="ssh" disabled=no]);
:put ("TC|winbox|" . [/ip/service print count-only where name="winbox" disabled=no]);
:put ("TC|api|" . [/ip/service print count-only where name="api" disabled=no]);
:put ("TC|mgmt_tcp|" . [/ip/firewall/filter print count-only where comment="Tikcentral management TCP"]);
:put ("TC|admin_tcp|" . [/ip/firewall/filter print count-only where comment="Tikcentral admin TCP"]);
:put ("TC|admin_icmp|" . [/ip/firewall/filter print count-only where comment="Tikcentral admin ICMP"]);
:put ("TC|admin_user|" . [/user print count-only where name="admin" disabled=no]);
:put ("TC|dns_static|" . [/ip/dns get servers]);
:put ("TC|dns_dynamic|" . [/ip/dns get dynamic-servers]);
:do { :put ("TC|ntp|" . [/system/ntp/client get enabled]) } on-error={ :put "TC|ntp|unknown" };
'''.strip()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _router(router_id):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _markers(raw: str) -> dict[str, str]:
    out = {}
    for name, value in re.findall(r"(?m)^TC\|([^|]+)\|([^\r\n]*)", raw or ""):
        out[name.strip()] = value.strip()
    return out


def _count(markers, name):
    try:
        return int(markers.get(name, "0") or "0")
    except ValueError:
        return 0


def evaluate(router_id: int):
    migrations.migrate()
    router = _router(router_id)
    if not router or not router["enabled"] or (router["lifecycle_state"] or "production")=="retired":
        return None
    raw = router_exec.read(router["vpn_ip"], POLICY_COMMAND, timeout=35, label="Golden policy compliance")
    m = _markers(raw)
    checks = []

    def check(key, title, ok, *, warning=False, evidence=""):
        status = "pass" if ok else ("warning" if warning else "fail")
        checks.append({"key": key, "title": title, "status": status, "evidence": str(evidence or "")})

    check("wireguard", "Tikcentral WireGuard interface exists", _count(m,"wg") == 1, evidence=m.get("wg"))
    check("wireguard_peer", "Tikcentral WireGuard peer exists", _count(m,"wg_peer") >= 1, evidence=m.get("wg_peer"))
    check("wireguard_address", "Management VPN address exists", _count(m,"wg_addr") >= 1, evidence=m.get("wg_addr"))
    check("tikcentral_user", "Tikcentral service account is enabled", _count(m,"tikcentral_user") == 1, evidence=m.get("tikcentral_user"))
    check("tikcentral_key", "Tikcentral SSH key is installed", _count(m,"tikcentral_key") >= 1, evidence=m.get("tikcentral_key"))
    check("ssh", "SSH management service is enabled", _count(m,"ssh") == 1, evidence=m.get("ssh"))
    check("winbox", "WinBox management service is enabled", _count(m,"winbox") == 1, evidence=m.get("winbox"))
    check("api", "RouterOS API management service is enabled", _count(m,"api") == 1, evidence=m.get("api"))
    check("mgmt_tcp", "Canonical Tikcentral management firewall rule exists", _count(m,"mgmt_tcp") == 1, evidence=m.get("mgmt_tcp"))
    check("admin_tcp", "Canonical admin TCP firewall rule exists", _count(m,"admin_tcp") == 1, evidence=m.get("admin_tcp"))
    check("admin_icmp", "Canonical admin ICMP firewall rule exists", _count(m,"admin_icmp") == 1, evidence=m.get("admin_icmp"))

    dns_ok = bool((m.get("dns_static") or "").strip() or (m.get("dns_dynamic") or "").strip())
    check("dns", "Router has DNS servers available", dns_ok, warning=True,
          evidence=f'static={m.get("dns_static","")} dynamic={m.get("dns_dynamic","")}')
    ntp = (m.get("ntp") or "").lower()
    check("ntp", "NTP client is enabled", ntp in {"true","yes"}, warning=True, evidence=ntp or "unknown")
    admin_active = _count(m,"admin_user")
    check("default_admin", "Default admin account is not active", admin_active == 0, warning=True,
          evidence=f"active admin accounts named admin={admin_active}")

    passed = sum(1 for x in checks if x["status"] == "pass")
    warnings = sum(1 for x in checks if x["status"] == "warning")
    failed = sum(1 for x in checks if x["status"] == "fail")
    status = "fail" if failed else ("warning" if warnings else "pass")
    checked = _now()

    with core.db() as conn:
        previous = conn.execute("SELECT status FROM router_policy_compliance WHERE router_id=?", (router_id,)).fetchone()
        conn.execute(
            """INSERT INTO router_policy_compliance(router_id,checked_at,status,passed,warnings,failed,details_json)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(router_id) DO UPDATE SET checked_at=excluded.checked_at,status=excluded.status,
                 passed=excluded.passed,warnings=excluded.warnings,failed=excluded.failed,details_json=excluded.details_json""",
            (router_id,checked,status,passed,warnings,failed,json.dumps(checks,ensure_ascii=False)),
        )
    if previous and previous["status"] != status:
        events.record(router_id,"compliance",f"Golden-policy compliance changed: {previous['status']} → {status}",
                      f"passed={passed}; warnings={warnings}; failed={failed}",
                      "warning" if status != "pass" else "info")
    return {"status":status,"passed":passed,"warnings":warnings,"failed":failed,"checks":checks,"checked_at":checked}


def register(app, page_func):
    migrations.migrate()

    @app.get("/compliance", response_class=HTMLResponse)
    def compliance_index(request: Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        with core.db() as conn:
            rows=conn.execute(
                """SELECT r.id,r.site_name,r.model,r.vpn_ip,c.checked_at,c.status,c.passed,c.warnings,c.failed
                   FROM routers r LEFT JOIN router_policy_compliance c ON c.router_id=r.id
                   WHERE r.enabled=1 ORDER BY r.site_name COLLATE NOCASE"""
            ).fetchall()
        body_rows="".join(
            f'<tr><td><strong>{html.escape(r["site_name"])}</strong><div class="muted">{html.escape(r["model"] or "")} · <code>{html.escape(r["vpn_ip"])}</code></div></td>'
            f'<td>{html.escape(r["status"] or "not checked")}</td><td>{r["passed"] or 0}</td><td>{r["warnings"] or 0}</td><td>{r["failed"] or 0}</td>'
            f'<td>{html.escape(r["checked_at"] or "")}</td><td><a href="/compliance/{r["id"]}">Details</a></td></tr>'
            for r in rows
        ) or '<tr><td colspan="7">No routers.</td></tr>'
        body=f'''<div class="panel pad"><h2>Golden-policy compliance</h2><div class="muted">Continuous read-only checks for Tikcentral management, security and basic resolver/time hygiene.</div></div>
<div class="panel"><table><thead><tr><th>Router</th><th>Status</th><th>Pass</th><th>Warnings</th><th>Fail</th><th>Checked</th><th></th></tr></thead><tbody>{body_rows}</tbody></table></div>'''
        return page_func("Compliance",body,user,"operations")

    @app.get("/compliance/{router_id}", response_class=HTMLResponse)
    def compliance_router(router_id:int, request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        router=_router(router_id)
        if not router: return RedirectResponse("/compliance",303)
        try:
            result=evaluate(router_id)
        except Exception:
            result=None
        with core.db() as conn:
            row=conn.execute("SELECT * FROM router_policy_compliance WHERE router_id=?",(router_id,)).fetchone()
        checks=json.loads(row["details_json"]) if row and row["details_json"] else []
        rendered="".join(
            f'<tr><td>{html.escape(x["status"])}</td><td><strong>{html.escape(x["title"])}</strong></td><td class="muted">{html.escape(x.get("evidence",""))}</td></tr>'
            for x in checks
        ) or '<tr><td colspan="3">Compliance data unavailable.</td></tr>'
        body=f'''<div class="panel pad"><h2>Compliance · {html.escape(router["site_name"])}</h2>
<div class="muted">{html.escape(router["model"] or "")} · <code>{html.escape(router["vpn_ip"])}</code> · last checked {html.escape(row["checked_at"] if row else "")}</div>
<div class="inline" style="margin-top:12px"><a href="/operations/{router_id}"><button>Back to router</button></a><a href="/compliance"><button>Fleet compliance</button></a></div></div>
<div class="panel"><table><thead><tr><th>Status</th><th>Check</th><th>Evidence</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Compliance",body,user,"operations")
