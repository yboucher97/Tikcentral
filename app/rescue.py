"""Static local rescue-port management.

No RouterOS Netwatch/scheduler scripts are installed. Rescue changes are explicit,
backed up first and blocked when an interface is already in use.
"""

import html

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import errors
from app import events
from app import guardian
from app import interface_choices
from app import jobs
from app import main as core
from app import migrations
from app import operations
from app import router_exec
from app import settings


def ensure_schema():
    migrations.migrate()


def _router(router_id):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,model,vpn_ip,public_key,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _markers(output):
    data = {}
    for line in (output or "").splitlines():
        if line.startswith("TC|"):
            parts = line.split("|", 2)
            if len(parts) == 3:
                data[parts[1]] = parts[2].strip()
    return data


def _require_router(router_id):
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise errors.OperationError("ROUTER_NOT_FOUND", "Enabled router not found")
    return router


def enable_rescue(router_id: int, interface: str, created_by: str):
    ensure_schema()
    if interface not in interface_choices.INTERFACE_SET:
        raise errors.OperationError("INVALID_INTERFACE", "Invalid rescue interface")
    router = _require_router(router_id)
    if not guardian.probe_router(router)["management_ok"]:
        raise errors.OperationError("GUARDIAN_UNHEALTHY", "Guardian access preflight failed; rescue change blocked")
    job_id = jobs.create(router_id, "rescue_enable", created_by, interface, serialize_router=True)
    jobs.running(job_id)
    try:
        check = router_exec.read(
            router["vpn_ip"],
            f':put ("TC|addresses|" . [/ip/address print count-only where interface={interface} comment!="Tikcentral rescue address"]); '
            f':put ("TC|dhcp_server|" . [/ip/dhcp-server print count-only where interface={interface} name!="Tikcentral-Rescue-DHCP"]); '
            f':put ("TC|dhcp_client|" . [/ip/dhcp-client print count-only where interface={interface}]); '
            f':put ("TC|pppoe|" . [/interface/pppoe-client print count-only where interface={interface}]); '
            f':put ("TC|vlans|" . [/interface/vlan print count-only where interface={interface}]); '
            f':put ("TC|bridge_ports|" . [/interface/bridge/port print count-only where interface={interface}]); '
            f':put ("TC|wan_member|" . [/interface/list/member print count-only where interface={interface} list=WAN])',
            timeout=30,
            label="Rescue interface safety check",
        )
        m = _markers(check)
        blockers = {
            "IP address": int(m.get("addresses", "0") or 0),
            "DHCP server": int(m.get("dhcp_server", "0") or 0),
            "DHCP client": int(m.get("dhcp_client", "0") or 0),
            "PPPoE client": int(m.get("pppoe", "0") or 0),
            "VLAN parent": int(m.get("vlans", "0") or 0),
            "bridge membership": int(m.get("bridge_ports", "0") or 0),
            "WAN membership": int(m.get("wan_member", "0") or 0),
        }
        active = [name for name, count in blockers.items() if count > 0]
        if active:
            raise errors.OperationError("INTERFACE_IN_USE", f"{interface} is already in use", ", ".join(active))
        operations.backup_router(router_id, "pre-change", created_by, track_job=False)
        command = f'''
/ip/dhcp-server remove [find where name="Tikcentral-Rescue-DHCP"];
/ip/dhcp-server/network remove [find where comment="Tikcentral rescue network"];
/ip/pool remove [find where name="Tikcentral-Rescue-Pool"];
/ip/address remove [find where comment="Tikcentral rescue address"];
/interface/list/member remove [find where comment="Tikcentral rescue LAN membership"];
:if ([:len [/interface/list/member find where interface={interface} list=LAN]] = 0) do={{ /interface/list/member add interface={interface} list=LAN comment="Tikcentral rescue LAN membership" }};
/ip/address add address={settings.RESCUE_ADDRESS} interface={interface} comment="Tikcentral rescue address";
/ip/pool add name="Tikcentral-Rescue-Pool" ranges={settings.RESCUE_POOL};
/ip/dhcp-server/network add address={settings.RESCUE_NETWORK} gateway={settings.RESCUE_GATEWAY} dns-server={settings.RESCUE_DNS} comment="Tikcentral rescue network";
/ip/dhcp-server add name="Tikcentral-Rescue-DHCP" interface={interface} address-pool="Tikcentral-Rescue-Pool" disabled=no;
:put "Tikcentral local rescue port enabled on {interface}"
'''.strip()
        output = router_exec.mutate(router["vpn_ip"], command, timeout=60, label="Enable rescue port")
        jobs.verifying(job_id)
        if not guardian.probe_router(router)["management_ok"]:
            raise errors.OperationError("ACCESS_VERIFY_FAILED", "Rescue port changed but management verification failed", severity="critical")
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_rescue_ports(router_id,enabled,interface,address,updated_at)
                   VALUES(?,1,?,?,?) ON CONFLICT(router_id) DO UPDATE SET
                   enabled=1,interface=excluded.interface,address=excluded.address,updated_at=excluded.updated_at""",
                (router_id, interface, settings.RESCUE_ADDRESS, operations.now_iso()),
            )
        jobs.succeeded(job_id)
        events.record(
            router_id,
            "rescue",
            f"Static local rescue port enabled on {interface}",
            f"{settings.RESCUE_ADDRESS} · network {settings.RESCUE_NETWORK} · DHCP {settings.RESCUE_POOL} · DNS {settings.RESCUE_DNS}",
        )
        return output
    except Exception as exc:
        jobs.failed(job_id, exc, code="RESCUE_ENABLE_FAILED", message="Enable rescue port failed")
        raise


def disable_rescue(router_id: int, created_by: str):
    ensure_schema()
    router = _require_router(router_id)
    if not guardian.probe_router(router)["management_ok"]:
        raise errors.OperationError("GUARDIAN_UNHEALTHY", "Guardian access preflight failed; rescue change blocked")
    job_id = jobs.create(router_id, "rescue_disable", created_by, serialize_router=True)
    jobs.running(job_id)
    try:
        operations.backup_router(router_id, "pre-change", created_by, track_job=False)
        command = r'''
/ip/dhcp-server remove [find where name="Tikcentral-Rescue-DHCP"];
/ip/dhcp-server/network remove [find where comment="Tikcentral rescue network"];
/ip/pool remove [find where name="Tikcentral-Rescue-Pool"];
/ip/address remove [find where comment="Tikcentral rescue address"];
/interface/list/member remove [find where comment="Tikcentral rescue LAN membership"];
:put "Tikcentral local rescue port disabled"
'''.strip()
        output = router_exec.mutate(router["vpn_ip"], command, timeout=60, label="Disable rescue port")
        jobs.verifying(job_id)
        if not guardian.probe_router(router)["management_ok"]:
            raise errors.OperationError("ACCESS_VERIFY_FAILED", "Rescue port disabled but management verification failed", severity="critical")
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_rescue_ports(router_id,enabled,interface,address,updated_at)
                   VALUES(?,0,'',?,?) ON CONFLICT(router_id) DO UPDATE SET enabled=0,interface='',updated_at=excluded.updated_at""",
                (router_id, settings.RESCUE_ADDRESS, operations.now_iso()),
            )
        jobs.succeeded(job_id)
        events.record(router_id, "rescue", "Static local rescue port disabled")
        return output
    except Exception as exc:
        jobs.failed(job_id, exc, code="RESCUE_DISABLE_FAILED", message="Disable rescue port failed")
        raise


def _actor(user):
    try:
        return user["email"]
    except Exception:
        return "admin"


def _error_page(page_func, user, router_id: int, title: str, exc):
    err = errors.from_exception(exc)
    try:
        events.record(router_id, "rescue", f"{title} failed", f"{err.code}: {err.detail}", err.severity)
    except Exception:
        pass
    body = f'''<div class="panel pad"><h2>{html.escape(title)}</h2><div class="error"><strong>{html.escape(err.code)}</strong><div style="margin-top:6px">{html.escape(err.message)}</div>{f'<div class="muted" style="margin-top:6px">{html.escape(err.detail)}</div>' if err.detail else ''}</div><div style="margin-top:14px"><a href="/rescue"><button class="primary">Back to Rescue</button></a></div></div>'''
    return page_func("Rescue", body, user, "rescue")


def register(app, page_func):
    ensure_schema()

    @app.get("/rescue", response_class=HTMLResponse)
    def rescue_page(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        csrf = core.csrf_token(request)
        with core.db() as conn:
            rows = conn.execute(
                """SELECT r.id,r.site_name,r.model,r.vpn_ip,a.management_ok,
                          p.enabled rescue_enabled,p.interface rescue_interface,p.address rescue_address
                   FROM routers r LEFT JOIN router_access_state a ON a.router_id=r.id
                   LEFT JOIN router_rescue_ports p ON p.router_id=r.id
                   WHERE r.enabled=1 ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()
        body_rows = []
        for r in rows:
            options = interface_choices.options_html(r["rescue_interface"] or "ether5")
            enable = f'''<form method="post" action="/rescue/{r['id']}/enable" class="inline"><input type="hidden" name="csrf" value="{csrf}"><select name="interface">{options}</select><button>Enable / move rescue</button></form>'''
            disable = f'''<form method="post" action="/rescue/{r['id']}/disable" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><button class="danger" onclick="return confirm('Disable the static rescue port?')">Disable</button></form>'''
            status = f"Enabled · {r['rescue_interface']} · {r['rescue_address'] or settings.RESCUE_ADDRESS}" if r["rescue_enabled"] else "Disabled"
            body_rows.append(f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')} · {html.escape(r['vpn_ip'])}</div></td><td>{'Healthy' if r['management_ok'] else 'Degraded'}</td><td>{html.escape(status)}</td><td>{enable} {disable if r['rescue_enabled'] else ''}</td></tr>''')
        body = f'''<div class="panel pad"><h2>Local Rescue Ports</h2><div class="muted">Choices: ether1–ether10 and sfp-sfpplus1–sfp-sfpplus24. Tikcentral refuses interfaces already used by IP, DHCP, PPPoE, VLANs, bridge membership or WAN membership. Rescue uses {settings.RESCUE_ADDRESS}, network {settings.RESCUE_NETWORK}, DHCP {settings.RESCUE_POOL}, DNS {settings.RESCUE_DNS}. No RouterOS script/Netwatch is installed.</div></div><div class="panel"><table><thead><tr><th>Router</th><th>Access</th><th>Rescue</th><th>Action</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="4">No routers.</td></tr>'}</tbody></table></div>'''
        return page_func("Rescue Ports", body, user, "rescue")

    @app.post("/rescue/{router_id}/enable", response_class=HTMLResponse)
    async def rescue_enable(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        try:
            enable_rescue(router_id, data.get("interface", "ether5"), _actor(user))
        except Exception as exc:
            return _error_page(page_func, user, router_id, "Enable rescue port", exc)
        return RedirectResponse("/rescue", status_code=303)

    @app.post("/rescue/{router_id}/disable", response_class=HTMLResponse)
    async def rescue_disable(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        try:
            disable_rescue(router_id, _actor(user))
        except Exception as exc:
            return _error_page(page_func, user, router_id, "Disable rescue port", exc)
        return RedirectResponse("/rescue", status_code=303)
