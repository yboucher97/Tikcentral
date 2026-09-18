"""Tikcentral production ASGI entrypoint.

Routes are registered directly on one FastAPI app. There are no renderer or
route monkey-patch layers in the production runtime.
"""

import html
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# Import route modules once; their decorators register directly on core.app.
from app import ai_analysis
from app import automation_inventory
from app import changes
from app import change_calendar
from app import capacity_forecast
from app import certificate_monitor
from app import compliance
from app import change_control
from app import change_preview
from app import enrollment
from app import errors
from app import events
from app import fleet_explorer
from app import fleet_web  # noqa: F401
from app import guardian
from app import hardware_inventory
from app import interface_monitor
from app import lifecycle
from app import jobs
from app import lte_monitor
from app import main as core
from app import maintenance_history
from app import management_script
from app import object_protection
from app import operations
from app import operator_audit
from app import operator_notes
from app import portal  # noqa: F401
from app import production  # noqa: F401
from app import diagnostics
from app import desired_state
from app import customer_reports
from app import rescue
from app import security_audit
from app import recovery_browser
from app import reliability
from app import role_access
from app import router_exec
from app import site_metadata
from app import system_health
from app import topology
from app import traffic_monitor
from app import troubleshooting
from app import upgrade_campaigns
from app import wan_probe
from app import ui

app = core.app

STATIC_DIR = Path(__file__).with_name("static")
if not any(getattr(route, "path", None) == "/static" for route in app.routes):
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _admin(request: Request):
    return core.require_web_admin(request)


def _router(router_id: int):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,public_key,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


# RouterOS hides sensitive values from /export by default. `show-sensitive` is
# a flag that enables secrets, not a boolean option. Passing an explicit false value is invalid
# RouterOS syntax and must not be used here.
AUDIT_COMMAND = '''/system resource print; /system identity print; /ip service print; /user print; /user ssh-keys print; /interface/wireguard print; /interface/wireguard/peers print; /ip/address print where interface="opticable-wg"; /ip/route print where comment~"Tikcentral"; /ip/firewall/filter print detail where comment~"Tikcentral"; /ip/firewall/nat print detail where comment~"Tikcentral"; /export'''


@app.get("/audit", response_class=HTMLResponse)
def audit_index(request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with core.db() as conn:
        routers = conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled FROM routers ORDER BY site_name COLLATE NOCASE,id"
        ).fetchall()
    rows = "".join(
        f'''<tr><td>{html.escape(r['site_name'])}</td><td>{html.escape(r['identity'] or '-')}</td><td>{html.escape(r['model'] or '-')}</td><td><code>{html.escape(r['vpn_ip'])}</code></td><td>{'Enabled' if r['enabled'] else 'Disabled'}</td><td><a href="/audit/{r['id']}"><button {'disabled' if not r['enabled'] else ''}>Audit configuration</button></a></td></tr>'''
        for r in routers
    ) or '<tr><td colspan="6">No routers enrolled.</td></tr>'
    body = f'''<div class="panel pad"><h2>Router Audit</h2><div class="muted">Live read-only audit over WireGuard. RouterOS export uses its default secret-redaction behavior.</div></div><div class="panel"><table><thead><tr><th>Site</th><th>Identity</th><th>Model</th><th>VPN IP</th><th>State</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>'''
    return ui.page("Audit", body, user, "audit")


@app.get("/audit/{router_id}", response_class=HTMLResponse)
def audit_router(router_id: int, request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    router = _router(router_id)
    if not router or not router["enabled"]:
        return RedirectResponse("/audit", status_code=303)
    try:
        output = router_exec.read(router["vpn_ip"], AUDIT_COMMAND, timeout=120, label="Router audit")
        status = "Audit completed"
    except Exception as exc:
        output = errors.short(exc)
        status = "Audit failed"
    csrf = core.csrf_token(request)
    body = f'''<div class="panel pad"><h2>{html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['identity'] or '')} · {html.escape(router['model'] or '')} · <code>{html.escape(router['vpn_ip'])}</code></div><div style="margin-top:12px"><strong>{html.escape(status)}</strong></div><div class="inline" style="margin-top:12px"><button type="button" onclick="tcCopyAudit(this)">Copy audit output</button><form method="post" action="/audit/{router_id}/normalize"><input type="hidden" name="csrf" value="{csrf}"><button class="primary" onclick="return confirm('Normalize only Tikcentral-owned management firewall rules? Tikcentral will take a pre-change backup, replace only rules carrying Tikcentral management comments, then verify management access.')">Normalize Tikcentral rules</button></form><a href="/audit"><button>Back</button></a></div><div class="muted" style="margin-top:10px">Normalize replaces only Tikcentral-owned management firewall rules with the canonical access rules. It does not intentionally modify unrelated customer firewall rules.</div></div><div class="panel pad"><pre id="audit-output" style="white-space:pre-wrap;max-height:75vh;overflow:auto;user-select:text">{html.escape(output or '(no output)')}</pre></div><script>
async function tcCopyAudit(button) {{
  const el = document.getElementById('audit-output');
  const text = el ? el.innerText : '';
  const original = button.textContent;
  try {{
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
  }} catch (err) {{
    const range = document.createRange();
    range.selectNodeContents(el);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    try {{ document.execCommand('copy'); button.textContent = 'Copied'; }}
    catch (copyErr) {{ button.textContent = 'Select output and copy'; }}
    selection.removeAllRanges();
  }}
  setTimeout(() => {{ button.textContent = original; }}, 1800);
}}
</script>'''
    return ui.page("Router Audit", body, user, "audit")


@app.post("/audit/{router_id}/normalize", response_class=HTMLResponse)
async def normalize_router(router_id: int, request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request)
    core.require_csrf(request, data.get("csrf", ""))
    router = _router(router_id)
    if not router or not router["enabled"]:
        return RedirectResponse("/audit", status_code=303)
    actor = user["email"] if "email" in user.keys() else "admin"
    tx_id = None
    try:
        preflight = change_control.require_management(router, "Tikcentral rule normalization")
        with jobs.operation(
            router_id,
            "audit_normalize",
            actor,
            serialize_router=True,
            fail_code="AUDIT_NORMALIZE_FAILED",
            fail_message="Tikcentral rule normalization failed",
        ) as job_id:
            tx_id = change_control.begin(router_id, "audit_normalize", actor, job_id=job_id, pre_access=preflight)
            change_control.step(tx_id, "backup", "info", "Creating retained pre-change backup")
            operations.backup_router(router_id, "pre-change", actor, track_job=False)
            change_control.step(tx_id, "backup", "ok", "Pre-change backup completed")
            change_control.step(tx_id, "apply", "info", "Reconciling Tikcentral-owned management firewall rules")
            normalize_command = management_script.firewall_reconcile_command(include_print=True)
            protected = object_protection.protected_matches(router_id, normalize_command)
            if protected:
                names = ", ".join(f'{p["object_type"]}:{p["selector"]}' for p in protected[:8])
                raise errors.OperationError("PROTECTED_OBJECT", "Normalization blocked by protected object rule", names, severity="critical")
            output = router_exec.mutate(
                router["vpn_ip"],
                normalize_command,
                timeout=90,
                label="Tikcentral rule normalization",
            )
            jobs.verifying(job_id)
            verified = change_control.verify_management(router, "Tikcentral rule normalization", transaction_id=tx_id)
            change_control.step(tx_id, "verify", "ok", "Management access verified after normalization")
            change_control.finish(tx_id, post_access=verified)
        events.record(router_id, "audit", "Tikcentral management rules normalized", output[-800:])
        return RedirectResponse(f"/audit/{router_id}", status_code=303)
    except Exception as exc:
        if tx_id is not None:
            try:
                change_control.fail(tx_id, exc, post_access=guardian.probe_router(router))
            except Exception:
                pass
        err = errors.from_exception(exc)
        event_detail = f"{err.code}: {err.message}" + (f" — {err.detail}" if err.detail else "")
        events.record(router_id, "audit", "Tikcentral rule normalization failed", event_detail, err.severity)
        body = f'''<div class="panel pad"><h2>Normalization not completed</h2><div class="error"><strong>{html.escape(err.code)}</strong><div>{html.escape(err.message)}</div><div class="muted">{html.escape(err.detail)}</div></div><div style="margin-top:12px"><a href="/guardian"><button>Open Access Guardian</button></a> <a href="/audit/{router_id}"><button class="primary">Back to audit</button></a></div></div>'''
        return ui.page("Audit", body, user, "audit")


# Feature modules without decorator-time routes register exactly once here.
guardian.register(app, ui.page)
operations.register(app, ui.page)
rescue.register(app, ui.page)
reliability.register(app, ui.page)
system_health.register(app, ui.page)
fleet_explorer.register(app, ui.page)
operator_audit.register(app, ui.page)
changes.register(app, ui.page)
change_calendar.register(app, ui.page)
certificate_monitor.register(app, ui.page)
capacity_forecast.register(app, ui.page)
operator_notes.register(app, ui.page)
customer_reports.register(app, ui.page)
security_audit.register(app, ui.page)
automation_inventory.register(app, ui.page)
traffic_monitor.register(app, ui.page)
topology.register(app, ui.page)
wan_probe.register(app, ui.page)
desired_state.register(app, ui.page)
hardware_inventory.register(app, ui.page)
compliance.register(app, ui.page)
lte_monitor.register(app, ui.page)
interface_monitor.register(app, ui.page)
site_metadata.register(app, ui.page)
lifecycle.register(app, ui.page)
maintenance_history.register(app, ui.page)
upgrade_campaigns.register(app, ui.page)
object_protection.register(app, ui.page)
diagnostics.register(app, ui.page)
recovery_browser.register(app, ui.page)
enrollment.register(app, ui.page)
ai_analysis.register(app, ui.page)
troubleshooting.register(app, ui.page)
operator_audit.install_middleware(app)
change_preview.install_middleware(app)
role_access.install_middleware(app)
