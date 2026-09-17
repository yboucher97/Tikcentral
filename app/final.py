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
from app import changes
from app import enrollment
from app import errors
from app import events
from app import fleet_web  # noqa: F401
from app import guardian
from app import jobs
from app import main as core
from app import management_script
from app import operations
from app import portal  # noqa: F401
from app import production  # noqa: F401
from app import rescue
from app import router_exec
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
# a flag that enables secrets, not a boolean option, so `show-sensitive=no` is
# invalid syntax on current RouterOS and must not be used here.
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
    try:
        preflight = guardian.probe_router(router)
        if not preflight["management_ok"]:
            raise errors.OperationError(
                "GUARDIAN_UNHEALTHY",
                "Guardian access preflight failed; normalization blocked",
                guardian.access_issue(preflight),
            )
        with jobs.operation(
            router_id,
            "audit_normalize",
            actor,
            serialize_router=True,
            fail_code="AUDIT_NORMALIZE_FAILED",
            fail_message="Tikcentral rule normalization failed",
        ) as job_id:
            operations.backup_router(router_id, "pre-change", actor, track_job=False)
            output = router_exec.mutate(
                router["vpn_ip"],
                management_script.firewall_reconcile_command(include_print=True),
                timeout=90,
                label="Tikcentral rule normalization",
            )
            jobs.verifying(job_id)
            verified = guardian.probe_router(router)
            if not verified["management_ok"]:
                raise errors.OperationError(
                    "ACCESS_VERIFY_FAILED",
                    "Rules normalized but management verification failed",
                    guardian.access_issue(verified),
                    severity="critical",
                )
        events.record(router_id, "audit", "Tikcentral management rules normalized", output[-800:])
        return RedirectResponse(f"/audit/{router_id}", status_code=303)
    except Exception as exc:
        err = errors.from_exception(exc)
        event_detail = f"{err.code}: {err.message}" + (f" — {err.detail}" if err.detail else "")
        events.record(router_id, "audit", "Tikcentral rule normalization failed", event_detail, err.severity)
        body = f'''<div class="panel pad"><h2>Normalization not completed</h2><div class="error"><strong>{html.escape(err.code)}</strong><div>{html.escape(err.message)}</div><div class="muted">{html.escape(err.detail)}</div></div><div style="margin-top:12px"><a href="/guardian"><button>Open Access Guardian</button></a> <a href="/audit/{router_id}"><button class="primary">Back to audit</button></a></div></div>'''
        return ui.page("Audit", body, user, "audit")


# Feature modules without decorator-time routes register exactly once here.
guardian.register(app, ui.page)
operations.register(app, ui.page)
rescue.register(app, ui.page)
changes.register(app, ui.page)
enrollment.register(app, ui.page)
ai_analysis.register(app, ui.page)
