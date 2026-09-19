"""Web SSH routes for individual routers.

Arbitrary submitted RouterOS commands are treated as serialized mutations: they
are attempted once and recorded in the unified router job lifecycle.
"""

import html

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import change_control
from app import errors
from app import jobs
from app import operations
from app import object_protection
from app import main as core
from app import router_exec
from app import ui

app = core.app


def _admin(request: Request):
    return core.require_web_admin(request)


@app.get("/ssh", response_class=HTMLResponse)
def ssh_router_list(request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with core.db() as conn:
        routers = conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled,lifecycle_state FROM routers ORDER BY site_name COLLATE NOCASE,id"
        ).fetchall()
    rows = "".join(
        f'''<tr><td>{html.escape(r['site_name'])}</td><td>{html.escape(r['identity'] or '-')}</td><td>{html.escape(r['model'] or '-')}</td><td><code>{html.escape(r['vpn_ip'])}</code></td><td>{'Retired' if (r['lifecycle_state'] or 'production')=='retired' else ('Enabled' if r['enabled'] else 'Disabled')}</td><td><a href="/ssh/{r['id']}"><button {'disabled' if (not r['enabled'] or (r['lifecycle_state'] or 'production')=='retired') else ''}>Open SSH console</button></a></td></tr>'''
        for r in routers
    ) or '<tr><td colspan="6">No routers enrolled.</td></tr>'
    body = f'''<div class="panel pad"><h2>Web SSH</h2><div class="muted">Commands run from the Tikcentral VPS over the private WireGuard address. Because arbitrary RouterOS commands may change state, they are serialized and never automatically retried.</div></div><div class="panel"><table><thead><tr><th>Site</th><th>Identity</th><th>Model</th><th>VPN IP</th><th>State</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>'''
    return ui.page("SSH", body, user, "ssh")


@app.get("/ssh/{router_id}", response_class=HTMLResponse)
def ssh_console(router_id: int, request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with core.db() as conn:
        router = conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,public_key,enabled,lifecycle_state FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()
    if not router or not router["enabled"] or (router["lifecycle_state"] or "production") == "retired":
        raise HTTPException(status_code=404, detail="active router not found")
    csrf = core.csrf_token(request)
    body = f'''<div class="panel pad"><h2>SSH — {html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['identity'] or '')} · {html.escape(router['model'] or '')} · <code>{html.escape(router['vpn_ip'])}</code></div><form method="post" action="/ssh/{router_id}" style="margin-top:16px"><input type="hidden" name="csrf" value="{csrf}"><textarea name="command" style="width:100%;min-height:100px" placeholder="/system resource print" required></textarea>
<div class="panel pad" style="margin-top:12px;background:var(--surface2)">
<label><input type="checkbox" name="override_degraded" value="1"> Allow this command while Guardian is degraded</label>
<div class="muted" style="margin-top:5px">Use only when necessary. WireGuard and SSH must still be reachable, and the override is logged as critical.</div>
<input name="override_reason" maxlength="240" placeholder="Required reason when overriding degraded-access protection" style="width:100%;margin-top:8px">
</div>
<div class="inline" style="margin-top:10px"><button class="primary">Run command</button><a href="/ssh">Back to routers</a></div></form></div>'''
    return ui.page("SSH Console", body, user, "ssh")


@app.post("/ssh/{router_id}", response_class=HTMLResponse)
async def ssh_console_run(router_id: int, request: Request):
    user = _admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await core.form_data(request)
    core.require_csrf(request, data.get("csrf", ""))
    command = data.get("command", "").strip()
    if not command:
        raise HTTPException(status_code=400, detail="command required")
    matches = object_protection.protected_matches(router_id, command)
    if matches:
        names = ", ".join(f'{m["object_type"]}:{m["selector"]}' for m in matches[:8])
        raise HTTPException(status_code=409, detail=f"command blocked by protected object rule(s): {names}")
    with core.db() as conn:
        router = conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled,lifecycle_state FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()
    if not router or not router["enabled"]:
        raise HTTPException(status_code=404, detail="enabled router not found")

    actor = user["email"] if "email" in user.keys() else "admin"
    override_degraded = str(data.get("override_degraded", "")) == "1"
    override_reason = str(data.get("override_reason", ""))[:240]
    tx_id = None
    try:
        pre_access = change_control.authorize_mutation(
            router,
            "Web SSH command",
            actor=actor,
            override_degraded=override_degraded,
            override_reason=override_reason,
        )
        with jobs.operation(
            router_id,
            "web_ssh",
            actor,
            target="manual RouterOS command",
            serialize_router=True,
            fail_code="WEB_SSH_FAILED",
            fail_message="Web SSH command failed",
        ) as job_id:
            tx_id = change_control.begin(router_id, "web_ssh", actor, job_id=job_id, pre_access=pre_access)
            if override_degraded:
                change_control.step(tx_id, "preflight", "warning", "Degraded-access protection explicitly overridden", override_reason)
            change_control.step(tx_id, "backup", "info", "Creating retained pre-command backup")
            operations.backup_router(router_id, "pre-change", actor, track_job=False)
            change_control.step(tx_id, "backup", "ok", "Pre-command backup completed")
            change_control.step(tx_id, "apply", "info", "Executing manual RouterOS command")
            output = router_exec.mutate(router["vpn_ip"], command, timeout=90, label="Web SSH command")
            jobs.verifying(job_id)
            verified = change_control.verify_management(router, "Web SSH command", transaction_id=tx_id)
            change_control.finish(tx_id, post_access=verified)
        status = "Success"
    except Exception as exc:
        if tx_id is not None:
            try:
                change_control.fail(tx_id, exc)
            except Exception:
                pass
        output = errors.short(exc)
        status = "Error"

    csrf = core.csrf_token(request)
    body = f'''<div class="panel pad"><h2>SSH — {html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['identity'] or '')} · <code>{html.escape(router['vpn_ip'])}</code></div><div style="margin-top:14px"><strong>{status}</strong></div><pre style="white-space:pre-wrap;padding:14px;border-radius:8px;max-height:520px;overflow:auto">{html.escape(output or '(no output)')}</pre><form method="post" action="/ssh/{router_id}"><input type="hidden" name="csrf" value="{csrf}"><textarea name="command" style="width:100%;min-height:100px" placeholder="Next RouterOS command" required></textarea>
<div class="panel pad" style="margin-top:12px;background:var(--surface2)">
<label><input type="checkbox" name="override_degraded" value="1"> Allow this command while Guardian is degraded</label>
<input name="override_reason" maxlength="240" placeholder="Required reason when overriding degraded-access protection" style="width:100%;margin-top:8px">
</div>
<div class="inline" style="margin-top:10px"><button class="primary">Run command</button><a href="/ssh">Back to routers</a></div></form></div>'''
    return ui.page("SSH Console", body, user, "ssh")
