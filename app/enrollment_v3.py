"""Enrollment UI v3 with expanded physical interface choices."""

import html
import secrets
from datetime import timedelta

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import enrollment_v2
from app import interface_choices
from app import main as core
from app import performance_profile
from app import portal
from app import provisioning
from app import ui_time

PROFILE_LABELS = enrollment_v2.PROFILE_LABELS
_apply_profile = enrollment_v2._apply_profile


def _page(page_func, user, csrf, message=""):
    username, password = provisioning.get_admin_credentials()
    configured = bool(username and password)
    note = f'<div class="panel pad" style="border-color:#355"><strong>{html.escape(message)}</strong></div>' if message else ""
    iface_options = interface_choices.options_html("ether2")
    body = f'''{note}
<div class="panel pad"><h2>Enroll / Provision MikroTik</h2>
<div class="muted">Use Tikcentral-only for an existing router, or fresh provisioning after RouterOS/RouterBOOT update and a no-defaults reset.</div>
<form method="post" action="/enroll/generate" style="margin-top:18px">
<input type="hidden" name="csrf" value="{csrf}">
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px">
<label>Mode<br><select name="mode" style="width:100%"><option value="enroll">Tikcentral only (existing router)</option><option value="default">Tikcentral + Opticable default config (fresh router)</option></select></label>
<label>Site identity<br><input name="site_name" maxlength="120" style="width:100%" placeholder="977-973 St-Faustin Mont-Blanc" required></label>
<label>Performance profile<br><select name="performance_profile" style="width:100%"><option value="throughput" selected>Maximum throughput (recommended E50)</option><option value="fairness">Fairness / QoS</option></select></label>
<label>Tenant VLAN count<br><input type="number" name="vlan_count" min="1" max="60" value="12" style="width:100%"></label>
<label>Active physical LANs<br><select name="lan_count" style="width:100%"><option>0</option><option>1</option><option>2</option><option>3</option><option selected>4</option></select></label>
<label>VLAN parent<br><select name="vlan_parent" style="width:100%">{iface_options}</select></label>
<label>WAN download Mbps<br><input type="number" name="wan_down" min="10" max="10000" value="500" style="width:100%"></label>
<label>WAN upload Mbps<br><input type="number" name="wan_up" min="10" max="10000" value="500" style="width:100%"></label>
<label>Tenant cap download Mbps<br><input type="number" name="tenant_down" min="0" max="10000" value="80" style="width:100%"></label>
<label>Tenant cap upload Mbps<br><input type="number" name="tenant_up" min="0" max="10000" value="40" style="width:100%"></label>
</div>
<div class="panel pad" style="margin-top:16px;background:#0d1528"><strong>Profile behavior</strong><div class="muted" style="margin-top:6px"><b>Always active:</b> conservative RAW prefiltering and TCP MSS clamp-to-PMTU.<br><b>Maximum throughput:</b> FastTrack active; CAKE, QoS mangle and tenant queues are created but disabled.<br><b>Fairness / QoS:</b> FastTrack disabled; CAKE shaping, QoS classification and tenant caps enabled.</div></div>
<div class="muted" style="margin-top:12px">Interface choices include ether1–ether10 and sfp-sfpplus1–sfp-sfpplus24. Fresh config creates DHCP on ether1 plus Bell VLAN35 and a disabled dummy PPPoE profile.</div>
<div style="margin-top:16px"><button class="primary">Generate script</button></div>
</form></div>
<div class="panel pad"><h2>Personal router administrator</h2>
<div class="muted">Saved once and reconciled on every generated script. Password is encrypted at rest on the VPS. Current status: <strong>{'Configured' if configured else 'Not configured'}</strong>.</div>
<form method="post" action="/enroll/admin-credentials" style="margin-top:14px"><input type="hidden" name="csrf" value="{csrf}"><div class="inline"><input name="username" value="{html.escape(username)}" placeholder="Personal username" autocomplete="off" required><input type="password" name="password" placeholder="{'Leave blank to keep current password' if configured else 'Password'}" autocomplete="new-password" {'required' if not configured else ''}><button>Save personal admin</button></div></form></div>'''
    return page_func("Enrollment", body, user, "enroll")


def register(app, page_func):
    provisioning.ensure_schema()
    app.router.routes[:] = [r for r in app.router.routes if getattr(r, "path", None) not in {"/enroll", "/enroll/generate", "/enroll/admin-credentials"}]

    @app.get("/enroll", response_class=HTMLResponse)
    def enroll_page(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        return _page(page_func, user, core.csrf_token(request))

    @app.post("/enroll/admin-credentials", response_class=HTMLResponse)
    async def save_admin_credentials(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        username = data.get("username", "").strip()
        password = data.get("password", "")
        if not username or len(username) > 64:
            raise HTTPException(status_code=400, detail="invalid personal username")
        _, old_password = provisioning.get_admin_credentials()
        if not password:
            password = old_password
        if not password or len(password) > 256:
            raise HTTPException(status_code=400, detail="invalid personal password")
        with core.db() as conn:
            conn.execute("UPDATE provisioning_settings SET admin_username=?,admin_password_enc=? WHERE id=1", (username, provisioning._encrypt(password)))
        return _page(page_func, user, core.csrf_token(request), "Personal router administrator saved.")

    @app.post("/enroll/generate", response_class=HTMLResponse)
    async def generate(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        site_name = data.get("site_name", "").strip()
        mode = data.get("mode", "enroll")
        profile = data.get("performance_profile", "throughput")
        if not site_name or len(site_name) > 120 or mode not in {"enroll", "default"} or profile not in PROFILE_LABELS:
            raise HTTPException(status_code=400, detail="invalid enrollment request")
        try:
            vlan_count = int(data.get("vlan_count", "12")); lan_count = int(data.get("lan_count", "4"))
            wan_down = int(data.get("wan_down", "500")); wan_up = int(data.get("wan_up", "500"))
            tenant_down = int(data.get("tenant_down", "80")); tenant_up = int(data.get("tenant_up", "40"))
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid numeric provisioning value")
        vlan_parent = data.get("vlan_parent", "ether2")
        if not (1 <= vlan_count <= 60 and 0 <= lan_count <= 4 and 10 <= wan_down <= 10000 and 10 <= wan_up <= 10000 and 0 <= tenant_down <= 10000 and 0 <= tenant_up <= 10000 and vlan_parent in interface_choices.INTERFACE_SET):
            raise HTTPException(status_code=400, detail="provisioning value out of range")

        token = secrets.token_urlsafe(24)
        now = core.utcnow(); expires = now + timedelta(hours=core.TOKEN_TTL_HOURS)
        with core.db() as conn:
            conn.execute("INSERT INTO enrollment_tokens(token_hash,site_name,created_at,expires_at) VALUES(?,?,?,?)", (core.hash_token(token), site_name, core.iso(now), core.iso(expires)))

        parts = []
        if mode == "default":
            base = performance_profile.performance_ready_default_config_script(site_name, vlan_count, lan_count, wan_down, wan_up, tenant_down, tenant_up, vlan_parent)
            parts.append(_apply_profile(base, profile))
        parts.append(portal.build_routeros_script(site_name, token))
        admin_user, admin_password = provisioning.get_admin_credentials()
        if admin_user and admin_password:
            parts.append(provisioning.personal_admin_block(admin_user, admin_password))
        script = "\n\n".join(x for x in parts if x)

        summary = "Tikcentral only" if mode == "enroll" else f"Opticable default config + Tikcentral · {vlan_count} VLANs · {lan_count} LANs · {wan_down}/{wan_up} Mbps · {PROFILE_LABELS[profile]}"
        warning = "" if mode == "enroll" else '<div class="error"><strong>Fresh-router provisioning:</strong> use after RouterOS/RouterBOOT update and reset with no defaults.</div>'
        admin_note = f"Personal admin <code>{html.escape(admin_user)}</code> will be reconciled." if admin_user and admin_password else "No personal admin credential is configured yet."
        expiry_local = ui_time.format_montreal(core.iso(expires))
        body = f'''{warning}<div class="panel pad"><h2>{html.escape(site_name)}</h2><div>{html.escape(summary)}</div><div class="muted">One-time token expires {html.escape(expiry_local)} (Montréal time). {admin_note}</div><div class="inline" style="margin-top:14px"><button type="button" class="primary" onclick="copyScript()">Copy script</button><a href="/enroll"><button type="button">Back</button></a></div></div><div class="panel pad"><textarea class="script" id="script" readonly>{html.escape(script)}</textarea></div><script>async function copyScript(){{const el=document.getElementById('script');try{{await navigator.clipboard.writeText(el.value);}}catch(e){{el.select();document.execCommand('copy');}}}}</script>'''
        return page_func("Enrollment Script", body, user, "enroll")
