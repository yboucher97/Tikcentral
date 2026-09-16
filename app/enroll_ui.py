import hashlib
import hmac
import html
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

DB_PATH = os.getenv("DB_PATH", "/var/lib/tikcentral/tikcentral.db")
ADMIN_API_KEY = os.environ["ADMIN_API_KEY"]
WG_ENDPOINT = os.environ["WG_ENDPOINT"]
TOKEN_TTL_HOURS = int(os.getenv("TOKEN_TTL_HOURS", "24"))

app = FastAPI(title="Tikcentral Enrollment UI", version="1.1.0")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def current_admin(request: Request):
    raw = request.cookies.get("tikcentral_session", "")
    if not raw:
        return None
    conn = db()
    try:
        row = conn.execute(
            """
            SELECT u.id,u.email,u.role,u.enabled,s.expires_at
            FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token_hash=?
            """,
            (hash_token(raw),),
        ).fetchone()
        if not row:
            return None
        if not row["enabled"] or row["role"] != "admin":
            return None
        if datetime.fromisoformat(row["expires_at"]) <= utcnow():
            return None
        return row
    finally:
        conn.close()


def csrf_token(request: Request) -> str:
    raw = request.cookies.get("tikcentral_session", "")
    return hmac.new(ADMIN_API_KEY.encode(), ("csrf:" + raw).encode(), hashlib.sha256).hexdigest()


def require_csrf(request: Request, value: str):
    if not hmac.compare_digest(value or "", csrf_token(request)):
        raise HTTPException(status_code=403, detail="invalid form token")


async def form_data(request: Request) -> dict[str, str]:
    raw = (await request.body()).decode("utf-8", "replace")
    parsed = parse_qs(raw, keep_blank_values=True)
    return {k: v[-1] for k, v in parsed.items()}


def page(body: str, email: str) -> HTMLResponse:
    return HTMLResponse(f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Enrollment - Tikcentral</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2d;--line:#26324c;--text:#ecf2ff;--muted:#92a0bb;--accent:#5b86e5}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}}main{{max-width:1700px;margin:0 auto;padding:24px 20px 48px}}a{{color:#9dbaff;text-decoration:none}}.shell-head{{display:flex;align-items:center;gap:18px;flex-wrap:wrap;padding:8px 0 22px;border-bottom:1px solid var(--line);margin-bottom:24px}}.brand{{min-width:180px}}.brand h1{{font-size:23px;margin:0}}.sub,.muted{{color:var(--muted)}}.topnav{{display:flex;gap:7px;align-items:center;flex:1;flex-wrap:wrap}}.topnav a{{padding:8px 11px;border-radius:8px;color:#b8c5df}}.topnav a:hover,.topnav a.active{{background:#1a2846;color:#fff}}.account{{display:flex;align-items:center;gap:10px;color:var(--muted);flex-wrap:wrap}}.panel{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:20px}}h2{{margin-top:0}}input,textarea{{width:100%;background:#0d1528;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:10px}}textarea{{min-height:520px;font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre}}button{{border:1px solid #395182;background:#294d8f;color:var(--text);border-radius:7px;padding:9px 13px;cursor:pointer}}.actions{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px}}
</style></head><body><main>
<div class="shell-head"><div class="brand"><h1>Tikcentral</h1><div class="sub">MikroTik remote management</div></div><nav class="topnav"><a href="/">Dashboard</a><a href="/routers">Routers</a><a class="active" href="/enroll">Enrollment</a><a href="/admin/users">Users</a><a href="/settings">Settings</a></nav><div class="account"><span>{html.escape(email)}</span></div></div>
{body}
</main></body></html>""")


def build_routeros_script(site_name: str, token: str) -> str:
    domain = WG_ENDPOINT.rsplit(":", 1)[0]
    return f'''# Tikcentral enrollment for: {site_name}
# Paste this entire script into a RouterOS 7 terminal.
:local token "{token}"
:local apiUrl "https://{domain}/api/enroll"
:local wgName "opticable-wg"

:if ([:len [/interface/wireguard find where name=$wgName]] = 0) do={{
    /interface/wireguard add name=$wgName comment="Tikcentral management"
}}

:local wgId [/interface/wireguard find where name=$wgName]
:local pub [/interface/wireguard get $wgId public-key]
:local serial [/system/routerboard get serial-number]
:local identity [/system/identity get name]
:local model [/system/routerboard get model]
:local routerosVersion [/system/resource get version]
:local routerbootVersion [/system/routerboard get current-firmware]
:local body ("{{\\\"token\\\":\\\"" . $token . "\\\",\\\"public_key\\\":\\\"" . $pub . "\\\",\\\"serial\\\":\\\"" . $serial . "\\\",\\\"identity\\\":\\\"" . $identity . "\\\",\\\"model\\\":\\\"" . $model . "\\\",\\\"routeros_version\\\":\\\"" . $routerosVersion . "\\\",\\\"routerboot_version\\\":\\\"" . $routerbootVersion . "\\\"}}")
:local r [/tool/fetch url=$apiUrl http-method=post http-header-field="Content-Type: application/json" http-data=$body output=user as-value]
:local cfg [:deserialize from=json value=($r->"data")]
:local vpnIP ($cfg->"vpn_ip")
:local serverKey ($cfg->"server_public_key")
:local endpoint ($cfg->"endpoint")
:local allowedNet ($cfg->"allowed_network")
:local endpointHost [:pick $endpoint 0 [:find $endpoint ":"]]
:local endpointPort [:pick $endpoint ([:find $endpoint ":"] + 1) [:len $endpoint]]

:if ([:len [/ip/address find where interface=$wgName]] = 0) do={{
    /ip/address add address=($vpnIP . "/32") interface=$wgName comment="Tikcentral management"
}}
:if ([:len [/interface/wireguard/peers find where interface=$wgName and public-key=$serverKey]] = 0) do={{
    /interface/wireguard/peers add interface=$wgName public-key=$serverKey endpoint-address=$endpointHost endpoint-port=$endpointPort allowed-address=$allowedNet persistent-keepalive=25 comment="Tikcentral hub"
}}
:if ([:len [/ip/route find where dst-address=$allowedNet and gateway=$wgName]] = 0) do={{
    /ip/route add dst-address=$allowedNet gateway=$wgName comment="Tikcentral management"
}}
:if ([:len [/ip/firewall/filter find where comment="Tikcentral relay WinBox"]] = 0) do={{
    /ip/firewall/filter add chain=input action=accept in-interface=$wgName src-address=10.250.0.1 protocol=tcp dst-port=8291 place-before=0 comment="Tikcentral relay WinBox"
}}
:if ([:len [/ip/firewall/filter find where comment="Tikcentral admin TCP"]] = 0) do={{
    /ip/firewall/filter add chain=input action=accept in-interface=$wgName src-address=10.250.254.0/24 protocol=tcp dst-port=22,8291 place-before=0 comment="Tikcentral admin TCP"
}}
:if ([:len [/ip/firewall/filter find where comment="Tikcentral admin ICMP"]] = 0) do={{
    /ip/firewall/filter add chain=input action=accept in-interface=$wgName src-address=10.250.254.0/24 protocol=icmp place-before=0 comment="Tikcentral admin ICMP"
}}
:put ("Tikcentral enrolled: " . $vpnIP)
:put ("Remote WinBox: " . ($cfg->"remote_winbox"))'''


@app.get("/enroll", response_class=HTMLResponse)
def enroll_page(request: Request):
    user = current_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    csrf = csrf_token(request)
    body = f'''<div class="panel"><h2>New site</h2><form method="post" action="/enroll/generate"><input type="hidden" name="csrf" value="{csrf}"><label>Site name</label><input name="site_name" maxlength="120" placeholder="Example: Pharmacy Laval" required><div class="actions"><button>Generate enrollment script</button></div></form></div>'''
    return page(body, user["email"])


@app.post("/enroll/generate", response_class=HTMLResponse)
async def generate(request: Request):
    user = current_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await form_data(request)
    require_csrf(request, data.get("csrf", ""))
    site_name = data.get("site_name", "").strip()
    if not site_name or len(site_name) > 120:
        raise HTTPException(status_code=400, detail="invalid site name")
    raw_token = secrets.token_urlsafe(24)
    now = utcnow()
    expires = now + timedelta(hours=TOKEN_TTL_HOURS)
    conn = db()
    try:
        conn.execute(
            "INSERT INTO enrollment_tokens(token_hash,site_name,created_at,expires_at) VALUES(?,?,?,?)",
            (hash_token(raw_token), site_name, iso(now), iso(expires)),
        )
        conn.commit()
    finally:
        conn.close()
    script = build_routeros_script(site_name, raw_token)
    safe_script = html.escape(script)
    body = f'''<div class="panel"><h2>{html.escape(site_name)}</h2><div class="muted">This one-time enrollment token expires at {html.escape(expires.strftime("%Y-%m-%d %H:%M UTC"))}.</div><div class="actions"><button type="button" onclick="copyScript()">Copy script</button><a href="/enroll">Generate another</a></div></div><div class="panel"><textarea id="script" readonly>{safe_script}</textarea></div><script>async function copyScript(){{const el=document.getElementById('script');try{{await navigator.clipboard.writeText(el.value)}}catch(e){{el.select();document.execCommand('copy')}}}}</script>'''
    return page(body, user["email"])
