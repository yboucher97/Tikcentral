import hashlib
import hmac
import html
import ipaddress
import secrets
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from app import migrations
from app import settings
from app import ui

# Compatibility names used by route modules and helper scripts. Environment
# parsing/validation itself is owned only by app.settings.
DB_PATH = settings.DB_PATH
ADMIN_API_KEY = settings.ADMIN_API_KEY
ADMIN_EMAIL = settings.ADMIN_EMAIL
BOOTSTRAP_PASSWORD = settings.BOOTSTRAP_PASSWORD
WG_HELPER = settings.WG_HELPER
WG_SERVER_PUBLIC_KEY = settings.WG_SERVER_PUBLIC_KEY
WG_ENDPOINT = settings.WG_ENDPOINT
WG_ROUTER_POOL = settings.WG_ROUTER_POOL
WG_ALLOWED_NETWORK = settings.WG_ALLOWED_NETWORK
TOKEN_TTL_HOURS = settings.TOKEN_TTL_HOURS
ONLINE_SECONDS = settings.ONLINE_SECONDS
WINBOX_PUBLIC_PORT_MIN = settings.WINBOX_PUBLIC_PORT_MIN
WINBOX_PUBLIC_PORT_MAX = settings.WINBOX_PUBLIC_PORT_MAX
TEMP_ACCESS_DAYS = settings.TEMP_ACCESS_DAYS
PUBLIC_HOSTNAME = settings.PUBLIC_HOSTNAME
SESSION_DAYS = settings.SESSION_DAYS

app = FastAPI(title="Tikcentral MikroTik Hub", version="1.4.0")
page = ui.page


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = stored.split("$", 5)
        if algorithm != "scrypt":
            return False
        derived = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p), dklen=32
        )
        return hmac.compare_digest(derived.hex(), digest_hex)
    except Exception:
        return False


def valid_email(value: str) -> bool:
    value = value.strip().lower()
    return 3 <= len(value) <= 254 and "@" in value and "." in value.rsplit("@", 1)[-1]


def allocate_public_port(conn: sqlite3.Connection) -> int:
    used = {int(row[0]) for row in conn.execute("SELECT public_winbox_port FROM routers WHERE public_winbox_port IS NOT NULL")}
    span = WINBOX_PUBLIC_PORT_MAX - WINBOX_PUBLIC_PORT_MIN + 1
    if len(used) >= span:
        raise RuntimeError("public WinBox port pool exhausted")
    for _ in range(5000):
        candidate = secrets.randbelow(span) + WINBOX_PUBLIC_PORT_MIN
        if candidate not in used:
            return candidate
    for candidate in range(WINBOX_PUBLIC_PORT_MIN, WINBOX_PUBLIC_PORT_MAX + 1):
        if candidate not in used:
            return candidate
    raise RuntimeError("public WinBox port pool exhausted")


def init_db():
    migrations.migrate()
    with db() as conn:
        # Historical installations may have routers created before public relay
        # ports were assigned. Schema evolution itself is owned by migrations.
        rows = conn.execute("SELECT id FROM routers WHERE public_winbox_port IS NULL").fetchall()
        for row in rows:
            conn.execute("UPDATE routers SET public_winbox_port=? WHERE id=?", (allocate_public_port(conn), row["id"]))
        conn.execute("DELETE FROM sessions WHERE expires_at<=?", (iso(utcnow()),))
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if user_count == 0 and ADMIN_EMAIL and BOOTSTRAP_PASSWORD:
            if not valid_email(ADMIN_EMAIL):
                raise RuntimeError("ADMIN_EMAIL is not a valid email address")
            now = iso(utcnow())
            conn.execute(
                "INSERT INTO users(email,password_hash,role,enabled,created_at,updated_at) VALUES(?,?, 'admin',1,?,?)",
                (ADMIN_EMAIL, hash_password(BOOTSTRAP_PASSWORD), now, now),
            )


def require_api_admin(x_api_key: str = Header(default="")):
    if not ADMIN_API_KEY or not secrets.compare_digest(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="invalid API key")


def session_user(request: Request):
    raw = request.cookies.get("tikcentral_session", "")
    if not raw:
        return None
    with db() as conn:
        row = conn.execute(
            """
            SELECT u.id,u.email,u.role,u.enabled,s.id AS session_id,s.expires_at
            FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token_hash=?
            """,
            (hash_token(raw),),
        ).fetchone()
        if not row:
            return None
        if not row["enabled"] or datetime.fromisoformat(row["expires_at"]) <= utcnow():
            conn.execute("DELETE FROM sessions WHERE id=?", (row["session_id"],))
            return None
        return row


def require_web_admin(request: Request):
    user = session_user(request)
    if not user:
        return None
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="admin access required")
    return user


def csrf_token(request: Request) -> str:
    raw = request.cookies.get("tikcentral_session", "")
    return hmac.new(ADMIN_API_KEY.encode(), ("csrf:" + raw).encode(), hashlib.sha256).hexdigest()


def require_csrf(request: Request, value: str):
    expected = csrf_token(request)
    if not hmac.compare_digest(value or "", expected):
        raise HTTPException(status_code=403, detail="invalid form token")


def request_public_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    candidate = forwarded.split(",", 1)[0].strip() if forwarded else ""
    if not candidate and request.client:
        candidate = request.client.host
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return ""
    return str(ip) if ip.version == 4 else ""


def next_router_ip(conn: sqlite3.Connection) -> str:
    used = {ipaddress.ip_address(r[0]) for r in conn.execute("SELECT vpn_ip FROM routers")}
    for host in WG_ROUTER_POOL.hosts():
        if host not in used:
            return str(host)
    raise HTTPException(status_code=409, detail="router address pool exhausted")


def wg_helper(*args: str) -> str:
    p = subprocess.run(
        ["sudo", "-n", WG_HELPER, *args],
        capture_output=True,
        text=True,
        timeout=settings.WG_HELPER_TIMEOUT,
    )
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail="WireGuard helper failed")
    return p.stdout.strip()


def parse_public_ip(endpoint: str) -> str:
    if not endpoint or endpoint == "(none)":
        return ""
    if endpoint.startswith("["):
        end = endpoint.find("]")
        return endpoint[1:end] if end > 1 else endpoint
    return endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint


def wireguard_peers() -> dict[str, dict]:
    try:
        output = wg_helper("dump")
    except HTTPException:
        return {}
    peers = {}
    for line in output.splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        try:
            latest = int(fields[4])
        except ValueError:
            latest = 0
        peers[fields[0]] = {
            "endpoint": fields[2],
            "public_ip": parse_public_ip(fields[2]),
            "latest_handshake": latest,
            "online": latest > 0 and (int(time.time()) - latest) <= ONLINE_SECONDS,
        }
    return peers


async def form_data(request: Request) -> dict[str, str]:
    raw = (await request.body()).decode("utf-8", "replace")
    parsed = parse_qs(raw, keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


class TokenCreate(BaseModel):
    site_name: str = Field(min_length=1, max_length=120)


class EnrollRequest(BaseModel):
    token: str = Field(min_length=16, max_length=256)
    public_key: str = Field(min_length=40, max_length=60)
    serial: str = Field(default="", max_length=120)
    identity: str = Field(default="", max_length=120)
    model: str = Field(default="", max_length=120)
    routeros_version: str = Field(default="", max_length=120)
    routerboot_version: str = Field(default="", max_length=120)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/healthz")
def health():
    with db() as conn:
        conn.execute("SELECT 1").fetchone()
    try:
        wg = wg_helper("status")
    except HTTPException:
        wg = "error"
    return {"ok": wg == "ok", "database": "ok", "wireguard": wg}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if session_user(request):
        return RedirectResponse("/", status_code=303)
    error = '<div class="error">Invalid email or password.</div>' if request.query_params.get("error") else ""
    body = f'''<div class="login"><div class="panel pad"><h2>Sign in</h2>{error}<form method="post" action="/login"><div><input style="width:100%;margin-bottom:10px" type="email" name="email" placeholder="Email" required></div><div><input style="width:100%;margin-bottom:14px" type="password" name="password" placeholder="Password" required></div><button class="primary" style="width:100%">Sign in</button></form></div></div>'''
    return page("Login", body)


@app.post("/login")
async def login(request: Request):
    data = await form_data(request)
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    with db() as conn:
        user = conn.execute("SELECT id,email,password_hash,role,enabled FROM users WHERE email=?", (email,)).fetchone()
        if not user or not user["enabled"] or not verify_password(password, user["password_hash"]):
            return RedirectResponse("/login?error=1", status_code=303)
        raw = secrets.token_urlsafe(32)
        now = utcnow()
        conn.execute("DELETE FROM sessions WHERE user_id=? AND expires_at<=?", (user["id"], iso(now)))
        conn.execute(
            "INSERT INTO sessions(user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)",
            (user["id"], hash_token(raw), iso(now + timedelta(days=SESSION_DAYS)), iso(now)),
        )
    try:
        from app import operator_audit
        operator_audit.record(
            user["email"],
            "Login",
            method="POST",
            path="/login",
            source_ip=request_public_ip(request) or "",
            status_code=303,
        )
    except Exception:
        pass
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        "tikcentral_session", raw, max_age=SESSION_DAYS * 86400,
        httponly=True, secure=True, samesite="lax", path="/",
    )
    return response


@app.post("/logout")
def logout(request: Request):
    raw = request.cookies.get("tikcentral_session", "")
    if raw:
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (hash_token(raw),))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("tikcentral_session", path="/")
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    user = require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    peers = wireguard_peers()
    current_ip = request_public_ip(request)
    now = utcnow()
    csrf = csrf_token(request)
    with db() as conn:
        rows = conn.execute(
            "SELECT id,site_name,identity,serial,model,routeros_version,routerboot_version,public_key,vpn_ip,public_winbox_port FROM routers WHERE enabled=1 ORDER BY site_name COLLATE NOCASE,id"
        ).fetchall()
        access_rows = conn.execute(
            "SELECT id,ip_address,label,always_allow,expires_at FROM authorized_ips ORDER BY always_allow DESC,ip_address"
        ).fetchall()
    router_rows = []
    for row in rows:
        live = peers.get(row["public_key"], {})
        online = bool(live.get("online"))
        public_ip = live.get("public_ip") or "-"
        latest = live.get("latest_handshake", 0)
        last_seen = datetime.fromtimestamp(latest, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if latest else "Never"
        remote_winbox = f'{PUBLIC_HOSTNAME}:{row["public_winbox_port"]}'
        direct_winbox = f'{row["vpn_ip"]}:8291'
        router_rows.append(
            f'''<tr><td><span class="dot {'online' if online else 'offline'}"></span>{'Online' if online else 'Offline'}</td><td>{html.escape(row['identity'] or '-')}</td><td>{html.escape(row['model'] or '-')}</td><td>{html.escape(row['serial'] or '-')}</td><td>{html.escape(row['routeros_version'] or '-')}</td><td>{html.escape(row['routerboot_version'] or '-')}</td><td><code>{html.escape(public_ip)}</code></td><td><code>{html.escape(row['vpn_ip'])}</code></td><td><code>{html.escape(remote_winbox)}</code></td><td><code>{html.escape(direct_winbox)}</code></td><td class="muted">{html.escape(last_seen)}</td></tr>'''
        )
    if not router_rows:
        router_rows.append('<tr><td colspan="11" class="muted">No MikroTik routers enrolled yet.</td></tr>')

    access_html = []
    for item in access_rows:
        if item["always_allow"]:
            expiry, mode = "Always", "Always authorized"
        else:
            expiry_dt = datetime.fromisoformat(item["expires_at"]) if item["expires_at"] else now
            if expiry_dt <= now:
                continue
            expiry, mode = expiry_dt.strftime("%Y-%m-%d %H:%M UTC"), "Temporary"
        access_html.append(
            f'''<tr><td><code>{html.escape(item['ip_address'])}</code></td><td>{html.escape(item['label'] or '-')}</td><td>{mode}</td><td>{html.escape(expiry)}</td><td><form method="post" action="/dashboard/access/{item['id']}/delete"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">Remove</button></form></td></tr>'''
        )
    if not access_html:
        access_html.append('<tr><td colspan="5" class="muted">No authorized public IPs.</td></tr>')

    body = f'''<div class="panel pad"><div class="inline" style="justify-content:space-between"><div><h2>Remote WinBox access</h2><div>Your current public IP: <code>{html.escape(current_ip or 'Unknown')}</code></div><div class="muted">Temporary authorization lasts {TEMP_ACCESS_DAYS} days.</div></div><form method="post" action="/dashboard/access/current"><input type="hidden" name="csrf" value="{csrf}"><button class="primary">Authorize my current IP for {TEMP_ACCESS_DAYS} days</button></form></div></div><div class="panel"><table><thead><tr><th>Status</th><th>Identity</th><th>Model</th><th>Serial</th><th>RouterOS</th><th>RouterBOOT</th><th>Public IP</th><th>VPN IP</th><th>Remote WinBox</th><th>VPN WinBox</th><th>Last handshake UTC</th></tr></thead><tbody>{''.join(router_rows)}</tbody></table></div><div class="panel pad"><h2>Always Authorized IPs</h2><form class="inline" method="post" action="/dashboard/access/always"><input type="hidden" name="csrf" value="{csrf}"><input name="ip_address" placeholder="203.0.113.10" required><input name="label" placeholder="Office / Home / Technician"><button>Add</button></form></div><div class="panel"><table><thead><tr><th>IP address</th><th>Label</th><th>Type</th><th>Expires</th><th></th></tr></thead><tbody>{''.join(access_html)}</tbody></table></div>'''
    return page("Dashboard", body, user, "dashboard")


@app.post("/dashboard/access/current")
async def authorize_current(request: Request):
    user = require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await form_data(request)
    require_csrf(request, data.get("csrf", ""))
    ip = request_public_ip(request)
    if not ip:
        raise HTTPException(status_code=400, detail="could not determine public IPv4 address")
    now = utcnow()
    expires = now + timedelta(days=TEMP_ACCESS_DAYS)
    with db() as conn:
        existing = conn.execute("SELECT always_allow FROM authorized_ips WHERE ip_address=?", (ip,)).fetchone()
        if not (existing and existing["always_allow"]):
            conn.execute(
                "INSERT INTO authorized_ips(ip_address,label,always_allow,expires_at,created_at) VALUES(?,?,0,?,?) ON CONFLICT(ip_address) DO UPDATE SET always_allow=0,expires_at=excluded.expires_at",
                (ip, "Current dashboard IP", iso(expires), iso(now)),
            )
    return RedirectResponse("/", status_code=303)


@app.post("/dashboard/access/always")
async def add_always(request: Request):
    user = require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await form_data(request)
    require_csrf(request, data.get("csrf", ""))
    raw_ip = data.get("ip_address", "").strip()
    label = data.get("label", "").strip()[:120]
    try:
        ip = ipaddress.ip_address(raw_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    if ip.version != 4:
        raise HTTPException(status_code=400, detail="IPv4 only")
    with db() as conn:
        conn.execute(
            "INSERT INTO authorized_ips(ip_address,label,always_allow,expires_at,created_at) VALUES(?,?,1,NULL,?) ON CONFLICT(ip_address) DO UPDATE SET label=excluded.label,always_allow=1,expires_at=NULL",
            (str(ip), label, iso(utcnow())),
        )
    return RedirectResponse("/", status_code=303)


@app.post("/dashboard/access/{access_id}/delete")
async def delete_access(access_id: int, request: Request):
    user = require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await form_data(request)
    require_csrf(request, data.get("csrf", ""))
    with db() as conn:
        conn.execute("DELETE FROM authorized_ips WHERE id=?", (access_id,))
    return RedirectResponse("/", status_code=303)


@app.get("/account/password", response_class=HTMLResponse)
def password_page(request: Request):
    user = require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    csrf = csrf_token(request)
    body = f'''<div class="panel pad" style="max-width:600px"><h2>Change password</h2><form method="post" action="/account/password"><input type="hidden" name="csrf" value="{csrf}"><div><input style="width:100%;margin-bottom:10px" type="password" name="current_password" placeholder="Current password" required></div><div><input style="width:100%;margin-bottom:10px" type="password" name="new_password" placeholder="New password (12+ characters)" minlength="12" required></div><button class="primary">Change password</button></form></div>'''
    return page("Password", body, user, "settings")


@app.post("/account/password")
async def change_password(request: Request):
    user = require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await form_data(request)
    require_csrf(request, data.get("csrf", ""))
    current = data.get("current_password", "")
    new = data.get("new_password", "")
    if len(new) < 12:
        raise HTTPException(status_code=400, detail="password must be at least 12 characters")
    with db() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id=?", (user["id"],)).fetchone()
        if not row or not verify_password(current, row["password_hash"]):
            raise HTTPException(status_code=400, detail="current password is incorrect")
        conn.execute("UPDATE users SET password_hash=?,updated_at=? WHERE id=?", (hash_password(new), iso(utcnow()), user["id"]))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("tikcentral_session", path="/")
    return response


@app.get("/admin/users", response_class=HTMLResponse)
def users_page(request: Request):
    user = require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    csrf = csrf_token(request)
    with db() as conn:
        rows = conn.execute("SELECT id,email,role,enabled,created_at FROM users ORDER BY email").fetchall()
    rendered = []
    for row in rows:
        if row["id"] == user["id"]:
            action = '<span class="muted">Current user</span>'
        else:
            action = f'''<form method="post" action="/admin/users/{row['id']}/toggle"><input type="hidden" name="csrf" value="{csrf}"><button>{'Disable' if row['enabled'] else 'Enable'}</button></form>'''
        rendered.append(
            f'''<tr><td>{html.escape(row['email'])}</td><td>{html.escape(row['role'])}</td><td>{'Active' if row['enabled'] else 'Disabled'}</td><td>{action}</td></tr>'''
        )
    body = f'''<div class="panel pad"><h2>Add user</h2><form class="inline" method="post" action="/admin/users"><input type="hidden" name="csrf" value="{csrf}"><input type="email" name="email" placeholder="user@example.com" required><input type="password" name="password" placeholder="Temporary password (12+)" minlength="12" required><select name="role"><option value="admin">Admin</option></select><button>Add user</button></form></div><div class="panel"><table><thead><tr><th>Email</th><th>Role</th><th>Status</th><th></th></tr></thead><tbody>{''.join(rendered)}</tbody></table></div>'''
    return page("Users", body, user, "users")


@app.post("/admin/users")
async def add_user(request: Request):
    user = require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await form_data(request)
    require_csrf(request, data.get("csrf", ""))
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if not valid_email(email):
        raise HTTPException(status_code=400, detail="invalid email")
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="password must be at least 12 characters")
    now = iso(utcnow())
    try:
        with db() as conn:
            conn.execute(
                "INSERT INTO users(email,password_hash,role,enabled,created_at,updated_at) VALUES(?,?, 'admin',1,?,?)",
                (email, hash_password(password), now, now),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="email already exists")
    return RedirectResponse("/admin/users", status_code=303)


@app.post("/admin/users/{user_id}/toggle")
async def toggle_user(user_id: int, request: Request):
    user = require_web_admin(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    data = await form_data(request)
    require_csrf(request, data.get("csrf", ""))
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="cannot disable your own account")
    with db() as conn:
        row = conn.execute("SELECT enabled FROM users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="user not found")
        enabled = 0 if row["enabled"] else 1
        conn.execute("UPDATE users SET enabled=?,updated_at=? WHERE id=?", (enabled, iso(utcnow()), user_id))
        if not enabled:
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    return RedirectResponse("/admin/users", status_code=303)


@app.post("/admin/tokens")
def create_token(req: TokenCreate, x_api_key: str = Header(default="")):
    require_api_admin(x_api_key)
    raw = secrets.token_urlsafe(24)
    now = utcnow()
    expires = now + timedelta(hours=TOKEN_TTL_HOURS)
    with db() as conn:
        conn.execute(
            "INSERT INTO enrollment_tokens(token_hash,site_name,created_at,expires_at) VALUES(?,?,?,?)",
            (hash_token(raw), req.site_name, iso(now), iso(expires)),
        )
    return {"token": raw, "site_name": req.site_name, "expires_at": iso(expires)}


@app.get("/admin/routers")
def routers(x_api_key: str = Header(default="")):
    require_api_admin(x_api_key)
    peers = wireguard_peers()
    with db() as conn:
        rows = conn.execute(
            "SELECT id,site_name,identity,serial,model,routeros_version,routerboot_version,vpn_ip,public_winbox_port,public_key,enabled,created_at FROM routers ORDER BY id"
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item.update(peers.get(row["public_key"], {}))
        item["remote_winbox"] = f'{PUBLIC_HOSTNAME}:{row["public_winbox_port"]}'
        item["vpn_winbox"] = f'{row["vpn_ip"]}:8291'
        result.append(item)
    return result


@app.post("/api/enroll")
def enroll(req: EnrollRequest, request: Request):
    now = utcnow()
    with db() as conn:
        token = conn.execute(
            "SELECT id,site_name,expires_at,used_at FROM enrollment_tokens WHERE token_hash=?",
            (hash_token(req.token),),
        ).fetchone()
        if not token or token["used_at"]:
            raise HTTPException(status_code=401, detail="invalid or already-used enrollment token")
        if datetime.fromisoformat(token["expires_at"]) < now:
            raise HTTPException(status_code=401, detail="enrollment token expired")
        existing = conn.execute(
            "SELECT site_name,vpn_ip,public_key,enabled,public_winbox_port FROM routers WHERE public_key=?",
            (req.public_key,),
        ).fetchone()
        if existing:
            if not existing["enabled"]:
                raise HTTPException(status_code=403, detail="router disabled")
            wg_helper("add", existing["public_key"], existing["vpn_ip"])
            conn.execute(
                "UPDATE routers SET identity=?,serial=?,model=?,routeros_version=?,routerboot_version=? WHERE public_key=?",
                (req.identity, req.serial, req.model, req.routeros_version, req.routerboot_version, req.public_key),
            )
            conn.execute("UPDATE enrollment_tokens SET used_at=? WHERE id=?", (iso(now), token["id"]))
            return {
                "vpn_ip": existing["vpn_ip"],
                "server_public_key": WG_SERVER_PUBLIC_KEY,
                "endpoint": WG_ENDPOINT,
                "allowed_network": WG_ALLOWED_NETWORK,
                "remote_winbox": f'{PUBLIC_HOSTNAME}:{existing["public_winbox_port"]}',
            }
        vpn_ip = next_router_ip(conn)
        public_port = allocate_public_port(conn)
        wg_helper("add", req.public_key, vpn_ip)
        conn.execute(
            "INSERT INTO routers(site_name,identity,serial,model,routeros_version,routerboot_version,public_key,vpn_ip,public_winbox_port,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (token["site_name"], req.identity, req.serial, req.model, req.routeros_version, req.routerboot_version, req.public_key, vpn_ip, public_port, iso(now)),
        )
        conn.execute("UPDATE enrollment_tokens SET used_at=? WHERE id=?", (iso(now), token["id"]))
    return {
        "vpn_ip": vpn_ip,
        "server_public_key": WG_SERVER_PUBLIC_KEY,
        "endpoint": WG_ENDPOINT,
        "allowed_network": WG_ALLOWED_NETWORK,
        "remote_winbox": f"{PUBLIC_HOSTNAME}:{public_port}",
    }
