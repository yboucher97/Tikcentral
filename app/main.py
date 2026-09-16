import hashlib
import hmac
import html
import ipaddress
import os
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

DB_PATH = os.getenv("DB_PATH", "/var/lib/tikcentral/tikcentral.db")
ADMIN_API_KEY = os.environ["ADMIN_API_KEY"]
WG_HELPER = os.getenv("WG_HELPER", "/usr/local/sbin/tikcentral-wg-peer")
WG_SERVER_PUBLIC_KEY = os.environ["WG_SERVER_PUBLIC_KEY"]
WG_ENDPOINT = os.environ["WG_ENDPOINT"]
WG_ROUTER_POOL = ipaddress.ip_network(os.getenv("WG_ROUTER_POOL", "10.250.1.0/24"))
WG_ALLOWED_NETWORK = os.getenv("WG_ALLOWED_NETWORK", "10.250.0.0/16")
TOKEN_TTL_HOURS = int(os.getenv("TOKEN_TTL_HOURS", "24"))
ONLINE_SECONDS = int(os.getenv("ONLINE_SECONDS", "180"))
WINBOX_PUBLIC_PORT_MIN = int(os.getenv("WINBOX_PUBLIC_PORT_MIN", "20000"))
WINBOX_PUBLIC_PORT_MAX = int(os.getenv("WINBOX_PUBLIC_PORT_MAX", "49999"))
TEMP_ACCESS_DAYS = int(os.getenv("TEMP_ACCESS_DAYS", "5"))
PUBLIC_HOSTNAME = os.getenv("PUBLIC_HOSTNAME", WG_ENDPOINT.rsplit(":", 1)[0])

app = FastAPI(title="Tikcentral MikroTik Hub", version="1.2.0")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    site_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS routers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_name TEXT NOT NULL,
    identity TEXT NOT NULL DEFAULT '',
    serial TEXT NOT NULL DEFAULT '',
    public_key TEXT NOT NULL UNIQUE,
    vpn_ip TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    winbox_port INTEGER NOT NULL DEFAULT 8291,
    public_winbox_port INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorized_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    always_allow INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    created_at TEXT NOT NULL
);
"""


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


def ensure_column(conn: sqlite3.Connection, table: str, name: str, definition: str):
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if name not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


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
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)
        ensure_column(conn, "routers", "winbox_port", "INTEGER NOT NULL DEFAULT 8291")
        ensure_column(conn, "routers", "public_winbox_port", "INTEGER")
        rows = conn.execute("SELECT id FROM routers WHERE public_winbox_port IS NULL").fetchall()
        for row in rows:
            conn.execute(
                "UPDATE routers SET public_winbox_port=? WHERE id=?",
                (allocate_public_port(conn), row["id"]),
            )


def require_admin(x_api_key: str = Header(default="")):
    if not ADMIN_API_KEY or not secrets.compare_digest(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="invalid API key")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token() -> str:
    return hmac.new(ADMIN_API_KEY.encode(), b"tikcentral-dashboard-csrf", hashlib.sha256).hexdigest()


def require_csrf(value: str):
    if not hmac.compare_digest(value or "", csrf_token()):
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
        timeout=10,
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
    lines = output.splitlines()
    peers = {}
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        public_key = fields[0]
        endpoint = fields[2]
        try:
            latest = int(fields[4])
        except ValueError:
            latest = 0
        peers[public_key] = {
            "endpoint": endpoint,
            "public_ip": parse_public_ip(endpoint),
            "latest_handshake": latest,
            "online": latest > 0 and (int(time.time()) - latest) <= ONLINE_SECONDS,
        }
    return peers


class TokenCreate(BaseModel):
    site_name: str = Field(min_length=1, max_length=120)


class EnrollRequest(BaseModel):
    token: str = Field(min_length=16, max_length=256)
    public_key: str = Field(min_length=40, max_length=60)
    serial: str = Field(default="", max_length=120)
    identity: str = Field(default="", max_length=120)


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


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    peers = wireguard_peers()
    current_ip = request_public_ip(request)
    now = utcnow()
    csrf = csrf_token()

    with db() as conn:
        rows = conn.execute(
            "SELECT id,site_name,identity,serial,public_key,vpn_ip,public_winbox_port FROM routers WHERE enabled=1 ORDER BY site_name COLLATE NOCASE,id"
        ).fetchall()
        access_rows = conn.execute(
            "SELECT id,ip_address,label,always_allow,expires_at FROM authorized_ips ORDER BY always_allow DESC,ip_address"
        ).fetchall()

    online_count = sum(1 for row in rows if peers.get(row["public_key"], {}).get("online"))
    router_rows = []
    for row in rows:
        live = peers.get(row["public_key"], {})
        online = bool(live.get("online"))
        status_class = "online" if online else "offline"
        status_text = "Online" if online else "Offline"
        public_ip = live.get("public_ip") or "-"
        latest = live.get("latest_handshake", 0)
        last_seen = datetime.fromtimestamp(latest, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if latest else "Never"
        remote_winbox = f'{PUBLIC_HOSTNAME}:{row["public_winbox_port"]}'
        direct_winbox = f'{row["vpn_ip"]}:8291'
        router_rows.append(f"""
        <tr>
          <td><span class="dot {status_class}"></span>{status_text}</td>
          <td>{html.escape(row['identity'] or '-')}</td>
          <td>{html.escape(row['serial'] or '-')}</td>
          <td><code>{html.escape(public_ip)}</code></td>
          <td><code>{html.escape(row['vpn_ip'])}</code></td>
          <td><div class="copy-wrap"><code>{html.escape(remote_winbox)}</code><button onclick="copyText('{html.escape(remote_winbox)}',this)">Copy</button></div></td>
          <td><div class="copy-wrap"><code>{html.escape(direct_winbox)}</code><button onclick="copyText('{html.escape(direct_winbox)}',this)">Copy</button></div></td>
          <td class="muted">{html.escape(last_seen)}</td>
        </tr>
        """)
    if not router_rows:
        router_rows.append('<tr><td colspan="8" class="empty">No MikroTik routers enrolled yet.</td></tr>')

    access_html = []
    for item in access_rows:
        if item["always_allow"]:
            expiry = "Always"
            mode = "Always authorized"
        else:
            expiry_dt = datetime.fromisoformat(item["expires_at"]) if item["expires_at"] else now
            if expiry_dt <= now:
                continue
            expiry = expiry_dt.strftime("%Y-%m-%d %H:%M UTC")
            mode = "Temporary"
        access_html.append(f"""
        <tr>
          <td><code>{html.escape(item['ip_address'])}</code></td>
          <td>{html.escape(item['label'] or '-')}</td>
          <td>{mode}</td>
          <td>{html.escape(expiry)}</td>
          <td><form method="post" action="/dashboard/access/{item['id']}/delete"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">Remove</button></form></td>
        </tr>
        """)
    if not access_html:
        access_html.append('<tr><td colspan="5" class="empty">No authorized public IPs.</td></tr>')

    return HTMLResponse(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tikcentral</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2d;--line:#26324c;--text:#ecf2ff;--muted:#92a0bb;--ok:#46d17d;--bad:#68758d;--accent:#5b86e5;--danger:#b94c5a}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}}main{{max-width:1320px;margin:42px auto;padding:0 20px}}
header{{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:22px}}h1{{font-size:28px;margin:0 0 4px}}h2{{font-size:18px;margin:0 0 14px}}.sub,.muted{{color:var(--muted)}}.count{{background:var(--panel);border:1px solid var(--line);padding:10px 14px;border-radius:10px}}
.panel{{overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:14px;margin-bottom:22px}}.pad{{padding:18px}}table{{width:100%;border-collapse:collapse;min-width:900px}}th,td{{padding:13px 15px;text-align:left;border-bottom:1px solid var(--line)}}th{{font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}}tr:last-child td{{border-bottom:0}}
code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#dce7ff}}.dot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px}}.dot.online{{background:var(--ok);box-shadow:0 0 9px var(--ok)}}.dot.offline{{background:var(--bad)}}
.copy-wrap,.inline{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}button{{border:1px solid #395182;background:#1a2846;color:var(--text);border-radius:7px;padding:7px 11px;cursor:pointer}}button:hover{{background:#22365f}}button.primary{{background:#294d8f}}button.danger{{border-color:#6f3340;background:#3e2027}}input{{background:#0d1528;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:8px 10px}}.empty{{text-align:center;color:var(--muted);padding:35px}}.notice{{display:flex;justify-content:space-between;gap:20px;align-items:center;flex-wrap:wrap}}
</style></head><body><main>
<header><div><h1>Tikcentral</h1><div class="sub">MikroTik remote management</div></div><div class="count"><strong>{online_count}</strong> online / <strong>{len(rows)}</strong> routers</div></header>
<div class="panel pad"><div class="notice"><div><h2>Remote WinBox access</h2><div>Your current public IP: <code>{html.escape(current_ip or 'Unknown')}</code></div><div class="muted">Temporary authorization lasts {TEMP_ACCESS_DAYS} days and applies to all router WinBox relay ports.</div></div>
<form method="post" action="/dashboard/access/current"><input type="hidden" name="csrf" value="{csrf}"><button class="primary" {'disabled' if not current_ip else ''}>Authorize my current IP for {TEMP_ACCESS_DAYS} days</button></form></div></div>
<div class="panel"><table><thead><tr><th>Status</th><th>Identity</th><th>Serial</th><th>Public IP</th><th>VPN IP</th><th>Remote WinBox</th><th>VPN WinBox</th><th>Last handshake UTC</th></tr></thead><tbody>{''.join(router_rows)}</tbody></table></div>
<div class="panel pad"><h2>Always Authorized IPs</h2><form class="inline" method="post" action="/dashboard/access/always"><input type="hidden" name="csrf" value="{csrf}"><input name="ip_address" placeholder="203.0.113.10" required><input name="label" placeholder="Office / Home / Technician"><button>Add always-authorized IP</button></form></div>
<div class="panel"><table><thead><tr><th>IP address</th><th>Label</th><th>Type</th><th>Expires</th><th></th></tr></thead><tbody>{''.join(access_html)}</tbody></table></div>
</main><script>
async function copyText(value,button){{try{{await navigator.clipboard.writeText(value)}}catch(e){{const t=document.createElement('textarea');t.value=value;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove();}}const old=button.textContent;button.textContent='Copied';setTimeout(()=>button.textContent=old,1000);}}
</script></body></html>""")


async def form_data(request: Request) -> dict[str, str]:
    raw = (await request.body()).decode("utf-8", "replace")
    parsed = parse_qs(raw, keep_blank_values=True)
    return {k: v[-1] for k, v in parsed.items()}


@app.post("/dashboard/access/current")
async def authorize_current(request: Request):
    data = await form_data(request)
    require_csrf(data.get("csrf", ""))
    ip = request_public_ip(request)
    if not ip:
        raise HTTPException(status_code=400, detail="could not determine public IPv4 address")
    now = utcnow()
    expires = now + timedelta(days=TEMP_ACCESS_DAYS)
    with db() as conn:
        existing = conn.execute("SELECT always_allow FROM authorized_ips WHERE ip_address=?", (ip,)).fetchone()
        if existing and existing["always_allow"]:
            pass
        else:
            conn.execute(
                """
                INSERT INTO authorized_ips(ip_address,label,always_allow,expires_at,created_at)
                VALUES(?,?,0,?,?)
                ON CONFLICT(ip_address) DO UPDATE SET always_allow=0,expires_at=excluded.expires_at
                """,
                (ip, "Current dashboard IP", iso(expires), iso(now)),
            )
    return RedirectResponse("/", status_code=303)


@app.post("/dashboard/access/always")
async def add_always(request: Request):
    data = await form_data(request)
    require_csrf(data.get("csrf", ""))
    raw_ip = data.get("ip_address", "").strip()
    label = data.get("label", "").strip()[:120]
    try:
        ip = ipaddress.ip_address(raw_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid IP address")
    if ip.version != 4:
        raise HTTPException(status_code=400, detail="IPv4 only for public WinBox access")
    with db() as conn:
        conn.execute(
            """
            INSERT INTO authorized_ips(ip_address,label,always_allow,expires_at,created_at)
            VALUES(?,?,1,NULL,?)
            ON CONFLICT(ip_address) DO UPDATE SET label=excluded.label,always_allow=1,expires_at=NULL
            """,
            (str(ip), label, iso(utcnow())),
        )
    return RedirectResponse("/", status_code=303)


@app.post("/dashboard/access/{access_id}/delete")
async def delete_access(access_id: int, request: Request):
    data = await form_data(request)
    require_csrf(data.get("csrf", ""))
    with db() as conn:
        conn.execute("DELETE FROM authorized_ips WHERE id=?", (access_id,))
    return RedirectResponse("/", status_code=303)


@app.post("/admin/tokens")
def create_token(req: TokenCreate, x_api_key: str = Header(default="")):
    require_admin(x_api_key)
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
    require_admin(x_api_key)
    peers = wireguard_peers()
    with db() as conn:
        rows = conn.execute(
            "SELECT id,site_name,identity,serial,vpn_ip,public_winbox_port,public_key,enabled,created_at FROM routers ORDER BY id"
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
        existing = conn.execute(
            "SELECT site_name,vpn_ip,public_key,enabled,public_winbox_port FROM routers WHERE public_key=?",
            (req.public_key,),
        ).fetchone()
        if existing:
            if not existing["enabled"]:
                raise HTTPException(status_code=403, detail="router disabled")
            wg_helper("add", existing["public_key"], existing["vpn_ip"])
            conn.execute(
                "UPDATE routers SET identity=?,serial=? WHERE public_key=?",
                (req.identity, req.serial, req.public_key),
            )
            return {
                "vpn_ip": existing["vpn_ip"],
                "server_public_key": WG_SERVER_PUBLIC_KEY,
                "endpoint": WG_ENDPOINT,
                "allowed_network": WG_ALLOWED_NETWORK,
                "remote_winbox": f'{PUBLIC_HOSTNAME}:{existing["public_winbox_port"]}',
            }

        token = conn.execute(
            "SELECT id,site_name,expires_at,used_at FROM enrollment_tokens WHERE token_hash=?",
            (hash_token(req.token),),
        ).fetchone()
        if not token or token["used_at"]:
            raise HTTPException(status_code=401, detail="invalid or already-used enrollment token")
        if datetime.fromisoformat(token["expires_at"]) < now:
            raise HTTPException(status_code=401, detail="enrollment token expired")

        vpn_ip = next_router_ip(conn)
        public_port = allocate_public_port(conn)
        wg_helper("add", req.public_key, vpn_ip)
        conn.execute(
            "INSERT INTO routers(site_name,identity,serial,public_key,vpn_ip,public_winbox_port,created_at) VALUES(?,?,?,?,?,?,?)",
            (token["site_name"], req.identity, req.serial, req.public_key, vpn_ip, public_port, iso(now)),
        )
        conn.execute("UPDATE enrollment_tokens SET used_at=? WHERE id=?", (iso(now), token["id"]))

    return {
        "vpn_ip": vpn_ip,
        "server_public_key": WG_SERVER_PUBLIC_KEY,
        "endpoint": WG_ENDPOINT,
        "allowed_network": WG_ALLOWED_NETWORK,
        "remote_winbox": f"{PUBLIC_HOSTNAME}:{public_port}",
    }
