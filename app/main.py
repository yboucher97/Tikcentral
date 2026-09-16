import hashlib
import ipaddress
import os
import secrets
import sqlite3
import subprocess
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

DB_PATH = os.getenv("DB_PATH", "/var/lib/tikcentral/tikcentral.db")
ADMIN_API_KEY = os.environ["ADMIN_API_KEY"]
WG_HELPER = os.getenv("WG_HELPER", "/usr/local/sbin/tikcentral-wg-peer")
WG_SERVER_PUBLIC_KEY = os.environ["WG_SERVER_PUBLIC_KEY"]
WG_ENDPOINT = os.environ["WG_ENDPOINT"]
WG_ROUTER_POOL = ipaddress.ip_network(os.getenv("WG_ROUTER_POOL", "10.250.1.0/24"))
WG_ALLOWED_NETWORK = os.getenv("WG_ALLOWED_NETWORK", "10.250.0.0/16")
TOKEN_TTL_HOURS = int(os.getenv("TOKEN_TTL_HOURS", "24"))

app = FastAPI(title="Tikcentral MikroTik Hub", version="1.0.0")

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


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)


def require_admin(x_api_key: str = Header(default="")):
    if not ADMIN_API_KEY or not secrets.compare_digest(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="invalid API key")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


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
    with db() as conn:
        rows = conn.execute(
            "SELECT id,site_name,identity,serial,vpn_ip,public_key,enabled,created_at FROM routers ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/enroll")
def enroll(req: EnrollRequest):
    now = utcnow()
    with db() as conn:
        existing = conn.execute(
            "SELECT site_name,vpn_ip,public_key,enabled FROM routers WHERE public_key=?",
            (req.public_key,),
        ).fetchone()
        if existing:
            if not existing["enabled"]:
                raise HTTPException(status_code=403, detail="router disabled")
            wg_helper("add", existing["public_key"], existing["vpn_ip"])
            return {
                "vpn_ip": existing["vpn_ip"],
                "server_public_key": WG_SERVER_PUBLIC_KEY,
                "endpoint": WG_ENDPOINT,
                "allowed_network": WG_ALLOWED_NETWORK,
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
        wg_helper("add", req.public_key, vpn_ip)
        conn.execute(
            "INSERT INTO routers(site_name,identity,serial,public_key,vpn_ip,created_at) VALUES(?,?,?,?,?,?)",
            (token["site_name"], req.identity, req.serial, req.public_key, vpn_ip, iso(now)),
        )
        conn.execute(
            "UPDATE enrollment_tokens SET used_at=? WHERE id=?",
            (iso(now), token["id"]),
        )

    return {
        "vpn_ip": vpn_ip,
        "server_public_key": WG_SERVER_PUBLIC_KEY,
        "endpoint": WG_ENDPOINT,
        "allowed_network": WG_ALLOWED_NETWORK,
    }
