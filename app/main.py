import hashlib
import ipaddress
import os
import secrets
import subprocess
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, DateTime, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_API_KEY = os.environ["ADMIN_API_KEY"]
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_SERVER_PUBLIC_KEY = os.environ["WG_SERVER_PUBLIC_KEY"]
WG_ENDPOINT = os.environ["WG_ENDPOINT"]
WG_ROUTER_POOL = ipaddress.ip_network(os.getenv("WG_ROUTER_POOL", "10.250.1.0/24"))
WG_ALLOWED_NETWORK = os.getenv("WG_ALLOWED_NETWORK", "10.250.0.0/16")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    site_name: Mapped[str] = mapped_column(String(120))
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class Router(Base):
    __tablename__ = "routers"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_name: Mapped[str] = mapped_column(String(120))
    identity: Mapped[str] = mapped_column(String(120), default="")
    serial: Mapped[str] = mapped_column(String(120), default="")
    public_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    vpn_ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)
app = FastAPI(title="MikroTik WireGuard Hub", version="1.0.0")

def db():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()

def require_admin(x_api_key: str = Header(default="")):
    if not secrets.compare_digest(x_api_key, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="invalid API key")

def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def next_router_ip(session: Session) -> str:
    used = {ipaddress.ip_address(x) for x in session.scalars(select(Router.vpn_ip)).all()}
    for host in WG_ROUTER_POOL.hosts():
        if host not in used:
            return str(host)
    raise HTTPException(status_code=409, detail="router address pool exhausted")

def apply_peer(public_key: str, vpn_ip: str):
    cmd = ["wg", "set", WG_INTERFACE, "peer", public_key, "allowed-ips", f"{vpn_ip}/32"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise HTTPException(status_code=500, detail=f"wg failed: {p.stderr.strip()}")
    subprocess.run(["wg-quick", "save", WG_INTERFACE], capture_output=True, text=True)

class TokenCreate(BaseModel):
    site_name: str = Field(min_length=1, max_length=120)

class EnrollRequest(BaseModel):
    token: str
    public_key: str
    serial: str = ""
    identity: str = ""

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/admin/tokens", dependencies=[Depends(require_admin)])
def create_token(req: TokenCreate, session: Session = Depends(db)):
    raw = secrets.token_urlsafe(24)
    row = EnrollmentToken(token_hash=token_hash(raw), site_name=req.site_name)
    session.add(row)
    session.commit()
    return {"token": raw, "site_name": req.site_name}

@app.get("/admin/routers", dependencies=[Depends(require_admin)])
def routers(session: Session = Depends(db)):
    rows = session.scalars(select(Router).order_by(Router.id)).all()
    return [{"id": r.id, "site_name": r.site_name, "identity": r.identity, "serial": r.serial,
             "vpn_ip": r.vpn_ip, "public_key": r.public_key, "enabled": r.enabled,
             "created_at": r.created_at} for r in rows]

@app.post("/api/enroll")
def enroll(req: EnrollRequest, session: Session = Depends(db)):
    existing = session.scalar(select(Router).where(Router.public_key == req.public_key))
    if existing:
        apply_peer(existing.public_key, existing.vpn_ip)
        return {"vpn_ip": existing.vpn_ip, "server_public_key": WG_SERVER_PUBLIC_KEY,
                "endpoint": WG_ENDPOINT, "allowed_network": WG_ALLOWED_NETWORK}

    t = session.scalar(select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash(req.token)))
    if not t or t.used:
        raise HTTPException(status_code=401, detail="invalid or already-used enrollment token")

    vpn_ip = next_router_ip(session)
    router = Router(site_name=t.site_name, identity=req.identity, serial=req.serial,
                    public_key=req.public_key, vpn_ip=vpn_ip)
    session.add(router)
    t.used = True
    t.used_at = datetime.now(timezone.utc)
    session.commit()
    apply_peer(req.public_key, vpn_ip)
    return {"vpn_ip": vpn_ip, "server_public_key": WG_SERVER_PUBLIC_KEY,
            "endpoint": WG_ENDPOINT, "allowed_network": WG_ALLOWED_NETWORK}
