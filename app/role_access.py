"""Role-based web authorization for Tikcentral.

viewer: authenticated read-only access.
technician: read access plus operational POST actions.
admin: full access including users, settings and persistent/global access policy.
"""

from fastapi import Request
from fastapi.responses import HTMLResponse

from app import main as core

ROLE_RANK = {"viewer": 10, "technician": 20, "admin": 30}

ADMIN_PREFIXES = ("/admin/users", "/settings", "/ssh", "/enroll")
ADMIN_POST_PREFIXES = ("/dashboard/access/always",)
ADMIN_POST_FRAGMENTS = ("/dashboard/access/",)


def normalize(role: str) -> str:
    return role if role in ROLE_RANK else "viewer"


def at_least(user, role: str) -> bool:
    if not user:
        return False
    return ROLE_RANK.get(normalize(user["role"]), 0) >= ROLE_RANK[role]


def install_middleware(app):
    @app.middleware("http")
    async def role_authorization(request: Request, call_next):
        path = request.url.path
        if path.startswith("/static") or path in {"/login", "/healthz", "/api/enroll"}:
            return await call_next(request)

        try:
            user = core.session_user(request)
        except Exception:
            user = None
        if not user:
            return await call_next(request)

        role = normalize(user["role"])
        method = request.method.upper()

        if any(path.startswith(p) for p in ADMIN_PREFIXES) and role != "admin":
            return HTMLResponse("<h1>403</h1><p>Admin access required.</p>", status_code=403)

        if method not in {"GET", "HEAD", "OPTIONS"}:
            if path in {"/logout", "/account/password", "/api/ui/preferences"}:
                return await call_next(request)
            if role == "viewer":
                return HTMLResponse("<h1>403</h1><p>Viewer accounts are read-only.</p>", status_code=403)
            if role != "admin":
                if any(path.startswith(p) for p in ADMIN_POST_PREFIXES):
                    return HTMLResponse("<h1>403</h1><p>Admin access required.</p>", status_code=403)
                if path.startswith("/dashboard/access/") and path != "/dashboard/access/current":
                    return HTMLResponse("<h1>403</h1><p>Admin access required.</p>", status_code=403)
        return await call_next(request)
