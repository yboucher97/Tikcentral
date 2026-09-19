"""Operator activity audit trail.

Only metadata is stored. Request bodies, passwords, commands and secrets are not
captured here; detailed mutation content remains in the existing transaction and
job transcripts.
"""

import html
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def record(actor: str, action: str, *, method: str = "", path: str = "", source_ip: str = "", status_code: int | None = None, details: str = ""):
    migrations.migrate()
    with core.db() as conn:
        conn.execute(
            """INSERT INTO operator_audit_log
               (event_at,actor,action,method,path,source_ip,status_code,details)
               VALUES(?,?,?,?,?,?,?,?)""",
            (
                now_iso(), (actor or "")[:200], (action or "")[:240],
                (method or "")[:16], (path or "")[:500], (source_ip or "")[:120],
                status_code, (details or "")[:2000],
            ),
        )


def _action_for(path: str):
    if path.startswith("/guardian/") and path.endswith("/repair"):
        return "Guardian repair"
    if path.startswith("/audit/") and path.endswith("/normalize"):
        return "Normalize Tikcentral rules"
    if path.startswith("/ssh/"):
        return "Manual Web SSH"
    if "/upgrade/" in path:
        return "RouterOS upgrade"
    if path.endswith("/routerboot"):
        return "RouterBOOT upgrade"
    if "/backup/" in path:
        return "Router backup"
    if path.startswith("/rescue/"):
        return "Rescue configuration"
    if path.startswith("/reliability/") and "/maintenance/" in path:
        return "Maintenance window change"
    if path.startswith("/reliability/") and "/breakglass" in path:
        return "Break-glass bundle"
    if path.startswith("/system-health/"):
        return "System health action"
    if path.startswith("/admin/users"):
        return "User administration"
    if path.startswith("/dashboard/access"):
        return "Remote access authorization"
    if path == "/account/password":
        return "Password change"
    if path == "/logout":
        return "Logout"
    return "Operator POST"


def install_middleware(app):
    @app.middleware("http")
    async def operator_audit_middleware(request: Request, call_next):
        user = None
        if request.method.upper() == "POST" and request.url.path != "/login":
            try:
                user = core.session_user(request)
            except Exception:
                user = None
        response = await call_next(request)
        if request.method.upper() == "POST" and request.url.path != "/login" and user:
            try:
                actor = user["email"] if "email" in user.keys() else str(user["id"])
                record(
                    actor,
                    _action_for(request.url.path),
                    method=request.method,
                    path=request.url.path,
                    source_ip=core.request_source_ip(request) or "",
                    status_code=response.status_code,
                )
            except Exception:
                pass
        return response


def register(app, page_func):
    @app.get("/operator-audit", response_class=HTMLResponse)
    def audit_page(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        q = request.query_params.get("q", "").strip().lower()
        actor_filter = request.query_params.get("actor", "").strip().lower()
        with core.db() as conn:
            rows = conn.execute(
                "SELECT * FROM operator_audit_log ORDER BY id DESC LIMIT 1000"
            ).fetchall()
            actors = [x[0] for x in conn.execute(
                "SELECT DISTINCT actor FROM operator_audit_log WHERE actor<>'' ORDER BY actor"
            ).fetchall()]

        filtered = []
        for row in rows:
            hay = " ".join(str(row[k] or "") for k in ("actor","action","path","source_ip","details")).lower()
            if q and q not in hay:
                continue
            if actor_filter and (row["actor"] or "").lower() != actor_filter:
                continue
            filtered.append(row)

        actor_opts = '<option value="">All operators</option>' + "".join(
            f'<option value="{html.escape(a)}" {"selected" if a.lower()==actor_filter else ""}>{html.escape(a)}</option>'
            for a in actors
        )
        rendered = "".join(
            f'''<tr><td>{html.escape(r["event_at"])}</td><td>{html.escape(r["actor"] or "-")}</td><td><strong>{html.escape(r["action"])}</strong></td><td>{html.escape(r["method"])} <code>{html.escape(r["path"])}</code></td><td><code>{html.escape(r["source_ip"] or "-")}</code></td><td>{html.escape(str(r["status_code"] or "-"))}</td><td>{html.escape(r["details"] or "")}</td></tr>'''
            for r in filtered
        ) or '<tr><td colspan="7">No audit entries match.</td></tr>'
        body = f'''<div class="panel pad"><h2>Operator Audit Log</h2>
<div class="muted">Who triggered changes, when, from which source IP and the resulting HTTP status. Sensitive form bodies and router commands are intentionally not duplicated here.</div>
<form method="get" class="inline" style="margin-top:12px"><input name="q" value="{html.escape(q)}" placeholder="Search action, path, IP"><select name="actor">{actor_opts}</select><button class="primary">Filter</button><a href="/operator-audit"><button type="button">Clear</button></a></form></div>
<div class="panel"><table><thead><tr><th>Time</th><th>Operator</th><th>Action</th><th>Request</th><th>Source IP</th><th>Status</th><th>Details</th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Operator Audit", body, user, "operator-audit")
