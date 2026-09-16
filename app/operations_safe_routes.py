"""Safe web wrappers for Operations actions.

A router timeout/config mismatch is an operational failure, not a Tikcentral web
server failure. These routes catch action errors, record a concise event, and
return the operator to the router page instead of exposing a generic HTTP 500.
"""

from fastapi import Request
from fastapi.responses import RedirectResponse

from app import events
from app import main as core
from app import operations


POST_PATHS = {
    "/operations/{router_id}/telemetry",
    "/operations/{router_id}/commission",
    "/operations/{router_id}/profile/{profile}",
    "/operations/{router_id}/backup/{tier}",
    "/operations/{router_id}/drift/check",
    "/operations/{router_id}/baseline",
    "/operations/{router_id}/update/check",
    "/operations/{router_id}/upgrade/{mode}",
    "/operations/{router_id}/routerboot",
    "/operations/{router_id}/approve-version",
}


def _actor(user):
    try:
        return user["email"]
    except Exception:
        return "admin"


def _short_error(exc):
    text = str(exc).strip()
    if not text:
        text = exc.__class__.__name__
    if "timed out after" in text.lower():
        return "router command timed out"
    line = text.splitlines()[-1].strip()
    return line[:300] + ("..." if len(line) > 300 else "")


def _record_failure(router_id: int, label: str, exc):
    try:
        events.record(router_id, "operation", f"{label} failed", _short_error(exc), "warning")
    except Exception:
        # Even event logging must never turn the fallback path into another 500.
        pass


async def _auth_form(request: Request):
    user = core.require_web_admin(request)
    if not user:
        return None, None
    data = await core.form_data(request)
    core.require_csrf(request, data.get("csrf", ""))
    return user, data


def register(app):
    # Remove only the POST action routes. Keep the Operations GET pages intact.
    app.router.routes[:] = [
        r for r in app.router.routes
        if not (getattr(r, "path", None) in POST_PATHS and "POST" in (getattr(r, "methods", set()) or set()))
    ]

    @app.post("/operations/{router_id}/telemetry")
    async def telemetry(router_id: int, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            operations.collect_telemetry(router_id, True)
        except Exception as exc:
            _record_failure(router_id, "Telemetry", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/commission")
    async def commission(router_id: int, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            operations.validate_commissioning(router_id, _actor(user))
        except Exception as exc:
            _record_failure(router_id, "Commissioning validation", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/profile/{profile}")
    async def profile(router_id: int, profile: str, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            operations.switch_profile(router_id, profile, _actor(user))
        except Exception as exc:
            _record_failure(router_id, f"Performance profile change to {profile}", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/backup/{tier}")
    async def backup(router_id: int, tier: str, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            operations.backup_router(router_id, tier, _actor(user))
        except Exception as exc:
            _record_failure(router_id, f"{tier} backup", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/drift/check")
    async def drift(router_id: int, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            operations.check_drift(router_id)
        except Exception as exc:
            _record_failure(router_id, "Configuration drift check", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/baseline")
    async def baseline(router_id: int, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            operations.accept_baseline(router_id, _actor(user))
        except Exception as exc:
            _record_failure(router_id, "Accept configuration baseline", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/update/check")
    async def update_check(router_id: int, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            operations.check_update(router_id)
        except Exception as exc:
            _record_failure(router_id, "RouterOS update check", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/upgrade/{mode}")
    async def upgrade(router_id: int, mode: str, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            if mode not in {"canary", "approved"}:
                raise ValueError("invalid upgrade mode")
            operations.queue_upgrade(router_id, mode == "canary", _actor(user))
        except Exception as exc:
            _record_failure(router_id, f"{mode} RouterOS upgrade", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/routerboot")
    async def routerboot(router_id: int, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            operations.queue_routerboot(router_id, _actor(user))
        except Exception as exc:
            _record_failure(router_id, "RouterBOOT upgrade", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/approve-version")
    async def approve_version(router_id: int, request: Request):
        user, _ = await _auth_form(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        try:
            operations.approve_current_version(router_id, _actor(user))
        except Exception as exc:
            _record_failure(router_id, "Approve RouterOS version", exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)
