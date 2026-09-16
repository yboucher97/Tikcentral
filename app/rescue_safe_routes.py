"""Safe web wrappers for Rescue actions.

Operational blockers such as an interface already being in use or a backup
failure are shown to the operator as a normal Tikcentral page instead of a raw
HTTP 500 response.
"""

import html

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events
from app import main as core
from app import rescue
from app import rescue_v2

POST_PATHS = {"/rescue/{router_id}/enable", "/rescue/{router_id}/disable"}


def _actor(user):
    try:
        return user["email"]
    except Exception:
        return "admin"


def _short_error(exc):
    text = str(exc).strip() or exc.__class__.__name__
    if "timed out after" in text.lower():
        return "Router command timed out. Guardian access may still be healthy; retry after checking the interface state."
    line = text.splitlines()[-1].strip()
    return line[:500] + ("..." if len(line) > 500 else "")


def _error_page(page_func, user, router_id: int, title: str, exc):
    message = _short_error(exc)
    try:
        events.record(router_id, "rescue", title, message, "warning")
    except Exception:
        pass
    body = f'''<div class="panel pad"><h2>{html.escape(title)}</h2>
<div class="error"><strong>Action not completed</strong><div style="margin-top:6px">{html.escape(message)}</div></div>
<div class="muted">No further Rescue configuration was intentionally applied after this error.</div>
<div style="margin-top:14px"><a href="/rescue"><button class="primary">Back to Rescue</button></a></div></div>'''
    return page_func("Rescue", body, user, "rescue")


def register(app, page_func):
    app.router.routes[:] = [
        r for r in app.router.routes
        if not (getattr(r, "path", None) in POST_PATHS and "POST" in (getattr(r, "methods", set()) or set()))
    ]

    @app.post("/rescue/{router_id}/enable", response_class=HTMLResponse)
    async def enable(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        try:
            rescue_v2.enable_rescue(router_id, data.get("interface", "ether5"), _actor(user))
        except Exception as exc:
            return _error_page(page_func, user, router_id, "Enable rescue port failed", exc)
        return RedirectResponse("/rescue", status_code=303)

    @app.post("/rescue/{router_id}/disable", response_class=HTMLResponse)
    async def disable(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        try:
            rescue.disable_rescue(router_id, _actor(user))
        except Exception as exc:
            return _error_page(page_func, user, router_id, "Disable rescue port failed", exc)
        return RedirectResponse("/rescue", status_code=303)
