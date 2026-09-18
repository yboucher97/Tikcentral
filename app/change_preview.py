"""Central pre-change safety preview for router-side mutations."""

import html
import re
from datetime import datetime, timezone
from urllib.parse import parse_qs

from fastapi import Request
from fastapi.responses import HTMLResponse

from app import main as core, migrations

# Only router-side mutations are intercepted. Read-only refresh/check actions and
# database-only acknowledgement actions intentionally bypass this preview.
_PATTERNS = [
    (re.compile(r"^/operations/(\d+)/profile/"), "Performance profile change",
     "Tikcentral performance-owned queue/FastTrack policy"),
    (re.compile(r"^/operations/(\d+)/upgrade/"), "RouterOS upgrade",
     "RouterOS package version and reboot cycle"),
    (re.compile(r"^/operations/(\d+)/routerboot$"), "RouterBOOT upgrade",
     "RouterBOARD firmware and reboot cycle"),
    (re.compile(r"^/guardian/(\d+)/repair$"), "Guardian repair",
     "Tikcentral-owned management access rules/services only"),
    (re.compile(r"^/audit/(\d+)/normalize$"), "Normalize management rules",
     "Tikcentral-commented management firewall rules only"),
    (re.compile(r"^/ssh/(\d+)$"), "Manual Web SSH",
     "Operator-supplied RouterOS command; exact scope depends on command"),
    (re.compile(r"^/rescue/(\d+)/"), "Rescue configuration",
     "Tikcentral rescue address/DHCP/recovery configuration"),
]


def _match(path: str):
    for regex, title, touch in _PATTERNS:
        m = regex.match(path)
        if m:
            return int(m.group(1)), title, touch
    return None


def _snapshot(router_id: int):
    migrations.migrate()
    with core.db() as conn:
        router = conn.execute(
            "SELECT id,site_name,identity,model,vpn_ip,enabled FROM routers WHERE id=?", (router_id,)
        ).fetchone()
        access = conn.execute("SELECT * FROM router_access_state WHERE router_id=?", (router_id,)).fetchone()
        backup = conn.execute(
            "SELECT created_at,tier,created_by,result FROM router_backup_records WHERE router_id=? ORDER BY id DESC LIMIT 1",
            (router_id,),
        ).fetchone()
        active = conn.execute(
            "SELECT id,kind,status,actor FROM router_jobs WHERE router_id=? AND status IN ('queued','running','verifying') ORDER BY id LIMIT 1",
            (router_id,),
        ).fetchone()
    return router, access, backup, active


def _preview_page(request: Request, router_id: int, title: str, touch: str, fields: dict[str, str]):
    router, access, backup, active = _snapshot(router_id)
    if not router:
        return HTMLResponse("<h1>404</h1><p>Router not found.</p>", status_code=404)
    access_state = "Healthy" if access and access["management_ok"] else "Degraded / unknown"
    paths = "WG {wg} · SSH {ssh} · WinBox {winbox} · API {api}".format(
        wg="✓" if access and access["wg_online"] else "✕",
        ssh="✓" if access and access["ssh_open"] else "✕",
        winbox="✓" if access and access["winbox_open"] else "✕",
        api="✓" if access and access["api_open"] else "✕",
    )
    backup_text = (
        f'{backup["created_at"]} · {backup["tier"]} · {backup["created_by"] or "-"}'
        if backup else "No retained backup recorded yet"
    )
    busy = f'Active change #{active["id"]}: {active["kind"]} ({active["status"]})' if active else "No active change job"
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in fields.items() if k != "preview_ack"
    )
    hidden += '<input type="hidden" name="preview_ack" value="1">'
    body = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Change Preview</title><style>
body{{font:14px system-ui;background:#0c120f;color:#f1f5f2;margin:0;padding:28px}}.wrap{{max-width:900px;margin:auto}}
.card{{background:#151d19;border:1px solid #2b3931;border-radius:12px;padding:18px;margin:12px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px}}.muted{{color:#9aa8a0}}
button{{padding:10px 16px;border-radius:8px;border:1px solid #2b3931;background:#278f5d;color:white;cursor:pointer}}
a{{color:#58cf8a}}code{{background:#1b2520;padding:2px 5px;border-radius:4px}}
.warn{{border-left:4px solid #d9a743}}
</style></head><body><div class="wrap">
<div class="card"><h2>Pre-change preview · {html.escape(title)}</h2>
<div><strong>{html.escape(router["site_name"])}</strong> · {html.escape(router["model"] or "")} · <code>{html.escape(router["vpn_ip"])}</code></div>
<div class="muted">Nothing has been changed yet.</div></div>
<div class="grid">
<div class="card"><strong>Planned touch</strong><div>{html.escape(touch)}</div></div>
<div class="card"><strong>Guardian</strong><div>{html.escape(access_state)}</div><div class="muted">{html.escape(paths)}</div></div>
<div class="card"><strong>Backup state</strong><div>{html.escape(backup_text)}</div></div>
<div class="card"><strong>Change lane</strong><div>{html.escape(busy)}</div></div>
</div>
<div class="card warn"><strong>Recovery path</strong>
<div>For managed changes Tikcentral creates/uses a retained pre-change backup where supported, records the transaction, verifies management access afterward, and records failure/recovery evidence in Reliability. Guardian repair remains limited to Tikcentral-owned management access.</div>
</div>
<div class="card"><form method="post" action="{html.escape(request.url.path)}">{hidden}
<button type="submit">Confirm and continue</button> <a href="{html.escape(request.headers.get("referer") or "/")}">Cancel</a>
</form></div></div></body></html>"""
    return HTMLResponse(body, status_code=200, headers={"Cache-Control": "no-store"})


def install_middleware(app):
    @app.middleware("http")
    async def change_preview_middleware(request: Request, call_next):
        if request.method.upper() != "POST":
            return await call_next(request)
        matched = _match(request.url.path)
        if not matched:
            return await call_next(request)

        body = await request.body()
        parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        fields = {k: values[-1] for k, values in parsed.items()}
        if fields.get("preview_ack") == "1":
            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}
            request._receive = receive
            return await call_next(request)

        router_id, title, touch = matched
        return _preview_page(request, router_id, title, touch, fields)
