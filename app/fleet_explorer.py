"""Read-only fleet search and operational filtering."""

import html
from datetime import datetime, timedelta, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations


def _age_days(value: str):
    if not value:
        return None
    try:
        return max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(value)).total_seconds() / 86400)
    except Exception:
        return None


def register(app, page_func):
    @app.get("/fleet-search", response_class=HTMLResponse)
    def fleet_search(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        migrations.migrate()
        q = request.query_params.get("q", "").strip().lower()
        model = request.query_params.get("model", "").strip()
        version = request.query_params.get("version", "").strip()
        access = request.query_params.get("access", "").strip()
        attention = request.query_params.get("attention", "").strip()

        with core.db() as conn:
            rows = conn.execute(
                """SELECT r.id,r.site_name,r.identity,r.model,r.routeros_version,r.vpn_ip,r.enabled,
                          a.management_ok,a.wg_online,a.ssh_open,a.winbox_open,a.api_open,a.last_error,
                          t.cpu_load,t.free_memory,t.total_memory,t.uptime,t.captured_at AS telemetry_at,
                          (SELECT created_at FROM router_backup_records b WHERE b.router_id=r.id ORDER BY b.id DESC LIMIT 1) AS last_backup,
                          (SELECT COUNT(*) FROM router_resource_alerts x WHERE x.router_id=r.id AND x.active=1) AS active_alerts,
                          (SELECT summary FROM router_events e WHERE e.router_id=r.id AND e.category='reboot' ORDER BY e.id DESC LIMIT 1) AS last_reboot,
                          (SELECT event_at FROM router_events e WHERE e.router_id=r.id AND e.category='reboot' ORDER BY e.id DESC LIMIT 1) AS last_reboot_at
                   FROM routers r
                   LEFT JOIN router_access_state a ON a.router_id=r.id
                   LEFT JOIN router_telemetry t ON t.id=(SELECT id FROM router_telemetry tt WHERE tt.router_id=r.id ORDER BY tt.id DESC LIMIT 1)
                   ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()
            models = [x[0] for x in conn.execute("SELECT DISTINCT model FROM routers WHERE model<>'' ORDER BY model").fetchall()]
            versions = [x[0] for x in conn.execute("SELECT DISTINCT routeros_version FROM routers WHERE routeros_version<>'' ORDER BY routeros_version").fetchall()]

        def keep(r):
            hay = " ".join(str(r[k] or "") for k in ("site_name","identity","model","routeros_version","vpn_ip")).lower()
            if q and q not in hay:
                return False
            if model and r["model"] != model:
                return False
            if version and r["routeros_version"] != version:
                return False
            state = "disabled" if not r["enabled"] else ("healthy" if r["management_ok"] else ("offline" if not r["wg_online"] else "degraded"))
            if access and state != access:
                return False
            age = _age_days(r["last_backup"])
            if attention == "backup" and not (age is None or age > 2):
                return False
            if attention == "cpu" and not ((r["cpu_load"] or 0) >= 85):
                return False
            if attention == "alerts" and not r["active_alerts"]:
                return False
            if attention == "reboot" and not r["last_reboot_at"]:
                return False
            return True

        filtered = [r for r in rows if keep(r)]
        rendered = []
        for r in filtered:
            state = "Disabled" if not r["enabled"] else ("Healthy" if r["management_ok"] else ("Offline" if not r["wg_online"] else "Degraded"))
            tone = "ok" if state == "Healthy" else ("warn" if state == "Degraded" else "bad")
            backup_age = _age_days(r["last_backup"])
            backup = "Never" if backup_age is None else f"{backup_age:.1f}d ago"
            rendered.append(
                f'''<tr><td><strong>{html.escape(r["site_name"])}</strong><div class="muted">{html.escape(r["identity"] or "")}</div></td>
<td>{html.escape(r["model"] or "-")}</td><td>{html.escape(r["routeros_version"] or "-")}</td><td><code>{html.escape(r["vpn_ip"])}</code></td>
<td><span class="tc-status {tone}"><span class="tc-status-dot"></span>{state}</span><div class="muted">{html.escape(r["last_error"] or "")}</div></td>
<td>{str(r["cpu_load"])+"%" if r["cpu_load"] is not None else "-"}<div class="muted">{html.escape(r["free_memory"] or "")}/{html.escape(r["total_memory"] or "")}</div></td>
<td>{html.escape(backup)}</td><td>{int(r["active_alerts"] or 0)}</td>
<td>{html.escape(r["last_reboot_at"] or "-")}<div class="muted">{html.escape(r["last_reboot"] or "")}</div></td>
<td><a href="/operations/{r["id"]}">Operations</a> · <a href="/guardian">Guardian</a> · <a href="/changes/{r["id"]}">Changes</a></td></tr>'''
            )

        model_opts = '<option value="">All models</option>' + "".join(
            f'<option value="{html.escape(x)}" {"selected" if x==model else ""}>{html.escape(x)}</option>' for x in models
        )
        version_opts = '<option value="">All versions</option>' + "".join(
            f'<option value="{html.escape(x)}" {"selected" if x==version else ""}>{html.escape(x)}</option>' for x in versions
        )
        body = f'''<div class="panel pad"><h2>Fleet Search</h2><div class="muted">Read-only fleet filtering. No bulk mutation actions are available here.</div>
<form method="get" class="inline" style="margin-top:12px;align-items:end">
<label>Search<br><input name="q" value="{html.escape(q)}" placeholder="site, identity, IP, model"></label>
<label>Model<br><select name="model">{model_opts}</select></label>
<label>RouterOS<br><select name="version">{version_opts}</select></label>
<label>Access<br><select name="access"><option value="">Any</option>{''.join(f'<option value="{x}" {"selected" if x==access else ""}>{x.title()}</option>' for x in ("healthy","degraded","offline","disabled"))}</select></label>
<label>Attention<br><select name="attention"><option value="">Any</option>{''.join(f'<option value="{x}" {"selected" if x==attention else ""}>{label}</option>' for x,label in (("backup","Backup stale >2d"),("cpu","CPU ≥85%"),("alerts","Active resource alert"),("reboot","Has reboot event")))}</select></label>
<button class="primary">Filter</button><a href="/fleet-search"><button type="button">Clear</button></a>
</form></div>
<div class="panel pad"><strong>{len(filtered)}</strong> of {len(rows)} router(s) shown</div>
<div class="panel"><table><thead><tr><th>Router</th><th>Model</th><th>RouterOS</th><th>VPN</th><th>Access</th><th>CPU / RAM</th><th>Backup</th><th>Alerts</th><th>Last reboot</th><th></th></tr></thead><tbody>{''.join(rendered) or '<tr><td colspan="10">No routers match these filters.</td></tr>'}</tbody></table></div>'''
        return page_func("Fleet Search", body, user, "fleet-search")
