"""Configuration history/diff UI backed by sanitized router snapshots."""

import difflib
import html

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core


def register(app, page_func):
    @app.get("/changes", response_class=HTMLResponse)
    def changes_index(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        with core.db() as conn:
            routers = conn.execute(
                """SELECT r.id,r.site_name,r.identity,r.model,r.vpn_ip,
                          COUNT(s.id) snapshot_count,MAX(s.captured_at) last_snapshot
                   FROM routers r LEFT JOIN router_snapshots s ON s.router_id=r.id
                   GROUP BY r.id ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()
        rows = "".join(
            f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')}</div></td><td><code>{html.escape(r['vpn_ip'])}</code></td><td>{r['snapshot_count']}</td><td class="muted">{html.escape(r['last_snapshot'] or 'Never')}</td><td><a href="/changes/{r['id']}"><button>View history / diff</button></a></td></tr>'''
            for r in routers
        ) or '<tr><td colspan="5">No routers.</td></tr>'
        body = f'''<div class="panel pad"><h2>Configuration Changes</h2><div class="muted">Snapshots come from sanitized backups (<code>/export show-sensitive=no</code>). Tikcentral stores hashes so an unchanged configuration does not create duplicate content.</div></div><div class="panel"><table><thead><tr><th>Router</th><th>VPN</th><th>Unique snapshots</th><th>Last snapshot</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>'''
        return page_func("Configuration Changes", body, user, "changes")

    @app.get("/changes/{router_id}", response_class=HTMLResponse)
    def router_changes(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        with core.db() as conn:
            router = conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?", (router_id,)).fetchone()
            snaps = conn.execute(
                "SELECT id,captured_at,sha256,content FROM router_snapshots WHERE router_id=? ORDER BY id DESC LIMIT 30",
                (router_id,),
            ).fetchall()
        if not router:
            raise HTTPException(status_code=404, detail="router not found")
        history = "".join(
            f'''<tr><td>{html.escape(s['captured_at'])}</td><td><code>{html.escape(s['sha256'][:12])}</code></td><td>{'Current' if i == 0 else ''}</td></tr>'''
            for i, s in enumerate(snaps)
        ) or '<tr><td colspan="3">No snapshots yet. Run Backup Now.</td></tr>'
        diff_text = "No previous configuration to compare."
        if len(snaps) >= 2:
            old = snaps[1]["content"].splitlines()
            new = snaps[0]["content"].splitlines()
            diff_text = "\n".join(difflib.unified_diff(
                old, new,
                fromfile=f"previous-{snaps[1]['captured_at']}",
                tofile=f"current-{snaps[0]['captured_at']}",
                lineterm="",
            )) or "No text differences."
        body = f'''<div class="panel pad"><h2>{html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['model'] or '')} · <code>{html.escape(router['vpn_ip'])}</code></div></div>
<div class="panel pad"><h2>Latest change</h2><pre style="white-space:pre-wrap;background:#0d1528;padding:14px;border-radius:8px;max-height:60vh;overflow:auto">{html.escape(diff_text)}</pre></div>
<div class="panel"><table><thead><tr><th>Captured</th><th>Hash</th><th></th></tr></thead><tbody>{history}</tbody></table></div>'''
        return page_func("Configuration Changes", body, user, "changes")
