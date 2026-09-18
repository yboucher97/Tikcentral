"""Backup/config browser with guided, non-automatic recovery advice."""

import html

from fastapi import Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from app import main as core, migrations


def register(app,page_func):
    migrations.migrate()

    @app.get("/recovery/{router_id}",response_class=HTMLResponse)
    def recovery_page(router_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return RedirectResponse("/login",303)
        with core.db() as conn:
            router=conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?",(router_id,)).fetchone()
            backups=conn.execute("SELECT * FROM router_backup_records WHERE router_id=? ORDER BY id DESC LIMIT 80",(router_id,)).fetchall()
            snaps=conn.execute("SELECT id,captured_at,sha256,source_kind,source_id,source_actor FROM router_snapshots WHERE router_id=? ORDER BY id DESC LIMIT 80",(router_id,)).fetchall()
            protected_count=conn.execute("SELECT COUNT(*) c FROM router_object_protection WHERE router_id=? AND protected=1",(router_id,)).fetchone()["c"]
        if not router: return RedirectResponse("/operations",303)
        backup_rows="".join(
            f'<tr><td>#{b["id"]}</td><td>{html.escape(b["created_at"])}</td><td>{html.escape(b["tier"])}</td><td>{html.escape(b["created_by"] or "-")}</td><td>{html.escape((b["result"] or "")[-300:])}</td></tr>'
            for b in backups
        ) or '<tr><td colspan="5">No tracked backups.</td></tr>'
        snap_rows="".join(
            f'<tr><td>#{s["id"]}</td><td>{html.escape(s["captured_at"])}</td><td><code>{html.escape(s["sha256"][:12])}</code></td><td>{html.escape(s["source_kind"] or "-")}</td><td>{html.escape(s["source_actor"] or "-")}</td><td><a href="/recovery/{router_id}/snapshot/{s["id"]}">View export</a></td></tr>'
            for s in snaps
        ) or '<tr><td colspan="6">No snapshots.</td></tr>'
        guidance=f'''<div class="panel pad"><h3>Guided recovery</h3>
<ol><li>Confirm Guardian/WireGuard access and identify the failure window in Timeline.</li>
<li>Open Configuration Changes and compare the last known-good snapshot with the newest snapshot.</li>
<li>Review the transaction transcript and pre/post snapshots if Tikcentral made the change.</li>
<li>Check the {protected_count} protected object rule(s) before applying any manual recovery command.</li>
<li>Prefer restoring only the affected configuration area. Avoid full blind rollback unless you have separately verified customer-owned changes since the selected backup.</li>
<li>After recovery, verify management access, WAN, compliance, interfaces, and capture a fresh snapshot.</li></ol>
<div class="muted">Tikcentral does not automatically apply a saved export or blind rollback from this page.</div></div>'''
        body=f'''<div class="panel pad"><h2>Recovery browser · {html.escape(router["site_name"])}</h2>
<div class="inline"><a href="/changes/{router_id}"><button>Configuration diffs</button></a><a href="/timeline/{router_id}"><button>Timeline</button></a><a href="/protection/{router_id}"><button>Protected objects</button></a></div></div>
{guidance}
<div class="panel"><div class="pad"><h3>Tracked backups</h3></div><table><thead><tr><th>ID</th><th>Time</th><th>Tier</th><th>By</th><th>Result</th></tr></thead><tbody>{backup_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Configuration snapshots</h3></div><table><thead><tr><th>ID</th><th>Time</th><th>Hash</th><th>Source</th><th>Actor</th><th></th></tr></thead><tbody>{snap_rows}</tbody></table></div>'''
        return page_func("Recovery Browser",body,user,"changes")

    @app.get("/recovery/{router_id}/snapshot/{snapshot_id}",response_class=PlainTextResponse)
    def snapshot_text(router_id:int,snapshot_id:int,request:Request):
        user=core.require_web_admin(request)
        if not user: return PlainTextResponse("Unauthorized",status_code=401)
        with core.db() as conn:
            row=conn.execute("SELECT content FROM router_snapshots WHERE id=? AND router_id=?",(snapshot_id,router_id)).fetchone()
        return PlainTextResponse(row["content"] if row else "Snapshot not found",status_code=200 if row else 404)
