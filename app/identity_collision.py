"""Detect duplicate RouterOS identities across enrolled routers."""

import html, json
from datetime import datetime, timezone
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from app import events, main as core, migrations

def _now(): return datetime.now(timezone.utc).isoformat()

def scan():
    migrations.migrate(); checked=_now()
    with core.db() as conn:
        rows=conn.execute("""SELECT LOWER(TRIM(identity)) ident,COUNT(*) c,GROUP_CONCAT(id) ids,GROUP_CONCAT(site_name,' | ') names
                             FROM routers WHERE enabled=1 AND TRIM(identity)<>'' AND COALESCE(lifecycle_state,'production')<>'retired'
                             GROUP BY LOWER(TRIM(identity)) HAVING COUNT(*)>1""").fetchall()
        current={r["ident"] for r in rows}
        existing={r["identity"] for r in conn.execute("SELECT identity FROM router_identity_collisions").fetchall()}
        for r in rows:
            ids=[int(x) for x in (r["ids"] or "").split(",") if x]
            summary=f'Identity "{r["ident"]}" is used by {r["c"]} active routers'
            conn.execute("""INSERT INTO router_identity_collisions(identity,checked_at,router_count,router_ids_json,status,summary)
                            VALUES(?,?,?,?, 'collision',?)
                            ON CONFLICT(identity) DO UPDATE SET checked_at=excluded.checked_at,router_count=excluded.router_count,
                            router_ids_json=excluded.router_ids_json,status='collision',summary=excluded.summary""",
                         (r["ident"],checked,r["c"],json.dumps(ids),summary))
            if r["ident"] not in existing:
                for rid in ids: events.record(rid,"identity-collision","Duplicate RouterOS identity detected",summary,"warning")
        for ident in existing-current:
            conn.execute("DELETE FROM router_identity_collisions WHERE identity=?",(ident,))
    return len(rows)

def register(app,page_func):
    @app.get("/identity-collisions",response_class=HTMLResponse)
    def page(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        scan()
        with core.db() as conn: rows=conn.execute("SELECT * FROM router_identity_collisions ORDER BY router_count DESC,identity").fetchall()
        body_rows=[]
        with core.db() as conn:
            for x in rows:
                ids=json.loads(x["router_ids_json"] or "[]")
                names=[]
                for rid in ids:
                    r=conn.execute("SELECT site_name FROM routers WHERE id=?",(rid,)).fetchone()
                    if r:names.append(f'<a href="/operations/{rid}">{html.escape(r["site_name"])}</a>')
                body_rows.append(f'<tr><td><strong>{html.escape(x["identity"])}</strong></td><td>{x["router_count"]}</td><td>{" · ".join(names)}</td></tr>')
        body=f'''<div class="panel pad"><h2>Router identity collisions</h2><div class="muted">Detects duplicate RouterOS identities across active enrolled routers. Matching is case-insensitive and ignores surrounding spaces.</div></div>
<div class="panel"><table><thead><tr><th>Identity</th><th>Routers</th><th>Sites</th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="3">No active identity collisions.</td></tr>'}</tbody></table></div>'''
        return page_func("Identity Collisions",body,user,"identity-collisions")
