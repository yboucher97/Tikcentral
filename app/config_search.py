"""Read-only fleet search across sanitized RouterOS configuration snapshots."""

import html

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations, router_exec


def _snippet(content:str, query:str, radius:int=260):
    low=(content or "").lower(); q=(query or "").lower()
    pos=low.find(q)
    if pos<0:return ""
    start=max(0,pos-radius); end=min(len(content),pos+len(query)+radius)
    text=(content[start:end] or "").strip()
    return router_exec.sanitize(text,1200)


def register(app,page_func):
    migrations.migrate()

    @app.get("/config-search",response_class=HTMLResponse)
    def page(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        q=(request.query_params.get("q","") or "").strip()[:160]
        scope=request.query_params.get("scope","latest")
        if scope not in {"latest","history"}:scope="latest"
        results=[]
        if len(q)>=2:
            with core.db() as conn:
                if scope=="latest":
                    rows=conn.execute(
                        """SELECT s.id,s.router_id,s.captured_at,s.content,s.source_kind,r.site_name,r.model
                           FROM router_snapshots s JOIN routers r ON r.id=s.router_id
                           WHERE s.id=(SELECT MAX(s2.id) FROM router_snapshots s2 WHERE s2.router_id=s.router_id)
                             AND instr(lower(s.content),lower(?))>0
                           ORDER BY r.site_name COLLATE NOCASE LIMIT 500""",(q,)
                    ).fetchall()
                else:
                    rows=conn.execute(
                        """SELECT s.id,s.router_id,s.captured_at,s.content,s.source_kind,r.site_name,r.model
                           FROM router_snapshots s JOIN routers r ON r.id=s.router_id
                           WHERE instr(lower(s.content),lower(?))>0
                           ORDER BY s.id DESC LIMIT 500""",(q,)
                    ).fetchall()
            for x in rows:
                results.append((x,_snippet(x["content"],q)))
        rendered="".join(
            f'<tr><td><strong>{html.escape(x["site_name"])}</strong><div class="muted">{html.escape(x["model"] or "")}</div></td>'
            f'<td>#{x["id"]}<div class="muted">{html.escape(x["captured_at"])}</div></td><td>{html.escape(x["source_kind"] or "snapshot")}</td>'
            f'<td><pre style="white-space:pre-wrap;max-width:900px">{html.escape(snippet)}</pre></td>'
            f'<td><a href="/changes/{x["router_id"]}?new={x["id"]}">Open config history</a></td></tr>'
            for x,snippet in results
        ) or '<tr><td colspan="5">Enter at least 2 characters to search, or no matches were found.</td></tr>'
        body=f'''<div class="panel pad"><h2>Fleet configuration search</h2>
<div class="muted">Read-only search across RouterOS snapshots. Results are sanitized before display. Latest-only is the default so stale historical configuration does not look current.</div>
<form method="get" class="inline" style="margin-top:12px">
<input name="q" value="{html.escape(q)}" placeholder="Subnet, VLAN ID, DNS server, comment, interface, route…" style="min-width:420px">
<select name="scope"><option value="latest" {"selected" if scope=="latest" else ""}>Latest snapshot per router</option><option value="history" {"selected" if scope=="history" else ""}>All retained history</option></select>
<button class="primary">Search</button></form></div>
<div class="panel"><table><thead><tr><th>Router</th><th>Snapshot</th><th>Source</th><th>Match</th><th></th></tr></thead><tbody>{rendered}</tbody></table></div>'''
        return page_func("Fleet Config Search",body,user,"config-search")
