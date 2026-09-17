"""Configuration history, selectable diffs and change attribution."""

import difflib
import html

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core


def _pick_snapshot(snaps, raw_id, fallback):
    if raw_id and str(raw_id).isdigit():
        wanted = int(raw_id)
        found = next((s for s in snaps if int(s["id"]) == wanted), None)
        if found:
            return found
    return fallback


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
        body = f'''<div class="panel pad"><h2>Configuration Changes</h2><div class="muted">Snapshots come from RouterOS exports with sensitive values hidden by default. Tikcentral stores hashes so unchanged configuration does not create duplicate content.</div></div><div class="panel"><table><thead><tr><th>Router</th><th>VPN</th><th>Unique snapshots</th><th>Last snapshot</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>'''
        return page_func("Configuration Changes", body, user, "changes")

    @app.get("/changes/{router_id}", response_class=HTMLResponse)
    def router_changes(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        with core.db() as conn:
            router = conn.execute("SELECT id,site_name,model,vpn_ip FROM routers WHERE id=?", (router_id,)).fetchone()
            snaps = conn.execute(
                "SELECT id,captured_at,sha256,content FROM router_snapshots WHERE router_id=? ORDER BY id DESC LIMIT 60",
                (router_id,),
            ).fetchall()
        if not router:
            raise HTTPException(status_code=404, detail="router not found")

        newest = snaps[0] if snaps else None
        default_old = snaps[1] if len(snaps) >= 2 else newest
        new = _pick_snapshot(snaps, request.query_params.get("new"), newest)
        old = _pick_snapshot(snaps, request.query_params.get("old"), default_old)

        options = "".join(
            f'<option value="{s["id"]}">#{s["id"]} · {html.escape(s["captured_at"])} · {html.escape(s["sha256"][:10])}</option>'
            for s in snaps
        )
        old_options = options.replace(f'value="{old["id"]}"', f'value="{old["id"]}" selected', 1) if old else options
        new_options = options.replace(f'value="{new["id"]}"', f'value="{new["id"]}" selected', 1) if new else options

        diff_text = "No previous configuration to compare."
        attribution = '<div class="muted">No attribution available.</div>'
        if old and new:
            old_lines = old["content"].splitlines()
            new_lines = new["content"].splitlines()
            diff_text = "\n".join(difflib.unified_diff(
                old_lines, new_lines,
                fromfile=f"snapshot-{old['id']}-{old['captured_at']}",
                tofile=f"snapshot-{new['id']}-{new['captured_at']}",
                lineterm="",
            )) or "No text differences."
            lo, hi = sorted([old["captured_at"], new["captured_at"]])
            with core.db() as conn:
                jobs = conn.execute(
                    """SELECT id,kind,status,actor,target,created_at,finished_at,error_code,error_message
                       FROM router_jobs WHERE router_id=? AND created_at>=? AND created_at<=?
                       ORDER BY id""",
                    (router_id, lo, hi),
                ).fetchall()
                evs = conn.execute(
                    """SELECT event_at,severity,category,summary,details
                       FROM router_events WHERE router_id=? AND event_at>=? AND event_at<=?
                         AND category<>'telemetry' ORDER BY id""",
                    (router_id, lo, hi),
                ).fetchall()
            pieces = []
            if jobs:
                pieces.append('<div class="tc-status warn"><span class="tc-status-dot"></span>Possible Tikcentral-attributed change</div>')
                pieces.extend(
                    f'<div style="margin-top:7px"><strong>Job #{j["id"]} · {html.escape(j["kind"])}</strong> · {html.escape(j["status"])} · {html.escape(j["actor"] or "-")}<div class="muted">{html.escape(j["created_at"])} → {html.escape(j["finished_at"] or "")} · target {html.escape(j["target"] or "-")}</div></div>'
                    for j in jobs
                )
            else:
                pieces.append('<div class="tc-status warn"><span class="tc-status-dot"></span>No matching Tikcentral mutation job</div><div class="muted" style="margin-top:6px">This does not prove the change was manual, but Tikcentral has no recorded mutation job in the selected snapshot interval.</div>')
            if evs:
                pieces.append('<h3 style="margin-top:16px">Events in interval</h3>')
                pieces.extend(
                    f'<div><code>{html.escape(e["event_at"])}</code> · {html.escape(e["category"])} · <strong>{html.escape(e["summary"])}</strong><div class="muted">{html.escape((e["details"] or "")[-400:])}</div></div>'
                    for e in evs
                )
            attribution = "".join(pieces)

        history = "".join(
            f'''<tr><td>#{s['id']}</td><td>{html.escape(s['captured_at'])}</td><td><code>{html.escape(s['sha256'][:12])}</code></td><td>{'Latest' if i == 0 else ''}</td></tr>'''
            for i, s in enumerate(snaps)
        ) or '<tr><td colspan="4">No snapshots yet. Run a retained backup.</td></tr>'

        selector = (
            f'''<form method="get" class="inline"><label>From <select name="old">{old_options}</select></label><label>To <select name="new">{new_options}</select></label><button class="primary">Compare</button></form>'''
            if snaps else '<span class="muted">No snapshots available.</span>'
        )
        body = f'''<div class="panel pad"><h2>{html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['model'] or '')} · <code>{html.escape(router['vpn_ip'])}</code></div><div style="margin-top:12px">{selector}</div></div>
<div class="panel pad"><h2>Configuration diff</h2><div class="inline" style="margin-bottom:10px"><button type="button" onclick="navigator.clipboard.writeText(document.getElementById('config-diff').innerText)">Copy diff</button><a href="/reliability/{router_id}/support"><button>Download support package</button></a></div><pre id="config-diff" style="white-space:pre-wrap;padding:14px;border:1px solid var(--line);border-radius:8px;max-height:60vh;overflow:auto;user-select:text">{html.escape(diff_text)}</pre></div>
<div class="panel pad"><h2>Change attribution</h2>{attribution}</div>
<div class="panel"><table><thead><tr><th>Snapshot</th><th>Captured</th><th>Hash</th><th></th></tr></thead><tbody>{history}</tbody></table></div>'''
        return page_func("Configuration Changes", body, user, "changes")
