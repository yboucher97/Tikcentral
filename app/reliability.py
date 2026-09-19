"""Reliability, maintenance, recovery bundles and support packages."""

import difflib
import html
import io
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse

from app import change_control, events, guardian, main as core, management_script, migrations, router_exec, state_capture


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _router(router_id: int):
    with core.db() as conn:
        return conn.execute(
            """SELECT id,site_name,identity,serial,model,routeros_version,routerboot_version,
                      vpn_ip,public_key,public_winbox_port,enabled,created_at
               FROM routers WHERE id=?""",
            (router_id,),
        ).fetchone()


def _json(value) -> str:
    if value is None:
        return "{}"
    if hasattr(value, "keys"):
        value = dict(value)
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _zip_response(filename: str, files: dict[str, str]):
    return StreamingResponse(
        io.BytesIO(_zip_bytes(files)),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


_BREAKGLASS_MAGIC = b"TIKCENTRAL-BREAKGLASS-V1\\n"
_BREAKGLASS_ITERATIONS = 600_000


def _encrypt_breakglass(files: dict[str, str], passphrase: str) -> bytes:
    """Encrypt a ZIP recovery payload with AES-256-GCM and a derived key."""
    if len(passphrase) < 12:
        raise ValueError("Break-glass passphrase must be at least 12 characters")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_BREAKGLASS_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, _zip_bytes(files), _BREAKGLASS_MAGIC)
    return _BREAKGLASS_MAGIC + salt + nonce + ciphertext


def _encrypted_response(filename: str, payload: bytes):
    return StreamingResponse(
        io.BytesIO(payload),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


def _recovery_files(router_id: int):
    router = _router(router_id)
    if not router:
        raise ValueError("router not found")
    with core.db() as conn:
        access = conn.execute("SELECT * FROM router_access_state WHERE router_id=?", (router_id,)).fetchone()
        history = conn.execute(
            "SELECT * FROM router_access_history WHERE router_id=? ORDER BY id DESC LIMIT 120",
            (router_id,),
        ).fetchall()
        backup = conn.execute(
            "SELECT * FROM router_backup_records WHERE router_id=? ORDER BY id DESC LIMIT 1",
            (router_id,),
        ).fetchone()
        maintenance = conn.execute("SELECT * FROM router_maintenance WHERE router_id=?", (router_id,)).fetchone()
        txs = conn.execute(
            "SELECT * FROM change_transactions WHERE router_id=? ORDER BY id DESC LIMIT 20",
            (router_id,),
        ).fetchall()
        steps = {}
        for tx in txs:
            steps[str(tx["id"])] = [
                dict(x) for x in conn.execute(
                    "SELECT * FROM change_transaction_steps WHERE transaction_id=? ORDER BY id",
                    (tx["id"],),
                ).fetchall()
            ]
    public_router = dict(router)
    checklist = """Tikcentral break-glass recovery bundle
======================================

This package is intentionally sanitized and contains no private keys, passwords,
tokens or RouterOS sensitive export data.

Recovery order:
1. Preserve any working local/WinBox access before changing anything.
2. Confirm the router identity/serial and current management VPN IP.
3. Confirm the opticable-wg interface and Tikcentral hub peer are present.
4. Confirm WinBox TCP/8291 and either SSH TCP/22 or API TCP/8728 are reachable.
5. Compare Tikcentral-owned firewall rules with canonical-management-policy.rsc.
6. Do not remove unrelated customer firewall/NAT/VLAN configuration.
7. If the VPS is unavailable, restore the Tikcentral control plane first rather
   than installing autonomous RouterOS recovery schedulers.
8. After recovery, run Guardian and take a retained backup.

The canonical policy file is reference material. Review it before applying it.
"""
    return {
        "README.txt": checklist,
        "router.json": _json(public_router),
        "access-state.json": _json(access),
        "access-history.json": _json([dict(x) for x in history]),
        "latest-backup-record.json": _json(backup),
        "maintenance.json": _json(maintenance),
        "change-transactions.json": _json([dict(x) for x in txs]),
        "change-transaction-steps.json": _json(steps),
        "canonical-management-policy.rsc": management_script.firewall_reconcile_command(include_print=True) + "\n",
    }


def _support_summary_html(router, telemetry, evs, jobs, ai, incidents, snaps) -> str:
    """Human-readable entry point for support ZIPs."""
    def esc(value):
        return html.escape(str(value or ""))

    latest_t = telemetry[0] if telemetry else None
    event_rows = "".join(
        f"<tr><td>{esc(x['event_at'])}</td><td>{esc(x['severity'])}</td><td>{esc(x['category'])}</td><td>{esc(x['summary'])}</td></tr>"
        for x in evs[:60]
    ) or '<tr><td colspan="4">No recent events.</td></tr>'
    job_rows = "".join(
        f"<tr><td>{esc(x['created_at'])}</td><td>{esc(x['kind'])}</td><td>{esc(x['status'])}</td><td>{esc(x['actor'])}</td><td>{esc(x['error_code'])} {esc(x['error_message'])}</td></tr>"
        for x in jobs[:40]
    ) or '<tr><td colspan="5">No recent jobs.</td></tr>'
    ai_rows = "".join(
        f"<tr><td>#{x['id']}</td><td>{esc(x['created_at'])}</td><td>{esc(x['status'])}</td><td>{esc(x['requested_by'])}</td><td>{esc((x['report'] or '')[:800])}</td></tr>"
        for x in ai[:10]
    ) or '<tr><td colspan="5">No AI analyses.</td></tr>'
    incident_rows = "".join(
        f"<tr><td>#{x['id']}</td><td>{esc(x['opened_at'])}</td><td>{esc(x['status'])}</td><td>{esc(x['summary'])}</td></tr>"
        for x in incidents[:30]
    ) or '<tr><td colspan="4">No fleet incidents.</td></tr>'
    telemetry_text = (
        f"CPU {esc(latest_t['cpu_load'])}% · RAM {esc(latest_t['free_memory'])}/{esc(latest_t['total_memory'])} · "
        f"uptime {esc(latest_t['uptime'])} · RouterOS {esc(latest_t['routeros_version'])}"
        if latest_t else "No telemetry"
    )
    snapshots = ", ".join(f"#{x['id']} {esc(x['captured_at'])}" for x in snaps) or "None"
    generated = datetime.now(timezone.utc).isoformat()
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Tikcentral Support Summary</title>
<style>body{{font:14px system-ui;max-width:1200px;margin:30px auto;padding:0 20px;color:#202722}}
table{{width:100%;border-collapse:collapse;margin:12px 0 28px}}th,td{{padding:8px;border:1px solid #d9e2dc;text-align:left;vertical-align:top}}
th{{background:#f3f7f4}}code{{background:#eef4f0;padding:2px 5px}}.muted{{color:#6b786f}}</style></head><body>
<h1>Tikcentral Support Summary</h1><p class="muted">Generated {esc(generated)}. Start here, then open the JSON/text files for full evidence.</p>
<h2>{esc(router['site_name'] if router else 'Unknown router')}</h2>
<p>{esc(router['identity'] if router else '')} · {esc(router['model'] if router else '')} · <code>{esc(router['vpn_ip'] if router else '')}</code></p>
<h3>Latest telemetry</h3><p>{telemetry_text}</p>
<h3>Configuration snapshots</h3><p>{snapshots}</p>
<h3>Recent events</h3><table><tr><th>Time</th><th>Severity</th><th>Category</th><th>Summary</th></tr>{event_rows}</table>
<h3>Recent jobs</h3><table><tr><th>Time</th><th>Job</th><th>Status</th><th>Actor</th><th>Error</th></tr>{job_rows}</table>
<h3>AI history</h3><table><tr><th>ID</th><th>Time</th><th>Status</th><th>By</th><th>Report excerpt</th></tr>{ai_rows}</table>
<h3>Fleet incidents</h3><table><tr><th>ID</th><th>Opened</th><th>Status</th><th>Summary</th></tr>{incident_rows}</table>
<p class="muted">Sensitive RouterOS values are not intentionally included. Review the package before external sharing.</p>
</body></html>"""


def _support_files(router_id: int):
    files = _recovery_files(router_id)
    router = _router(router_id)
    with core.db() as conn:
        telemetry = conn.execute(
            "SELECT * FROM router_telemetry WHERE router_id=? ORDER BY id DESC LIMIT 200",
            (router_id,),
        ).fetchall()
        evs = conn.execute(
            "SELECT * FROM router_events WHERE router_id=? ORDER BY id DESC LIMIT 300",
            (router_id,),
        ).fetchall()
        jobs = conn.execute(
            "SELECT * FROM router_jobs WHERE router_id=? ORDER BY id DESC LIMIT 150",
            (router_id,),
        ).fetchall()
        snaps = conn.execute(
            "SELECT * FROM router_snapshots WHERE router_id=? ORDER BY id DESC LIMIT 3",
            (router_id,),
        ).fetchall()
        ai = conn.execute(
            """SELECT id,status,requested_by,created_at,started_at,finished_at,report,error_code,error_detail
               FROM router_ai_analyses WHERE router_id=? ORDER BY id DESC LIMIT 10""",
            (router_id,),
        ).fetchall()
        incidents = conn.execute(
            "SELECT * FROM fleet_incidents ORDER BY id DESC LIMIT 50"
        ).fetchall()
    files["telemetry.json"] = _json([dict(x) for x in telemetry])
    files["events.json"] = _json([dict(x) for x in evs])
    files["jobs.json"] = _json([dict(x) for x in jobs])
    files["ai-history.json"] = _json([dict(x) for x in ai])
    files["fleet-incidents.json"] = _json([dict(x) for x in incidents])
    files["snapshot-metadata.json"] = _json([
        {"id": x["id"], "captured_at": x["captured_at"], "sha256": x["sha256"]} for x in snaps
    ])
    if snaps:
        files["latest-config.rsc"] = router_exec.sanitize(snaps[0]["content"])
    if len(snaps) >= 2:
        files["latest-config.diff"] = "\n".join(difflib.unified_diff(
            snaps[1]["content"].splitlines(),
            snaps[0]["content"].splitlines(),
            fromfile=f"snapshot-{snaps[1]['id']}",
            tofile=f"snapshot-{snaps[0]['id']}",
            lineterm="",
        ))
    if router and router["enabled"]:
        for name, command in {
            "live-config.rsc": "/export terse",
            "router-log.txt": "/log print without-paging",
            "interfaces.txt": "/interface print stats-detail without-paging",
            "routes.txt": "/ip route print detail without-paging",
        }.items():
            try:
                output = router_exec.read(router["vpn_ip"], command, timeout=60, label="Support package")
                files[name] = router_exec.sanitize(output)
            except Exception as exc:
                files[name + ".error.txt"] = str(exc)
    files["SUMMARY.html"] = _support_summary_html(router, telemetry, evs, jobs, ai, incidents, snaps)
    files["PACKAGE-NOTE.txt"] = (
        "Generated by Tikcentral. Open SUMMARY.html first. Sensitive RouterOS values are not intentionally included. "
        "Review before sharing outside Opticable.\n"
    )
    return files


def _quality_summary(rows):
    rows = list(rows or [])
    if not rows:
        return {
            "samples": 0, "healthy_pct": None, "failed": 0,
            "consecutive_failed": 0, "avg_winbox": None, "max_winbox": None,
            "avg_ssh": None, "avg_api": None,
        }
    healthy = sum(1 for x in rows if x["management_ok"])
    consecutive = 0
    for x in reversed(rows):
        if x["management_ok"]:
            break
        consecutive += 1

    def avg(name):
        vals = [float(x[name]) for x in rows if x[name] is not None]
        return round(sum(vals) / len(vals), 1) if vals else None

    win = [float(x["winbox_latency_ms"]) for x in rows if x["winbox_latency_ms"] is not None]
    return {
        "samples": len(rows),
        "healthy_pct": round(healthy * 100 / len(rows), 2),
        "failed": len(rows) - healthy,
        "consecutive_failed": consecutive,
        "avg_winbox": avg("winbox_latency_ms"),
        "max_winbox": round(max(win), 1) if win else None,
        "avg_ssh": avg("ssh_latency_ms"),
        "avg_api": avg("api_latency_ms"),
    }


def _availability_svg(rows):
    rows = list(rows or [])
    if not rows:
        return '<div class="muted">No Guardian history in this window.</div>'
    width, height, pad = 1000, 150, 24
    usable = width - pad * 2
    n = len(rows)
    step = usable / max(1, n)
    rects = []
    for i, row in enumerate(rows):
        x = pad + i * step
        cls = "var(--green)" if row["management_ok"] else "var(--danger)"
        rects.append(
            f'<rect x="{x:.2f}" y="35" width="{max(1.0, step + .25):.2f}" height="70" rx="1" fill="{cls}" opacity=".9"><title>{html.escape(row["checked_at"])} · {"Healthy" if row["management_ok"] else "Failed"}</title></rect>'
        )
    return f'''<svg viewBox="0 0 {width} {height}" role="img" aria-label="Guardian availability history" style="width:100%;height:150px;display:block">
<line x1="{pad}" y1="105" x2="{width-pad}" y2="105" stroke="var(--line)"/>
{''.join(rects)}
<text x="{pad}" y="132" fill="var(--muted)" font-size="12">Oldest</text>
<text x="{width-pad}" y="132" fill="var(--muted)" font-size="12" text-anchor="end">Newest</text>
</svg>'''


def _latency_svg(rows):
    rows = list(rows or [])
    if not rows:
        return '<div class="muted">No latency history in this window.</div>'
    series = [
        ("WinBox", "winbox_latency_ms", "var(--green)"),
        ("SSH", "ssh_latency_ms", "var(--warn)"),
        ("API", "api_latency_ms", "var(--danger)"),
    ]
    values = [float(r[k]) for r in rows for _, k, _ in series if r[k] is not None]
    if not values:
        return '<div class="muted">No successful TCP latency samples in this window.</div>'
    width, height = 1000, 260
    left, right, top, bottom = 52, 20, 20, 38
    usable_w, usable_h = width-left-right, height-top-bottom
    maximum = max(5.0, max(values) * 1.12)

    def path_for(key):
        parts = []
        for i, row in enumerate(rows):
            value = row[key]
            if value is None:
                parts.append(None)
                continue
            x = left + (i / max(1, len(rows)-1)) * usable_w
            y = top + (1 - min(float(value), maximum) / maximum) * usable_h
            parts.append((x, y))
        segments, current = [], []
        for point in parts:
            if point is None:
                if current:
                    segments.append(current)
                    current = []
            else:
                current.append(point)
        if current:
            segments.append(current)
        return " ".join(
            f'<polyline points="{" ".join(f"{x:.1f},{y:.1f}" for x,y in seg)}" fill="none" stroke="{color}" stroke-width="2" vector-effect="non-scaling-stroke"/>'
            for label, k, color in series if k == key
            for seg in segments if len(seg) >= 2
        )

    grid = []
    for pct in (0, .25, .5, .75, 1):
        y = top + (1-pct) * usable_h
        value = maximum * pct
        grid.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" stroke="var(--line)" opacity=".7"/><text x="{left-8}" y="{y+4:.1f}" text-anchor="end" fill="var(--muted)" font-size="11">{value:.0f}</text>')
    legend = " ".join(
        f'<span style="display:inline-flex;align-items:center;gap:5px;margin-right:14px"><span style="width:16px;height:3px;background:{color};display:inline-block"></span>{label}</span>'
        for label, _, color in series
    )
    paths = "".join(path_for(k) for _, k, _ in series)
    svg = f'''<svg viewBox="0 0 {width} {height}" role="img" aria-label="Management TCP latency history" style="width:100%;height:260px;display:block">
{''.join(grid)}
{paths}
<text x="{left}" y="{height-10}" fill="var(--muted)" font-size="12">Oldest</text>
<text x="{width-right}" y="{height-10}" fill="var(--muted)" font-size="12" text-anchor="end">Newest</text>
<text x="13" y="{top+12}" fill="var(--muted)" font-size="11">ms</text>
</svg>'''
    return f'<div class="muted" style="margin-bottom:8px">{legend}</div>{svg}'


def _wan_svg(rows):
    rows = list(rows or [])
    if not rows:
        return '<div class="muted">No WAN history in this window.</div>'
    width, height, pad = 1000, 170, 24
    usable = width - pad * 2
    step = usable / max(1, len(rows))
    bars = []
    for i, row in enumerate(rows):
        x = pad + i * step
        internet_ok = (row["internet_ping"] or 0) > 0
        dns_ok = row["dns_ok"] == 1
        route_ok = (row["active_default_routes"] or 0) > 0
        color = "var(--green)" if internet_ok and dns_ok and route_ok else ("var(--warn)" if route_ok else "var(--danger)")
        title = (
            f'{row["captured_at"]} · routes={row["active_default_routes"]} · '
            f'ping={row["internet_ping"]} · dns={row["dns_ok"]}'
        )
        bars.append(
            f'<rect x="{x:.2f}" y="38" width="{max(1.0, step + .25):.2f}" height="78" rx="1" fill="{color}" opacity=".9"><title>{html.escape(title)}</title></rect>'
        )
    return f'''<svg viewBox="0 0 {width} {height}" role="img" aria-label="WAN health history" style="width:100%;height:170px;display:block">
<line x1="{pad}" y1="116" x2="{width-pad}" y2="116" stroke="var(--line)"/>
{''.join(bars)}
<text x="{pad}" y="145" fill="var(--muted)" font-size="12">Oldest</text>
<text x="{width-pad}" y="145" fill="var(--muted)" font-size="12" text-anchor="end">Newest</text>
</svg>'''


def _management_diff(known: str, current: str):
    return "\n".join(difflib.unified_diff(
        (known or "").splitlines(),
        (current or "").splitlines(),
        fromfile="last-known-good",
        tofile="current",
        lineterm="",
    )) or "No differences."


def register(app, page_func):
    migrations.migrate()

    @app.get("/reliability", response_class=HTMLResponse)
    def reliability_page(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        csrf = core.csrf_token(request)
        now = now_iso()
        with core.db() as conn:
            routers = conn.execute(
                """SELECT r.id,r.site_name,r.model,r.vpn_ip,r.enabled,
                          a.management_ok,a.last_good_at,a.last_error,
                          m.start_at,m.end_at,m.reason,
                          (SELECT COUNT(*) FROM router_access_history h WHERE h.router_id=r.id AND h.management_ok=0 AND h.checked_at>=datetime('now','-24 hours')) AS failed_24h,
                          (SELECT AVG(h.winbox_latency_ms) FROM router_access_history h WHERE h.router_id=r.id AND h.winbox_latency_ms IS NOT NULL AND h.checked_at>=datetime('now','-24 hours')) AS avg_winbox_ms,
                          (SELECT captured_at FROM router_management_known_good k WHERE k.router_id=r.id) AS known_good_at,
                          (SELECT active_default_routes FROM router_wan_history w WHERE w.router_id=r.id ORDER BY w.id DESC LIMIT 1) AS wan_routes,
                          (SELECT internet_ping FROM router_wan_history w WHERE w.router_id=r.id ORDER BY w.id DESC LIMIT 1) AS wan_ping,
                          (SELECT dns_ok FROM router_wan_history w WHERE w.router_id=r.id ORDER BY w.id DESC LIMIT 1) AS wan_dns
                   FROM routers r
                   LEFT JOIN router_access_state a ON a.router_id=r.id
                   LEFT JOIN router_maintenance m ON m.router_id=r.id
                   ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()
            incidents = conn.execute(
                "SELECT * FROM fleet_incidents ORDER BY id DESC LIMIT 30"
            ).fetchall()
            txs = conn.execute(
                """SELECT t.*,r.site_name FROM change_transactions t
                   JOIN routers r ON r.id=t.router_id ORDER BY t.id DESC LIMIT 40"""
            ).fetchall()

        router_rows = []
        for r in routers:
            maintained = bool(r["start_at"] and r["end_at"] and r["start_at"] <= now < r["end_at"])
            state = "Maintenance" if maintained else ("Healthy" if r["management_ok"] else "Degraded")
            tone = "warn" if maintained else ("ok" if r["management_ok"] else "bad")
            maintenance = (
                f'<div class="muted">Until {html.escape(r["end_at"])} · {html.escape(r["reason"] or "")}</div>'
                if maintained else ""
            )
            if maintained:
                maintenance_action = f'''<form method="post" action="/reliability/{r['id']}/maintenance/clear" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><button>End maintenance</button></form>'''
            else:
                maintenance_action = f'''<form method="post" action="/reliability/{r['id']}/maintenance/start" class="inline"><input type="hidden" name="csrf" value="{csrf}"><select name="minutes"><option value="60">1 hour</option><option value="240">4 hours</option><option value="480">8 hours</option><option value="1440">24 hours</option></select><input name="reason" placeholder="Reason" maxlength="180"><button>Start maintenance</button></form>'''
            router_rows.append(
                f'''<tr><td><strong>{html.escape(r["site_name"])}</strong><div class="muted">{html.escape(r["model"] or "")} · <code>{html.escape(r["vpn_ip"])}</code></div></td>
<td><span class="tc-status {tone} live"><span class="tc-status-dot"></span>{state}</span>{maintenance}</td>
<td>{int(r["failed_24h"] or 0)} failed probes<div class="muted">{f'{float(r["avg_winbox_ms"]):.1f} ms avg WinBox' if r["avg_winbox_ms"] is not None else 'No latency sample'}</div><div style="margin-top:7px"><a href="/reliability/{r['id']}/quality">View quality history</a></div></td>
<td>{maintenance_action}</td>
<td><div><a href="/reliability/{r['id']}/known-good">Known-good management</a><div class="muted">{html.escape(r["known_good_at"] or "Not captured yet")}</div></div>
<div style="margin-top:7px"><a href="/reliability/{r['id']}/wan">WAN history</a><div class="muted">{("route ✓" if (r["wan_routes"] or 0)>0 else "route ✕")} · {("internet ✓" if (r["wan_ping"] or 0)>0 else "internet ✕")} · {("DNS ✓" if r["wan_dns"]==1 else "DNS ✕")}</div></div></td>
<td><a href="/reliability/{r['id']}/breakglass"><button>Encrypted break-glass bundle</button></a> <a href="/reliability/{r['id']}/support"><button>Support package</button></a></td></tr>'''
            )

        incident_rows = "".join(
            f'''<tr><td>#{x["id"]}</td><td>{html.escape(x["opened_at"])}</td><td>{html.escape(x["status"])}</td><td>{x["router_count"]}</td><td><strong>{html.escape(x["summary"])}</strong><div class="muted">{html.escape(x["details"] or "")}</div></td><td>{html.escape(x["resolved_at"] or "")}</td></tr>'''
            for x in incidents
        ) or '<tr><td colspan="6">No correlated incidents.</td></tr>'

        tx_rows = []
        for t in txs:
            with core.db() as conn:
                steps = conn.execute(
                    "SELECT * FROM change_transaction_steps WHERE transaction_id=? ORDER BY id",
                    (t["id"],),
                ).fetchall()
            transcript = "".join(
                f'''<div style="padding:7px 0;border-bottom:1px solid var(--line)">
<code>{html.escape(s["step_at"])}</code> <strong>{html.escape(s["phase"])}</strong> · <span class="tc-status {"ok" if s["status"]=="ok" else ("bad" if s["status"]=="failed" else "warn")}">{html.escape(s["status"])}</span>
<div>{html.escape(s["message"])}</div>{f'<div class="muted" style="white-space:pre-wrap">{html.escape(s["details"])}</div>' if s["details"] else ''}
</div>'''
                for s in steps
            )
            impact_link=f'<div style="margin-top:8px"><a href="/change-impact/{t["id"]}">Measured before/after impact</a></div>' if t["status"] in {"succeeded","failed"} else ""
            tx_rows.append(
                f'''<tr id="tx-{t["id"]}"><td>#{t["id"]}</td><td>{html.escape(t["site_name"])}</td><td>{html.escape(t["kind"])}</td><td>{html.escape(t["status"])}</td><td>{html.escape(t["actor"] or "")}</td><td>{transcript or '<span class="muted">No transcript steps.</span>'}{impact_link}</td></tr>'''
            )
        body = f'''<div class="panel pad"><h2>Reliability Center</h2><div class="muted">Access-first change safety, maintenance windows, correlated incidents, connectivity quality, recovery bundles and support packages.</div></div>
<div class="panel"><table><thead><tr><th>Router</th><th>State</th><th>24h quality</th><th>Maintenance</th><th>Known-good / WAN</th><th>Recovery / support</th></tr></thead><tbody>{''.join(router_rows) or '<tr><td colspan="6">No routers.</td></tr>'}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Correlated incidents</h3><div class="muted">Guardian groups simultaneous multi-router access failures so central outages are easier to distinguish from site failures.</div></div><table><thead><tr><th>ID</th><th>Opened</th><th>Status</th><th>Routers</th><th>Incident</th><th>Resolved</th></tr></thead><tbody>{incident_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Change transaction transcripts</h3><div class="muted">Preflight, backup, apply and verification steps for access-sensitive changes.</div></div><table><thead><tr><th>TX</th><th>Router</th><th>Change</th><th>Status</th><th>Actor</th><th>Transcript</th></tr></thead><tbody>{''.join(tx_rows) or '<tr><td colspan="6">No transactions.</td></tr>'}</tbody></table></div>'''
        return page_func("Reliability", body, user, "reliability")

    @app.get("/reliability/{router_id}/known-good", response_class=HTMLResponse)
    def known_good_page(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        router = _router(router_id)
        if not router:
            return RedirectResponse("/reliability", status_code=303)
        csrf = core.csrf_token(request)
        try:
            comparison = state_capture.compare_management_known_good(router_id)
        except Exception as exc:
            comparison = {"status": "error", "known": None, "current": "", "current_sha256": "", "error": str(exc)}
        if comparison["status"] == "missing":
            status_html = '<span class="tc-status warn"><span class="tc-status-dot"></span>No known-good snapshot yet</span>'
            details = '<div class="muted" style="margin-top:8px">Tikcentral will capture one automatically while Guardian is Healthy, or you can capture the verified current state below.</div>'
            diff = ""
        elif comparison["status"] == "match":
            known = comparison["known"]
            status_html = '<span class="tc-status ok"><span class="tc-status-dot"></span>Current management state matches known-good</span>'
            details = f'<div class="muted" style="margin-top:8px">Saved {html.escape(known["captured_at"])} · source {html.escape(known["source_kind"] or "-")} · actor {html.escape(known["source_actor"] or "-")}</div>'
            diff = "No differences."
        elif comparison["status"] == "drift":
            known = comparison["known"]
            status_html = '<span class="tc-status bad"><span class="tc-status-dot"></span>Management state differs from known-good</span>'
            details = f'<div class="muted" style="margin-top:8px">Known-good saved {html.escape(known["captured_at"])} · source {html.escape(known["source_kind"] or "-")}</div>'
            diff = _management_diff(known["content"], comparison["current"])
        else:
            status_html = '<span class="tc-status bad"><span class="tc-status-dot"></span>Comparison unavailable</span>'
            details = f'<div class="muted" style="margin-top:8px">{html.escape(comparison.get("error", ""))}</div>'
            diff = ""
        body = f'''<div class="panel pad"><h2>Known-good management · {html.escape(router["site_name"])}</h2>
<div class="muted">{html.escape(router["model"] or "")} · <code>{html.escape(router["vpn_ip"])}</code></div>
<div style="margin-top:12px">{status_html}{details}</div>
<form method="post" action="/reliability/{router_id}/known-good/capture" style="margin-top:14px"><input type="hidden" name="csrf" value="{csrf}"><button class="primary" onclick="return confirm('Save the currently verified Tikcentral management state as known-good?')">Capture verified current state</button> <a href="/reliability"><button type="button">Back</button></a></form></div>
<div class="panel pad"><h3>Management-state difference</h3><div class="muted">Only Tikcentral management objects are compared. Customer firewall/NAT/VLAN configuration is outside this snapshot.</div><pre style="white-space:pre-wrap;max-height:60vh;overflow:auto;user-select:text">{html.escape(diff)}</pre></div>'''
        return page_func("Known-good Management", body, user, "reliability")

    @app.post("/reliability/{router_id}/known-good/capture")
    async def known_good_capture(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        router = _router(router_id)
        if not router:
            return RedirectResponse("/reliability", status_code=303)
        access = guardian.probe_router(router)
        if not access["management_ok"]:
            body = f'''<div class="panel pad"><h2>Known-good snapshot not changed</h2><div class="error">Guardian is not Healthy. Tikcentral will not bless a degraded management state as known-good.<div class="muted">{html.escape(guardian.access_issue(access))}</div></div><div style="margin-top:12px"><a href="/guardian"><button>Open Guardian</button></a> <a href="/reliability/{router_id}/known-good"><button>Back</button></a></div></div>'''
            return page_func("Known-good Management", body, user, "reliability")
        actor = user["email"] if "email" in user.keys() else "admin"
        state_capture.capture_management_known_good(router_id, source_kind="manual_verified", actor=actor)
        events.record(router_id, "known_good", "Verified management state saved as known-good", f"actor={actor}")
        return RedirectResponse(f"/reliability/{router_id}/known-good", status_code=303)

    @app.get("/reliability/{router_id}/wan", response_class=HTMLResponse)
    def wan_history(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        router = _router(router_id)
        if not router:
            return RedirectResponse("/reliability", status_code=303)
        window = request.query_params.get("window", "24h")
        windows = {"6h": 6, "24h": 24, "7d": 168, "30d": 720}
        hours = windows.get(window, 24)
        window = window if window in windows else "24h"
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with core.db() as conn:
            rows = conn.execute(
                """SELECT * FROM router_wan_history WHERE router_id=? AND captured_at>=?
                   ORDER BY id""",
                (router_id, cutoff),
            ).fetchall()
        latest = rows[-1] if rows else None
        changes = []
        previous = None
        for row in rows:
            if previous is None or row["fingerprint"] != previous["fingerprint"]:
                changes.append(row)
            previous = row
        links = " ".join(
            f'<a href="/reliability/{router_id}/wan?window={key}"><button class="{"primary" if key == window else ""}">{key}</button></a>'
            for key in windows
        )
        if latest:
            cards = f'''<div class="tc-health-grid">
<div class="tc-health-card {"ok" if latest["active_default_routes"] else "bad"}"><div class="big">{latest["active_default_routes"]}</div><div class="muted">Active default routes</div></div>
<div class="tc-health-card {"ok" if (latest["internet_ping"] or 0)>0 else "bad"}"><div class="big">{latest["internet_ping"] if latest["internet_ping"] is not None else "—"}/2</div><div class="muted">Internet ping replies</div></div>
<div class="tc-health-card {"ok" if latest["dns_ok"]==1 else "bad"}"><div class="big">{"OK" if latest["dns_ok"]==1 else "Failed"}</div><div class="muted">DNS resolution</div></div>
<div class="tc-health-card"><div class="big">{latest["dhcp_bound"]} / {latest["pppoe_running"]}</div><div class="muted">Bound DHCP / running PPPoE</div></div>
</div>'''
            detail = html.escape(latest["summary"] or "No WAN detail returned.")
        else:
            cards = '<div class="panel pad muted">No WAN samples yet. They are collected with scheduled telemetry while Guardian is Healthy.</div>'
            detail = "No WAN detail available."
        change_rows = "".join(
            f'''<tr><td>{html.escape(x["captured_at"])}</td><td>{x["active_default_routes"]}</td><td>{x["dhcp_bound"]}</td><td>{x["pppoe_running"]}</td><td>{html.escape(str(x["internet_ping"]))}</td><td>{"OK" if x["dns_ok"]==1 else "Failed"}</td></tr>'''
            for x in reversed(changes[-100:])
        ) or '<tr><td colspan="6">No WAN state changes in this window.</td></tr>'
        body = f'''<div class="panel pad"><h2>WAN history · {html.escape(router["site_name"])}</h2><div class="muted">Internet/WAN health is tracked separately from Tikcentral management access.</div><div class="inline" style="margin-top:12px">{links}<a href="/reliability"><button>Back</button></a></div></div>
{cards}
<div class="panel pad"><h3>WAN health timeline</h3><div class="muted">Green = route + Internet ping + DNS working. Amber = route present but one Internet test failed. Red = no active default route.</div>{_wan_svg(rows)}</div>
<div class="panel"><div class="pad"><h3>WAN state changes</h3><div class="muted">Only points where the observed WAN fingerprint changed are listed.</div></div><table><thead><tr><th>Time</th><th>Default routes</th><th>DHCP bound</th><th>PPPoE running</th><th>Ping replies</th><th>DNS</th></tr></thead><tbody>{change_rows}</tbody></table></div>
<div class="panel pad"><h3>Latest WAN detail</h3><pre style="white-space:pre-wrap;max-height:50vh;overflow:auto;user-select:text">{detail}</pre></div>'''
        return page_func("WAN History", body, user, "reliability")

    @app.get("/reliability/{router_id}/quality", response_class=HTMLResponse)
    def quality_history(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        router = _router(router_id)
        if not router:
            return RedirectResponse("/reliability", status_code=303)
        window = request.query_params.get("window", "24h")
        windows = {"6h": 6, "24h": 24, "7d": 24 * 7, "30d": 24 * 30}
        hours = windows.get(window, 24)
        window = window if window in windows else "24h"
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with core.db() as conn:
            rows = conn.execute(
                """SELECT checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok,
                          ssh_latency_ms,winbox_latency_ms,api_latency_ms
                   FROM router_access_history
                   WHERE router_id=? AND checked_at>=?
                   ORDER BY id""",
                (router_id, cutoff),
            ).fetchall()
        summary = _quality_summary(rows)
        window_links = " ".join(
            f'<a href="/reliability/{router_id}/quality?window={key}"><button class="{"primary" if key == window else ""}">{key}</button></a>'
            for key in windows
        )
        healthy = "—" if summary["healthy_pct"] is None else f'{summary["healthy_pct"]:.2f}%'
        avg_win = "—" if summary["avg_winbox"] is None else f'{summary["avg_winbox"]:.1f} ms'
        max_win = "—" if summary["max_winbox"] is None else f'{summary["max_winbox"]:.1f} ms'
        avg_ssh = "—" if summary["avg_ssh"] is None else f'{summary["avg_ssh"]:.1f} ms'
        avg_api = "—" if summary["avg_api"] is None else f'{summary["avg_api"]:.1f} ms'
        body = f'''<div class="panel pad"><h2>Connectivity quality · {html.escape(router["site_name"])}</h2>
<div class="muted">{html.escape(router["model"] or "")} · <code>{html.escape(router["vpn_ip"])}</code> · Guardian TCP probe history</div>
<div class="inline" style="margin-top:12px">{window_links}<a href="/reliability"><button>Back</button></a></div></div>
<div class="tc-health-grid">
<div class="tc-health-card ok"><div class="big">{healthy}</div><div class="muted">Management healthy · {summary["samples"]} samples</div></div>
<div class="tc-health-card {"bad" if summary["failed"] else "ok"}"><div class="big">{summary["failed"]}</div><div class="muted">Failed probes · {summary["consecutive_failed"]} consecutive now</div></div>
<div class="tc-health-card"><div class="big">{avg_win}</div><div class="muted">Avg WinBox latency · max {max_win}</div></div>
<div class="tc-health-card"><div class="big">{avg_ssh} / {avg_api}</div><div class="muted">Avg SSH / API latency</div></div>
</div>
<div class="panel pad"><h3>Management availability</h3><div class="muted">Green = Guardian Healthy. Red = required management condition failed.</div>{_availability_svg(rows)}</div>
<div class="panel pad"><h3>Management path latency</h3><div class="muted">TCP connect time through the management tunnel. Gaps mean the path was unreachable or not sampled.</div>{_latency_svg(rows)}</div>'''
        return page_func("Connectivity Quality", body, user, "reliability")

    @app.post("/reliability/{router_id}/maintenance/start")
    async def maintenance_start(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        try:
            minutes = max(15, min(int(data.get("minutes", "60")), 10080))
        except Exception:
            minutes = 60
        reason = str(data.get("reason", ""))[:180]
        start = datetime.now(timezone.utc)
        end = start + timedelta(minutes=minutes)
        actor = user["email"] if "email" in user.keys() else "admin"
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_maintenance(router_id,start_at,end_at,reason,created_by,created_at)
                   VALUES(?,?,?,?,?,?)
                   ON CONFLICT(router_id) DO UPDATE SET start_at=excluded.start_at,end_at=excluded.end_at,
                     reason=excluded.reason,created_by=excluded.created_by,created_at=excluded.created_at""",
                (router_id, start.isoformat(), end.isoformat(), reason, actor, start.isoformat()),
            )
        events.record(router_id, "maintenance", f"Maintenance window started for {minutes} minutes", reason)
        return RedirectResponse("/reliability", status_code=303)

    @app.post("/reliability/{router_id}/maintenance/clear")
    async def maintenance_clear(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        with core.db() as conn:
            conn.execute("DELETE FROM router_maintenance WHERE router_id=?", (router_id,))
        events.record(router_id, "maintenance", "Maintenance window ended")
        return RedirectResponse("/reliability", status_code=303)

    @app.get("/reliability/{router_id}/breakglass", response_class=HTMLResponse)
    def breakglass_form(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        router = _router(router_id)
        if not router:
            return RedirectResponse("/reliability", status_code=303)
        csrf = core.csrf_token(request)
        body = f'''<div class="panel pad"><h2>Encrypted break-glass bundle · {html.escape(router["site_name"])}</h2>
<div class="muted">The recovery ZIP is encrypted before it leaves Tikcentral using AES-256-GCM. The passphrase is used only for this request and is not stored. Use a unique passphrase of at least 12 characters and keep it somewhere independent of the VPS.</div>
<form method="post" action="/reliability/{router_id}/breakglass" style="margin-top:16px;max-width:620px">
<input type="hidden" name="csrf" value="{csrf}">
<div style="margin-bottom:10px"><label>Passphrase<br><input type="password" name="passphrase" minlength="12" required autocomplete="new-password" style="width:100%"></label></div>
<div style="margin-bottom:14px"><label>Confirm passphrase<br><input type="password" name="confirm" minlength="12" required autocomplete="new-password" style="width:100%"></label></div>
<button class="primary">Generate encrypted bundle</button> <a href="/reliability"><button type="button">Cancel</button></a>
</form>
<div class="muted" style="margin-top:14px">Decrypt later with <code>python3 scripts/decrypt_breakglass.py bundle.tcbundle</code>. The script prompts for the passphrase and writes the recovered ZIP.</div></div>'''
        return page_func("Break-glass Recovery", body, user, "reliability")

    @app.post("/reliability/{router_id}/breakglass")
    async def breakglass_download(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        router = _router(router_id)
        if not router:
            return RedirectResponse("/reliability", status_code=303)
        passphrase = str(data.get("passphrase", ""))
        confirm = str(data.get("confirm", ""))
        if passphrase != confirm or len(passphrase) < 12:
            body = '''<div class="panel pad"><h2>Break-glass bundle not generated</h2><div class="error">Passphrases must match and be at least 12 characters.</div><div style="margin-top:12px"><button onclick="history.back()">Back</button></div></div>'''
            return page_func("Break-glass Recovery", body, user, "reliability")
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in router["site_name"])[:60]
        payload = _encrypt_breakglass(_recovery_files(router_id), passphrase)
        events.record(router_id, "recovery", "Encrypted break-glass recovery bundle generated", "AES-256-GCM; passphrase not stored")
        return _encrypted_response(f"tikcentral-breakglass-{safe}.tcbundle", payload)

    @app.get("/reliability/{router_id}/support")
    def support(router_id: int, request: Request):
        if not core.require_web_admin(request):
            return RedirectResponse("/login", status_code=303)
        router = _router(router_id)
        if not router:
            return RedirectResponse("/reliability", status_code=303)
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in router["site_name"])[:60]
        return _zip_response(f"tikcentral-support-{safe}.zip", _support_files(router_id))
