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

from app import change_control, events, main as core, management_script, migrations, router_exec


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
    files["PACKAGE-NOTE.txt"] = (
        "Generated by Tikcentral. Sensitive RouterOS values are not intentionally included. "
        "Review before sharing outside Opticable.\n"
    )
    return files


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
                          (SELECT AVG(h.winbox_latency_ms) FROM router_access_history h WHERE h.router_id=r.id AND h.winbox_latency_ms IS NOT NULL AND h.checked_at>=datetime('now','-24 hours')) AS avg_winbox_ms
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
<td>{int(r["failed_24h"] or 0)} failed probes<div class="muted">{f'{float(r["avg_winbox_ms"]):.1f} ms avg WinBox' if r["avg_winbox_ms"] is not None else 'No latency sample'}</div></td>
<td>{maintenance_action}</td>
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
                f'<div><code>{html.escape(s["step_at"])}</code> <strong>{html.escape(s["phase"])}</strong> · {html.escape(s["status"])} · {html.escape(s["message"])}</div>'
                for s in steps
            )
            tx_rows.append(
                f'''<tr><td>#{t["id"]}</td><td>{html.escape(t["site_name"])}</td><td>{html.escape(t["kind"])}</td><td>{html.escape(t["status"])}</td><td>{html.escape(t["actor"] or "")}</td><td>{transcript or '<span class="muted">No transcript steps.</span>'}</td></tr>'''
            )
        body = f'''<div class="panel pad"><h2>Reliability Center</h2><div class="muted">Access-first change safety, maintenance windows, correlated incidents, connectivity quality, recovery bundles and support packages.</div></div>
<div class="panel"><table><thead><tr><th>Router</th><th>State</th><th>24h quality</th><th>Maintenance</th><th>Recovery / support</th></tr></thead><tbody>{''.join(router_rows) or '<tr><td colspan="5">No routers.</td></tr>'}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Correlated incidents</h3><div class="muted">Guardian groups simultaneous multi-router access failures so central outages are easier to distinguish from site failures.</div></div><table><thead><tr><th>ID</th><th>Opened</th><th>Status</th><th>Routers</th><th>Incident</th><th>Resolved</th></tr></thead><tbody>{incident_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Change transaction transcripts</h3><div class="muted">Preflight, backup, apply and verification steps for access-sensitive changes.</div></div><table><thead><tr><th>TX</th><th>Router</th><th>Change</th><th>Status</th><th>Actor</th><th>Transcript</th></tr></thead><tbody>{''.join(tx_rows) or '<tr><td colspan="6">No transactions.</td></tr>'}</tbody></table></div>'''
        return page_func("Reliability", body, user, "reliability")

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
