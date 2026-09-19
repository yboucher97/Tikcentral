"""Local Tikcentral self-health and backup restore verification.

These checks use only the existing VPS and local storage. They do not require
external monitoring or a second server.
"""

import hashlib
import html
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import main as core, migrations, settings


DB_BACKUP_WARN_HOURS = 36
DB_BACKUP_CRITICAL_HOURS = 72
ROUTER_BACKUP_WARN_HOURS = 36
ROUTER_BACKUP_CRITICAL_HOURS = 72


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _age_seconds(value: str) -> float:
    if not value:
        return 10**12
    try:
        return max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(value)).total_seconds())
    except Exception:
        return 10**12


def _status(ok: bool, detail: str, *, warning: bool = False):
    return {
        "status": "warning" if warning else ("ok" if ok else "critical"),
        "detail": detail,
    }


def _tcp(host: str, port: int, timeout: float = 2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _unit_state(unit: str):
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        state = (proc.stdout or proc.stderr or "").strip() or f"exit {proc.returncode}"
        return proc.returncode == 0 and state == "active", state
    except Exception as exc:
        return False, str(exc)


def _writable_dir(path: Path):
    try:
        path.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".tikcentral-health-", dir=path, delete=True):
            pass
        return True, str(path)
    except Exception as exc:
        return False, f"{path}: {exc}"


def collect_health():
    migrations.migrate()
    checks = {}

    try:
        with sqlite3.connect(settings.DB_PATH, timeout=10) as conn:
            quick = conn.execute("PRAGMA quick_check").fetchone()[0]
            conn.execute("SELECT COUNT(*) FROM routers").fetchone()
        checks["database"] = _status(quick == "ok", f"SQLite quick_check: {quick}")
    except Exception as exc:
        checks["database"] = _status(False, str(exc))

    try:
        usage = shutil.disk_usage(Path(settings.DB_PATH).parent)
        free_pct = (usage.free / usage.total * 100) if usage.total else 0
        warning = free_pct < 15
        critical = free_pct < 7
        checks["disk"] = _status(
            not critical,
            f"{free_pct:.1f}% free · {usage.free // (1024**3)} GiB available",
            warning=warning and not critical,
        )
    except Exception as exc:
        checks["disk"] = _status(False, str(exc))

    try:
        wg = core.wg_helper("status")
        checks["wireguard"] = _status(wg == "ok", f"wg0 helper: {wg}")
    except Exception as exc:
        checks["wireguard"] = _status(False, str(exc))

    checks["web"] = _status(_tcp("127.0.0.1", 8080), "Uvicorn TCP/8080 reachable")
    checks["caddy"] = _status(_tcp("127.0.0.1", 443), "Caddy TCP/443 reachable")

    for unit in (
        "tikcentral.service",
        "tikcentral-winbox-proxy.service",
        "tikcentral-fleet.timer",
        "tikcentral-backup.timer",
        "tikcentral-ai.timer",
    ):
        ok, state = _unit_state(unit)
        checks[f"unit:{unit}"] = _status(ok, state)

    key = Path(settings.SSH_KEY)
    try:
        key_ok = key.is_file() and key.stat().st_size > 0 and os.access(key, os.R_OK)
        checks["ssh_key"] = _status(key_ok, f"{key} · {'readable' if key_ok else 'missing or unreadable'}")
    except Exception as exc:
        checks["ssh_key"] = _status(False, f"{key}: {exc}")

    known = Path(settings.KNOWN_HOSTS)
    try:
        known_ok = known.is_file() and os.access(known, os.R_OK | os.W_OK)
        checks["known_hosts"] = _status(
            known_ok,
            f"{known} · {'read/write' if known_ok else 'missing or inaccessible'}",
        )
    except Exception as exc:
        checks["known_hosts"] = _status(False, str(exc))

    primary_ok, primary_detail = _writable_dir(settings.BACKUP_ROOT)
    fallback_ok, fallback_detail = _writable_dir(settings.BACKUP_FALLBACK_ROOT)
    if primary_ok:
        checks["router_backup_storage"] = _status(True, f"primary writable · {primary_detail}")
    elif fallback_ok:
        checks["router_backup_storage"] = _status(
            True,
            f"primary unavailable: {primary_detail} · fallback writable: {fallback_detail}",
            warning=True,
        )
    else:
        checks["router_backup_storage"] = _status(
            False,
            f"primary unavailable: {primary_detail} · fallback unavailable: {fallback_detail}",
        )

    helper = Path(settings.AI_CODEX_HELPER)
    helper_ok = helper.is_file() and os.access(helper, os.X_OK)
    checks["codex_helper"] = _status(
        helper_ok,
        f"{helper} · {'executable' if helper_ok else 'missing or not executable'}",
    )

    with core.db() as conn:
        verified = conn.execute(
            "SELECT checked_at,status,details FROM backup_verifications WHERE kind='database' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if verified:
        age_h = _age_seconds(verified["checked_at"]) / 3600
        detail = f"{verified['status']} · {age_h:.1f}h ago · {verified['details']}"
        if verified["status"] == "critical" or age_h > 36:
            checks["db_restore_test"] = _status(False, detail)
        elif verified["status"] == "warning" or age_h > 24:
            checks["db_restore_test"] = _status(True, detail, warning=True)
        else:
            checks["db_restore_test"] = _status(True, detail)
    else:
        checks["db_restore_test"] = _status(True, "No restore verification has run yet", warning=True)

    with core.db() as conn:
        router_checked = conn.execute(
            "SELECT MAX(checked_at) checked_at FROM backup_verifications WHERE kind='router'"
        ).fetchone()["checked_at"]
        router_verify_rows = conn.execute(
            "SELECT status,COUNT(*) count FROM backup_verifications WHERE kind='router' AND checked_at=? GROUP BY status",
            (router_checked or "",),
        ).fetchall() if router_checked else []
    if router_verify_rows:
        counts = {row["status"]: int(row["count"]) for row in router_verify_rows}
        total = sum(counts.values())
        detail = (
            f"{counts.get('ok',0)}/{total} router backup(s) verified"
            f" · {counts.get('warning',0)} warning · {counts.get('critical',0)} critical"
        )
        verify_age_h = _age_seconds(router_checked) / 3600
        if counts.get("critical", 0) or verify_age_h > ROUTER_BACKUP_CRITICAL_HOURS:
            checks["router_backup_verification"] = _status(False, f"{detail} · checked {verify_age_h:.1f}h ago")
        elif counts.get("warning", 0) or verify_age_h > ROUTER_BACKUP_WARN_HOURS:
            checks["router_backup_verification"] = _status(True, f"{detail} · checked {verify_age_h:.1f}h ago", warning=True)
        else:
            checks["router_backup_verification"] = _status(True, f"{detail} · checked {verify_age_h:.1f}h ago")
    else:
        checks["router_backup_verification"] = _status(True, "No router backup verification has run yet", warning=True)

    statuses = [v["status"] for v in checks.values()]
    overall = "critical" if "critical" in statuses else ("warning" if "warning" in statuses else "ok")
    return overall, checks


def record_health():
    overall, checks = collect_health()
    with core.db() as conn:
        conn.execute(
            "INSERT INTO system_health_history(checked_at,overall_status,checks_json) VALUES(?,?,?)",
            (now_iso(), overall, json.dumps(checks, sort_keys=True)),
        )
        conn.execute(
            """DELETE FROM system_health_history WHERE id NOT IN
               (SELECT id FROM system_health_history ORDER BY id DESC LIMIT 2000)"""
        )
    return overall, checks


def _latest_db_backup():
    root = Path("/var/backups/tikcentral")
    try:
        scheduled = sorted(root.glob("tikcentral-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        scheduled = []
    if scheduled:
        return scheduled[0], "scheduled"
    try:
        pre_update = sorted(root.glob("pre-update-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        pre_update = []
    if pre_update:
        return pre_update[0], "pre-update"
    return None, ""


def _verify_database_backup(path: Path):
    temp_dir = Path("/var/lib/tikcentral/verification")
    temp_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="db-restore-", suffix=".db", dir=temp_dir, delete=False) as tmp:
        restored = Path(tmp.name)
    try:
        shutil.copy2(path, restored)
        with sqlite3.connect(restored, timeout=10) as conn:
            quick = conn.execute("PRAGMA quick_check").fetchone()[0]
            version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            routers = conn.execute("SELECT COUNT(*) FROM routers").fetchone()[0]
        required = {"routers", "users", "router_access_state", "router_jobs", "router_backup_records"}
        if quick != "ok":
            raise RuntimeError(f"SQLite quick_check returned {quick}")
        if not required.issubset(tables):
            raise RuntimeError(f"restored database is missing tables: {sorted(required - tables)}")
        return f"restore copy opened successfully · schema v{version} · {routers} router(s)"
    finally:
        restored.unlink(missing_ok=True)


def _router_backup_status():
    results = []
    with core.db() as conn:
        routers = conn.execute("SELECT id,site_name FROM routers WHERE enabled=1 AND COALESCE(lifecycle_state,'production')<>'retired' ORDER BY id").fetchall()
    roots = [settings.BACKUP_ROOT, settings.BACKUP_FALLBACK_ROOT]
    for router in routers:
        found = []
        for root in roots:
            folder = root / str(router["id"]) / "daily"
            try:
                if folder.exists():
                    found.extend(folder.glob("*.rsc"))
            except OSError:
                continue
        try:
            found = sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            found = []
        if not found:
            results.append(("warning", "", f"{router['site_name']}: no daily .rsc backup found"))
            continue
        path = found[0]
        try:
            data = path.read_bytes()
            if len(data) < 20:
                raise RuntimeError("file is unexpectedly small")
            text = data.decode("utf-8")
            digest = hashlib.sha256(text.rstrip("\n").encode()).hexdigest()
            with core.db() as conn:
                snapshot = conn.execute(
                    "SELECT id FROM router_snapshots WHERE router_id=? AND sha256=? LIMIT 1",
                    (router["id"], digest),
                ).fetchone()
            suffix = f"snapshot #{snapshot['id']} hash matched" if snapshot else "readable export; no matching retained snapshot hash"
            age_h = max(0.0, (datetime.now(timezone.utc).timestamp() - path.stat().st_mtime) / 3600)
            status = "critical" if age_h > ROUTER_BACKUP_CRITICAL_HOURS else ("warning" if age_h > ROUTER_BACKUP_WARN_HOURS else "ok")
            results.append((status, str(path), f"{router['site_name']}: {path.name} · {age_h:.1f}h old · {suffix}"))
        except Exception as exc:
            results.append(("critical", str(path), f"{router['site_name']}: {path}: {exc}"))
    return results


def verify_backups():
    migrations.migrate()
    checked = now_iso()
    records = []

    db_backup, db_backup_kind = _latest_db_backup()
    if not db_backup:
        records.append(("database", "", "warning", "No local Tikcentral database backup found yet"))
    else:
        try:
            detail = _verify_database_backup(db_backup)
            backup_age_h = max(0.0, (datetime.now(timezone.utc).timestamp() - db_backup.stat().st_mtime) / 3600)
            if db_backup_kind == "scheduled":
                status = "critical" if backup_age_h > DB_BACKUP_CRITICAL_HOURS else ("warning" if backup_age_h > DB_BACKUP_WARN_HOURS else "ok")
                records.append(("database", str(db_backup), status, f"{detail} · backup age {backup_age_h:.1f}h"))
            else:
                status = "critical" if backup_age_h > DB_BACKUP_CRITICAL_HOURS else "warning"
                records.append((
                    "database",
                    str(db_backup),
                    status,
                    f"{detail} · backup age {backup_age_h:.1f}h · scheduled backup not found; verified latest pre-update backup instead",
                ))
        except Exception as exc:
            records.append(("database", str(db_backup), "critical", str(exc)))

    router_results = _router_backup_status()
    if not router_results:
        records.append(("router", "", "warning", "No enabled routers to verify"))
    else:
        for status, path, detail in router_results:
            records.append(("router", path, status, detail))

    with core.db() as conn:
        for kind, path, status, detail in records:
            conn.execute(
                "INSERT INTO backup_verifications(checked_at,kind,path,status,details) VALUES(?,?,?,?,?)",
                (checked, kind, path, status, detail[:4000]),
            )
        conn.execute(
            """DELETE FROM backup_verifications WHERE id NOT IN
               (SELECT id FROM backup_verifications ORDER BY id DESC LIMIT 3000)"""
        )
    return records


def scheduled_tick():
    migrations.migrate()
    with core.db() as conn:
        last_health = conn.execute(
            "SELECT checked_at FROM system_health_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_verify = conn.execute(
            "SELECT checked_at FROM backup_verifications ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if not last_health or _age_seconds(last_health["checked_at"]) >= settings.SYSTEM_HEALTH_INTERVAL_SECONDS:
        record_health()
    if not last_verify or _age_seconds(last_verify["checked_at"]) >= settings.BACKUP_VERIFY_INTERVAL_SECONDS:
        verify_backups()


def register(app, page_func):
    @app.get("/system-health", response_class=HTMLResponse)
    def system_health_page(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        csrf = core.csrf_token(request)
        overall, checks = collect_health()
        with core.db() as conn:
            health_history = conn.execute(
                "SELECT * FROM system_health_history ORDER BY id DESC LIMIT 48"
            ).fetchall()
            verifications = conn.execute(
                "SELECT * FROM backup_verifications ORDER BY id DESC LIMIT 80"
            ).fetchall()

        cards = []
        for name, result in checks.items():
            tone = "ok" if result["status"] == "ok" else ("warn" if result["status"] == "warning" else "bad")
            cards.append(
                f'''<div class="tc-health-card {tone}"><div class="big">{html.escape(name.replace("unit:","").replace("_"," "))}</div><span class="tc-status {tone}"><span class="tc-status-dot"></span>{html.escape(result["status"].upper())}</span><div class="muted" style="margin-top:7px">{html.escape(result["detail"])}</div></div>'''
            )

        verify_rows = "".join(
            f'''<tr><td>{html.escape(v["checked_at"])}</td><td>{html.escape(v["kind"])}</td><td><span class="tc-status {"ok" if v["status"]=="ok" else ("warn" if v["status"]=="warning" else "bad")}">{html.escape(v["status"])}</span></td><td>{html.escape(v["path"] or "-")}</td><td>{html.escape(v["details"])}</td></tr>'''
            for v in verifications
        ) or '<tr><td colspan="5">No backup verification has run yet.</td></tr>'

        history_dots = "".join(
            f'<span title="{html.escape(h["checked_at"])} · {html.escape(h["overall_status"])}" style="display:inline-block;width:8px;height:24px;border-radius:2px;background:{("var(--ok)" if h["overall_status"]=="ok" else ("var(--warn)" if h["overall_status"]=="warning" else "var(--danger)"))}"></span>'
            for h in reversed(health_history)
        ) or '<span class="muted">No history yet.</span>'

        overall_tone = "ok" if overall == "ok" else ("warn" if overall == "warning" else "bad")
        body = f'''<div class="panel pad"><h2>Tikcentral Self-Health</h2>
<div><span class="tc-status {overall_tone} live"><span class="tc-status-dot"></span>{html.escape(overall.upper())}</span></div>
<div class="muted" style="margin-top:8px">Local checks only: database, disk, WireGuard helper, web/Caddy, systemd units, backup storage, SSH files, Codex helper and restore verification. No paid external monitoring is used.</div>
<form method="post" action="/system-health/run" class="inline" style="margin-top:14px"><input type="hidden" name="csrf" value="{csrf}"><button class="primary">Run self-check now</button></form>
<form method="post" action="/system-health/verify-backups" class="inline" style="margin-top:14px;margin-left:8px"><input type="hidden" name="csrf" value="{csrf}"><button>Verify backups now</button></form></div>
<div class="tc-health-grid">{''.join(cards)}</div>
<div class="panel pad"><h3>Self-health history</h3><div style="display:flex;gap:3px;align-items:end;overflow:auto">{history_dots}</div></div>
<div class="panel"><div class="pad"><h3>Backup / restore verification</h3><div class="muted">Database backups are copied to an isolated temporary restore file, opened, quick-checked and validated for core schema. Router exports are opened and matched to retained snapshot hashes when possible.</div></div><table><thead><tr><th>Checked</th><th>Kind</th><th>Status</th><th>Source</th><th>Details</th></tr></thead><tbody>{verify_rows}</tbody></table></div>'''
        return page_func("System Health", body, user, "system-health")

    @app.post("/system-health/run")
    async def system_health_run(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        record_health()
        return RedirectResponse("/system-health", status_code=303)

    @app.post("/system-health/verify-backups")
    async def backup_verify_run(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        verify_backups()
        record_health()
        return RedirectResponse("/system-health", status_code=303)
