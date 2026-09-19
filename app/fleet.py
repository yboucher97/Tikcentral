"""Fleet backup and read-only analysis helpers.

Router-changing operations are owned by app.jobs/app.operations. Fleet backups
acquire the same per-router mutation slot; read-only analysis skips busy routers.
"""

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from app import errors
from app import events
from app import jobs
from app import main as core
from app import migrations
from app import router_exec
from app import settings
from app import state_capture


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _ros_string(value: str) -> str:
    return (value or "").replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")


def ensure_schema():
    migrations.migrate()


def enabled_routers(*, skip_busy: bool = True):
    busy = jobs.active_change_router_ids() if skip_busy else set()
    with core.db() as conn:
        rows = conn.execute(
            "SELECT id,site_name,vpn_ip FROM routers WHERE enabled=1 AND COALESCE(lifecycle_state,'production')<>'retired' ORDER BY site_name COLLATE NOCASE,id"
        ).fetchall()
    return [row for row in rows if int(row["id"]) not in busy]


def create_job(job_type: str, command: str = "", created_by: str = "system"):
    ensure_schema()
    with core.db() as conn:
        cur = conn.execute(
            "INSERT INTO fleet_jobs(job_type,command,status,created_by,created_at) VALUES(?,?,?,?,?)",
            (job_type, command, "queued", created_by, now_iso()),
        )
        return cur.lastrowid


def _record_result(job_id, router, status, output, error, started, finished):
    with core.db() as conn:
        conn.execute(
            "INSERT INTO fleet_job_results(job_id,router_id,site_name,vpn_ip,status,output,error,started_at,finished_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (job_id, router["id"], router["site_name"], router["vpn_ip"], status, output[-20000:], error[-2000:], started, finished),
        )


def _finish_job(job_id):
    with core.db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) total, SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) ok FROM fleet_job_results WHERE job_id=?",
            (job_id,),
        ).fetchone()
        total = int(row["total"] or 0)
        ok = int(row["ok"] or 0)
        conn.execute(
            "UPDATE fleet_jobs SET status=?,finished_at=?,total=?,succeeded=?,failed=? WHERE id=?",
            ("success" if total == ok else "completed_with_errors", now_iso(), total, ok, total - ok, job_id),
        )


def _run_read_job(job_type: str, command: str, created_by: str):
    routers = enabled_routers(skip_busy=True)
    job_id = create_job(job_type, command, created_by)
    with core.db() as conn:
        conn.execute(
            "UPDATE fleet_jobs SET status='running',started_at=?,total=? WHERE id=?",
            (now_iso(), len(routers), job_id),
        )

    def one(router):
        started = now_iso()
        try:
            out = router_exec.read(
                router["vpn_ip"], command,
                timeout=max(settings.SSH_TIMEOUT + 15, 45),
                label=f"Fleet {job_type}",
            )
            return router, "success", out, "", started, now_iso()
        except Exception as exc:
            return router, "error", "", errors.short(exc), started, now_iso()

    with ThreadPoolExecutor(max_workers=max(1, min(settings.MAX_WORKERS, len(routers) or 1))) as pool:
        futures = [pool.submit(one, router) for router in routers]
        for future in as_completed(futures):
            _record_result(job_id, *future.result())
    _finish_job(job_id)
    return job_id


def _root_is_writable(root: Path, router_id=None) -> bool:
    try:
        root.mkdir(parents=True, exist_ok=True)
        target = root / str(router_id) if router_id is not None else root
        target.mkdir(parents=True, exist_ok=True)
        probe = target / ".tikcentral-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def backup_root(router_id=None) -> Path:
    for root in (settings.BACKUP_ROOT, settings.BACKUP_FALLBACK_ROOT):
        if _root_is_writable(root, router_id):
            return root
    raise PermissionError("Tikcentral cannot write to either configured router-backup location")


def _backup_one(router, stamp, tier="daily"):
    if tier not in {"daily", "pre-change", "commissioning"}:
        raise ValueError("invalid backup tier")
    base = backup_root(router["id"]) / str(router["id"]) / tier
    base.mkdir(parents=True, exist_ok=True)
    export = router_exec.read(
        router["vpn_ip"], "/export terse",
        timeout=60, label="Configuration export",
    )
    export_path = base / f"{stamp}.rsc"
    export_path.write_text(export + "\n", encoding="utf-8")

    binary_note = ""
    if settings.BACKUP_PASSWORD:
        remote_name = f"tikcentral-{stamp}"
        safe_pw = _ros_string(settings.BACKUP_PASSWORD)
        router_exec.mutate(
            router["vpn_ip"],
            f'/system backup save name={remote_name} password="{safe_pw}"',
            timeout=90,
            label="Router binary backup",
        )
        binary_path = base / f"{stamp}.backup"
        try:
            router_exec.sftp_get_remove(router["vpn_ip"], f"{remote_name}.backup", str(binary_path), timeout=120)
        except Exception as exc:
            binary_note = f"; binary backup retrieval failed: {errors.short(exc)}"

    digest = hashlib.sha256(export.encode()).hexdigest()
    state_capture.store_config_snapshot_content(
        int(router["id"]),
        export,
        source_kind=f"backup:{tier}",
        actor="backup",
    )
    return f"Saved {export_path}{binary_note}"


def run_backup_job(created_by="scheduler"):
    ensure_schema()
    # Include every enabled router. The per-router job reservation below is the
    # authoritative race-free concurrency check; a router that becomes busy is
    # reported explicitly instead of silently omitted from "backup all".
    routers = enabled_routers(skip_busy=False)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    job_id = create_job("backup", "configuration + binary backup", created_by)
    with core.db() as conn:
        conn.execute(
            "UPDATE fleet_jobs SET status='running',started_at=?,total=? WHERE id=?",
            (now_iso(), len(routers), job_id),
        )

    def one(router):
        started = now_iso()
        try:
            with jobs.operation(
                int(router["id"]),
                "backup",
                created_by,
                "daily",
                serialize_router=True,
                fail_code="BACKUP_FAILED",
                fail_message="Fleet router backup failed",
            ):
                out = _backup_one(router, stamp, tier="daily")
                with core.db() as conn:
                    conn.execute(
                        "INSERT INTO router_backup_records(router_id,created_at,tier,created_by,result) VALUES(?,?,?,?,?)",
                        (router["id"], now_iso(), "daily", created_by, out),
                    )
            return router, "success", out, "", started, now_iso()
        except Exception as exc:
            return router, "error", "", errors.short(exc), started, now_iso()

    with ThreadPoolExecutor(max_workers=max(1, min(settings.MAX_WORKERS, len(routers) or 1))) as pool:
        for future in as_completed([pool.submit(one, router) for router in routers]):
            _record_result(job_id, *future.result())
    _finish_job(job_id)
    cleanup_backups()
    return job_id


def cleanup_backups():
    ensure_schema()
    now = datetime.now(timezone.utc)
    with core.db() as conn:
        days = int(conn.execute("SELECT backup_retention_days FROM fleet_settings WHERE id=1").fetchone()[0])
    cutoff = now.timestamp() - days * 86400
    for root in (settings.BACKUP_ROOT, settings.BACKUP_FALLBACK_ROOT):
        if not root.exists():
            continue
        for daily in root.glob("*/daily"):
            if not daily.is_dir():
                continue
            for path in daily.rglob("*"):
                if path.is_file() and path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
    # Daily backup history represents recoverable retained backups, not an
    # eternal audit trail. Keep it aligned with the files rotated above; the
    # separately-retained pre-change/commissioning tiers are never touched.
    cutoff_iso = (now - timedelta(days=days)).isoformat()
    with core.db() as conn:
        conn.execute(
            "DELETE FROM router_backup_records WHERE tier='daily' AND created_at<?",
            (cutoff_iso,),
        )


def run_analysis_job(created_by="scheduler"):
    command = '/system resource print; /interface print stats; /log print where topics~"critical|error|warning"'
    job_id = _run_read_job("analysis", command, created_by)
    with core.db() as conn:
        results = conn.execute(
            "SELECT router_id,output FROM fleet_job_results WHERE job_id=? AND status='success'",
            (job_id,),
        ).fetchall()
        for row in results:
            low = row["output"].lower()
            findings = []
            if "critical" in low:
                findings.append(("critical", "logs", "Critical log entries detected"))
            if "error" in low:
                findings.append(("warning", "logs", "Error log entries detected"))
            if "warning" in low:
                findings.append(("info", "logs", "Warning log entries detected"))
            for severity, category, summary in findings:
                conn.execute(
                    "INSERT INTO fleet_findings(router_id,detected_at,severity,category,summary,evidence) VALUES(?,?,?,?,?,?)",
                    (row["router_id"], now_iso(), severity, category, summary, row["output"][-4000:]),
                )
    return job_id


def scheduled_tick():
    ensure_schema()
    with core.db() as conn:
        config = conn.execute("SELECT * FROM fleet_settings WHERE id=1").fetchone()
    if not config["backups_enabled"]:
        return None
    try:
        local = datetime.now(ZoneInfo(config["timezone"] or settings.TIMEZONE))
    except Exception:
        local = datetime.now(ZoneInfo(settings.TIMEZONE))
    today = local.date().isoformat()
    if local.strftime("%H:%M") < config["backup_time"] or config["last_backup_date"] == today:
        return None
    job_id = run_backup_job("scheduler")
    # Mark today's backup before optional analysis. Analysis is deliberately
    # best-effort and must never cause the daily backup to repeat every timer
    # tick if its read-only probes fail.
    with core.db() as conn:
        conn.execute("UPDATE fleet_settings SET last_backup_date=? WHERE id=1", (today,))
    if config["analysis_enabled"]:
        try:
            run_analysis_job("scheduler")
        except Exception as exc:
            try:
                events.record(None, "fleet-analysis", "Post-backup fleet analysis failed", errors.short(exc), "warning")
            except Exception:
                pass
    return job_id
