import hashlib
import os
import shutil
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from app import main as core

SSH_USER = os.getenv("TIKCENTRAL_ROUTER_USER", "tikcentral")
SSH_KEY = os.getenv("TIKCENTRAL_SSH_KEY", "/etc/tikcentral/ssh/tikcentral_ed25519")
KNOWN_HOSTS = os.getenv("TIKCENTRAL_KNOWN_HOSTS", "/var/lib/tikcentral/known_hosts")
ROUTER_BACKUP_DIR = os.getenv("ROUTER_BACKUP_DIR", "/var/backups/tikcentral/routers")
BACKUP_PASSWORD = os.getenv("ROUTER_BACKUP_PASSWORD", "")
SSH_TIMEOUT = int(os.getenv("TIKCENTRAL_SSH_TIMEOUT", "20"))
MAX_WORKERS = int(os.getenv("TIKCENTRAL_FLEET_WORKERS", "8"))

FLEET_SCHEMA = """
CREATE TABLE IF NOT EXISTS fleet_settings (
    id INTEGER PRIMARY KEY CHECK(id=1),
    backups_enabled INTEGER NOT NULL DEFAULT 1,
    backup_time TEXT NOT NULL DEFAULT '03:00',
    timezone TEXT NOT NULL DEFAULT 'America/Toronto',
    backup_retention_days INTEGER NOT NULL DEFAULT 30,
    analysis_enabled INTEGER NOT NULL DEFAULT 1,
    last_backup_date TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS fleet_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type TEXT NOT NULL,
    command TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    total INTEGER NOT NULL DEFAULT 0,
    succeeded INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS fleet_job_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    router_id INTEGER NOT NULL,
    site_name TEXT NOT NULL,
    vpn_ip TEXT NOT NULL,
    status TEXT NOT NULL,
    output TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    FOREIGN KEY(job_id) REFERENCES fleet_jobs(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS router_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    captured_at TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    content TEXT NOT NULL,
    UNIQUE(router_id, sha256)
);
CREATE TABLE IF NOT EXISTS fleet_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    detected_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence TEXT NOT NULL DEFAULT ''
);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_schema():
    with core.db() as conn:
        conn.executescript(FLEET_SCHEMA)
        conn.execute("INSERT OR IGNORE INTO fleet_settings(id) VALUES(1)")


def ssh_base(ip: str):
    return [
        "ssh", "-T", "-i", SSH_KEY,
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={SSH_TIMEOUT}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
        f"{SSH_USER}@{ip}",
    ]


def ssh_exec(ip: str, command: str, timeout: int | None = None):
    Path(KNOWN_HOSTS).parent.mkdir(parents=True, exist_ok=True)
    Path(KNOWN_HOSTS).touch(exist_ok=True)
    p = subprocess.run(
        ssh_base(ip) + [command], capture_output=True, text=True,
        timeout=timeout or SSH_TIMEOUT + 15,
    )
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or f"ssh exited {p.returncode}").strip())
    return p.stdout.strip()


def enabled_routers():
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,vpn_ip FROM routers WHERE enabled=1 ORDER BY site_name COLLATE NOCASE,id"
        ).fetchall()


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
            (job_id, router["id"], router["site_name"], router["vpn_ip"], status, output[-20000:], error[-10000:], started, finished),
        )


def _finish_job(job_id):
    with core.db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) total, SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) ok FROM fleet_job_results WHERE job_id=?",
            (job_id,),
        ).fetchone()
        total = int(row["total"] or 0); ok = int(row["ok"] or 0)
        conn.execute(
            "UPDATE fleet_jobs SET status=?,finished_at=?,total=?,succeeded=?,failed=? WHERE id=?",
            ("success" if total == ok else "completed_with_errors", now_iso(), total, ok, total-ok, job_id),
        )


def run_mass_command(command: str, created_by: str = "admin"):
    routers = enabled_routers()
    job_id = create_job("command", command, created_by)
    with core.db() as conn:
        conn.execute("UPDATE fleet_jobs SET status='running',started_at=?,total=? WHERE id=?", (now_iso(), len(routers), job_id))

    def one(router):
        started = now_iso()
        try:
            out = ssh_exec(router["vpn_ip"], command, timeout=max(SSH_TIMEOUT + 15, 45))
            return router, "success", out, "", started, now_iso()
        except Exception as exc:
            return router, "error", "", str(exc), started, now_iso()

    with ThreadPoolExecutor(max_workers=max(1, min(MAX_WORKERS, len(routers) or 1))) as pool:
        futures = [pool.submit(one, r) for r in routers]
        for fut in as_completed(futures):
            _record_result(job_id, *fut.result())
    _finish_job(job_id)
    return job_id


def _backup_one(router, stamp):
    base = Path(ROUTER_BACKUP_DIR) / str(router["id"])
    base.mkdir(parents=True, exist_ok=True)
    export = ssh_exec(router["vpn_ip"], "/export show-sensitive=no terse", timeout=60)
    export_path = base / f"{stamp}.rsc"
    export_path.write_text(export + "\n", encoding="utf-8")

    binary_note = ""
    if BACKUP_PASSWORD:
        remote_name = f"tikcentral-{stamp}"
        safe_pw = BACKUP_PASSWORD.replace('"', '')
        ssh_exec(router["vpn_ip"], f'/system backup save name={remote_name} password="{safe_pw}"', timeout=90)
        binary_path = base / f"{stamp}.backup"
        batch = f"get {remote_name}.backup {binary_path}\nrm {remote_name}.backup\n"
        p = subprocess.run(
            ["sftp", "-b", "-", "-i", SSH_KEY,
             "-o", "BatchMode=yes", "-o", f"ConnectTimeout={SSH_TIMEOUT}",
             "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
             f"{SSH_USER}@{router['vpn_ip']}"],
            input=batch, capture_output=True, text=True, timeout=120,
        )
        if p.returncode != 0:
            binary_note = f"; binary backup retrieval failed: {(p.stderr or p.stdout).strip()}"
    digest = hashlib.sha256(export.encode()).hexdigest()
    with core.db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO router_snapshots(router_id,captured_at,sha256,content) VALUES(?,?,?,?)",
            (router["id"], now_iso(), digest, export),
        )
    return f"Saved {export_path}{binary_note}"


def run_backup_job(created_by="scheduler"):
    ensure_schema()
    routers = enabled_routers()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    job_id = create_job("backup", "configuration + binary backup", created_by)
    with core.db() as conn:
        conn.execute("UPDATE fleet_jobs SET status='running',started_at=?,total=? WHERE id=?", (now_iso(), len(routers), job_id))

    def one(router):
        started = now_iso()
        try:
            out = _backup_one(router, stamp)
            return router, "success", out, "", started, now_iso()
        except Exception as exc:
            return router, "error", "", str(exc), started, now_iso()

    with ThreadPoolExecutor(max_workers=max(1, min(MAX_WORKERS, len(routers) or 1))) as pool:
        for fut in as_completed([pool.submit(one, r) for r in routers]):
            _record_result(job_id, *fut.result())
    _finish_job(job_id)
    cleanup_backups()
    return job_id


def cleanup_backups():
    ensure_schema()
    with core.db() as conn:
        days = int(conn.execute("SELECT backup_retention_days FROM fleet_settings WHERE id=1").fetchone()[0])
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    root = Path(ROUTER_BACKUP_DIR)
    if root.exists():
        for p in root.rglob("*"):
            if p.is_file() and p.stat().st_mtime < cutoff:
                p.unlink(missing_ok=True)


def run_analysis_job(created_by="scheduler"):
    cmd = '/system resource print; /interface print stats; /log print where topics~"critical|error|warning"'
    job_id = run_mass_command(cmd, created_by)
    with core.db() as conn:
        results = conn.execute("SELECT router_id,output FROM fleet_job_results WHERE job_id=? AND status='success'", (job_id,)).fetchall()
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
        s = conn.execute("SELECT * FROM fleet_settings WHERE id=1").fetchone()
    if not s["backups_enabled"]:
        return None
    try:
        local = datetime.now(ZoneInfo(s["timezone"]))
    except Exception:
        local = datetime.now(ZoneInfo("America/Toronto"))
    today = local.date().isoformat()
    if local.strftime("%H:%M") < s["backup_time"] or s["last_backup_date"] == today:
        return None
    job_id = run_backup_job("scheduler")
    if s["analysis_enabled"]:
        run_analysis_job("scheduler")
    with core.db() as conn:
        conn.execute("UPDATE fleet_settings SET last_backup_date=? WHERE id=1", (today,))
    return job_id
