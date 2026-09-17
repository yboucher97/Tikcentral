"""Versioned SQLite migrations for Tikcentral.

All persistent schema is created here. Existing installations are migrated with
CREATE/ALTER operations that preserve data. Application modules must not create
or alter tables at runtime outside this file.
"""

import sqlite3
from pathlib import Path

from app import settings


def _connect():
    Path(settings.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _has_column(conn, table: str, column: str) -> bool:
    return column in {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _m1(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS enrollment_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT NOT NULL UNIQUE,
        site_name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        provision_mode TEXT NOT NULL DEFAULT 'enroll',
        performance_profile TEXT NOT NULL DEFAULT 'throughput'
    );
    CREATE TABLE IF NOT EXISTS routers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_name TEXT NOT NULL,
        identity TEXT NOT NULL DEFAULT '',
        serial TEXT NOT NULL DEFAULT '',
        model TEXT NOT NULL DEFAULT '',
        routeros_version TEXT NOT NULL DEFAULT '',
        routerboot_version TEXT NOT NULL DEFAULT '',
        public_key TEXT NOT NULL UNIQUE,
        vpn_ip TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1,
        winbox_port INTEGER NOT NULL DEFAULT 8291,
        public_winbox_port INTEGER,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS authorized_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL DEFAULT '',
        always_allow INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    """)


def _m2(conn):
    conn.executescript(f"""
    CREATE TABLE IF NOT EXISTS operations_settings (
        id INTEGER PRIMARY KEY CHECK(id=1),
        telemetry_interval_seconds INTEGER NOT NULL DEFAULT {settings.TELEMETRY_INTERVAL_SECONDS},
        drift_interval_seconds INTEGER NOT NULL DEFAULT {settings.DRIFT_INTERVAL_SECONDS},
        last_telemetry_at TEXT NOT NULL DEFAULT '',
        last_drift_at TEXT NOT NULL DEFAULT ''
    );
    INSERT OR IGNORE INTO operations_settings(id) VALUES(1);
    CREATE TABLE IF NOT EXISTS router_telemetry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        cpu_load INTEGER,
        free_memory TEXT NOT NULL DEFAULT '',
        total_memory TEXT NOT NULL DEFAULT '',
        uptime TEXT NOT NULL DEFAULT '',
        routeros_version TEXT NOT NULL DEFAULT '',
        routerboot_current TEXT NOT NULL DEFAULT '',
        routerboot_upgrade TEXT NOT NULL DEFAULT '',
        fasttrack_enabled INTEGER NOT NULL DEFAULT 0,
        qos_enabled INTEGER NOT NULL DEFAULT 0,
        tenant_queues_enabled INTEGER NOT NULL DEFAULT 0,
        raw_rule_count INTEGER NOT NULL DEFAULT 0,
        mss_clamp_enabled INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_router_telemetry_router_time ON router_telemetry(router_id,captured_at DESC);
    CREATE TABLE IF NOT EXISTS router_expected_state (
        router_id INTEGER PRIMARY KEY,
        expected_profile TEXT NOT NULL DEFAULT 'throughput',
        baseline_sha256 TEXT NOT NULL DEFAULT '',
        baseline_at TEXT NOT NULL DEFAULT '',
        last_drift_check_at TEXT NOT NULL DEFAULT '',
        drifted INTEGER NOT NULL DEFAULT 0,
        commissioning_status TEXT NOT NULL DEFAULT 'not_checked',
        commissioning_at TEXT NOT NULL DEFAULT '',
        commissioning_report TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS router_backup_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        tier TEXT NOT NULL,
        created_by TEXT NOT NULL DEFAULT '',
        result TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_router_backup_records_router_time ON router_backup_records(router_id,created_at DESC);
    CREATE TABLE IF NOT EXISTS approved_versions (
        model TEXT PRIMARY KEY,
        version TEXT NOT NULL,
        approved_at TEXT NOT NULL,
        approved_by TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS router_update_status (
        router_id INTEGER PRIMARY KEY,
        checked_at TEXT NOT NULL DEFAULT '',
        current_version TEXT NOT NULL DEFAULT '',
        latest_version TEXT NOT NULL DEFAULT '',
        update_status TEXT NOT NULL DEFAULT '',
        last_error TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS router_rescue_ports (
        router_id INTEGER PRIMARY KEY,
        enabled INTEGER NOT NULL DEFAULT 0,
        interface TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL DEFAULT '10.255.255.1/24',
        updated_at TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS router_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER,
        event_at TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'info',
        category TEXT NOT NULL DEFAULT 'system',
        summary TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_router_events_router_time ON router_events(router_id,event_at DESC);
    CREATE TABLE IF NOT EXISTS router_access_state (
        router_id INTEGER PRIMARY KEY,
        checked_at TEXT NOT NULL,
        wg_online INTEGER NOT NULL DEFAULT 0,
        ssh_open INTEGER NOT NULL DEFAULT 0,
        winbox_open INTEGER NOT NULL DEFAULT 0,
        api_open INTEGER NOT NULL DEFAULT 0,
        management_ok INTEGER NOT NULL DEFAULT 0,
        last_good_at TEXT NOT NULL DEFAULT '',
        last_error TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS router_access_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        checked_at TEXT NOT NULL,
        wg_online INTEGER NOT NULL DEFAULT 0,
        ssh_open INTEGER NOT NULL DEFAULT 0,
        winbox_open INTEGER NOT NULL DEFAULT 0,
        api_open INTEGER NOT NULL DEFAULT 0,
        management_ok INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_router_access_history_router_time ON router_access_history(router_id,checked_at DESC);
    CREATE TABLE IF NOT EXISTS router_capabilities (
        router_id INTEGER PRIMARY KEY,
        mode TEXT NOT NULL DEFAULT 'tikcentral_only',
        supports_performance_profiles INTEGER NOT NULL DEFAULT 0,
        supports_rescue INTEGER NOT NULL DEFAULT 1,
        detected_at TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'detected'
    );
    CREATE TABLE IF NOT EXISTS router_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER,
        kind TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        actor TEXT NOT NULL DEFAULT '',
        target TEXT NOT NULL DEFAULT '',
        payload TEXT NOT NULL DEFAULT '',
        error_code TEXT NOT NULL DEFAULT '',
        error_message TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        started_at TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        finished_at TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_router_jobs_router_status ON router_jobs(router_id,status,id DESC);
    CREATE INDEX IF NOT EXISTS idx_router_jobs_status ON router_jobs(status,id);
    CREATE TABLE IF NOT EXISTS provisioning_settings (
        id INTEGER PRIMARY KEY CHECK(id=1),
        admin_username TEXT NOT NULL DEFAULT '',
        admin_password_enc TEXT NOT NULL DEFAULT ''
    );
    INSERT OR IGNORE INTO provisioning_settings(id) VALUES(1);
    """)


def _m3(conn):
    if not _has_column(conn, "enrollment_tokens", "provision_mode"):
        conn.execute("ALTER TABLE enrollment_tokens ADD COLUMN provision_mode TEXT NOT NULL DEFAULT 'enroll'")
    if not _has_column(conn, "enrollment_tokens", "performance_profile"):
        conn.execute("ALTER TABLE enrollment_tokens ADD COLUMN performance_profile TEXT NOT NULL DEFAULT 'throughput'")
    columns = {
        "winbox_port": "INTEGER NOT NULL DEFAULT 8291",
        "public_winbox_port": "INTEGER",
        "model": "TEXT NOT NULL DEFAULT ''",
        "routeros_version": "TEXT NOT NULL DEFAULT ''",
        "routerboot_version": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in columns.items():
        if not _has_column(conn, "routers", name):
            conn.execute(f"ALTER TABLE routers ADD COLUMN {name} {definition}")


def _m4(conn):
    conn.execute("CREATE INDEX IF NOT EXISTS idx_router_backup_records_router_time ON router_backup_records(router_id,created_at DESC)")


def _m5(conn):
    """Move the historical fleet/automation schema under migration ownership."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS fleet_settings (
        id INTEGER PRIMARY KEY CHECK(id=1),
        backups_enabled INTEGER NOT NULL DEFAULT 1,
        backup_time TEXT NOT NULL DEFAULT '03:00',
        timezone TEXT NOT NULL DEFAULT 'America/Toronto',
        backup_retention_days INTEGER NOT NULL DEFAULT 30,
        analysis_enabled INTEGER NOT NULL DEFAULT 1,
        last_backup_date TEXT NOT NULL DEFAULT ''
    );
    INSERT OR IGNORE INTO fleet_settings(id) VALUES(1);
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
    CREATE INDEX IF NOT EXISTS idx_fleet_job_results_job ON fleet_job_results(job_id,id);
    CREATE INDEX IF NOT EXISTS idx_fleet_findings_router_time ON fleet_findings(router_id,detected_at DESC);
    """)


MIGRATIONS = [_m1, _m2, _m3, _m4, _m5]


def migrate() -> int:
    with _connect() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
        applied = {int(r[0]) for r in conn.execute("SELECT version FROM schema_version")}
        for version, fn in enumerate(MIGRATIONS, start=1):
            if version in applied:
                continue
            fn(conn)
            conn.execute("INSERT INTO schema_version(version) VALUES(?)", (version,))
        conn.commit()
        return len(MIGRATIONS)


def current_version() -> int:
    migrate()
    with _connect() as conn:
        row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return int(row[0] or 0)
