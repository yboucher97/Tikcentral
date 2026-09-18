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


def _m6(conn):
    """Persistent queue/history for read-only Codex router analysis."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_ai_analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'queued',
        requested_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        report TEXT NOT NULL DEFAULT '',
        error_code TEXT NOT NULL DEFAULT '',
        error_detail TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_ai_router_time ON router_ai_analyses(router_id,id DESC);
    CREATE INDEX IF NOT EXISTS idx_router_ai_status_time ON router_ai_analyses(status,id);
    """)


def _m7(conn):
    """Reliability control plane: transactions, maintenance, incidents and probe quality."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS change_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        job_id INTEGER,
        kind TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'running',
        created_at TEXT NOT NULL,
        finished_at TEXT NOT NULL DEFAULT '',
        pre_access TEXT NOT NULL DEFAULT '',
        post_access TEXT NOT NULL DEFAULT '',
        error_code TEXT NOT NULL DEFAULT '',
        error_detail TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_change_transactions_router_time ON change_transactions(router_id,id DESC);
    CREATE TABLE IF NOT EXISTS change_transaction_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id INTEGER NOT NULL,
        step_at TEXT NOT NULL,
        phase TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(transaction_id) REFERENCES change_transactions(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_change_steps_tx ON change_transaction_steps(transaction_id,id);
    CREATE TABLE IF NOT EXISTS router_maintenance (
        router_id INTEGER PRIMARY KEY,
        start_at TEXT NOT NULL,
        end_at TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS fleet_incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        opened_at TEXT NOT NULL,
        resolved_at TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'open',
        kind TEXT NOT NULL DEFAULT 'access',
        router_count INTEGER NOT NULL DEFAULT 0,
        router_ids TEXT NOT NULL DEFAULT '[]',
        summary TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_fleet_incidents_status_time ON fleet_incidents(status,id DESC);
    """)
    for name, definition in {
        "ssh_latency_ms": "REAL",
        "winbox_latency_ms": "REAL",
        "api_latency_ms": "REAL",
    }.items():
        if not _has_column(conn, "router_access_history", name):
            conn.execute(f"ALTER TABLE router_access_history ADD COLUMN {name} {definition}")


def _m8(conn):
    """Known-good management state, attributed config snapshots and WAN history."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_management_known_good (
        router_id INTEGER PRIMARY KEY,
        captured_at TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        content TEXT NOT NULL,
        source_kind TEXT NOT NULL DEFAULT '',
        source_id INTEGER,
        source_actor TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS router_wan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        active_default_routes INTEGER NOT NULL DEFAULT 0,
        dhcp_bound INTEGER NOT NULL DEFAULT 0,
        pppoe_running INTEGER NOT NULL DEFAULT 0,
        internet_ping INTEGER,
        dns_ok INTEGER,
        summary TEXT NOT NULL DEFAULT '',
        fingerprint TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_wan_history_router_time
      ON router_wan_history(router_id,captured_at DESC);
    """)
    for name, definition in {
        "source_kind": "TEXT NOT NULL DEFAULT ''",
        "source_id": "INTEGER",
        "source_actor": "TEXT NOT NULL DEFAULT ''",
    }.items():
        if not _has_column(conn, "router_snapshots", name):
            conn.execute(f"ALTER TABLE router_snapshots ADD COLUMN {name} {definition}")


def _m9(conn):
    """Access escalation/flap state plus local health and backup verification history."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_access_alert_state (
        router_id INTEGER PRIMARY KEY,
        outage_started_at TEXT NOT NULL DEFAULT '',
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        escalation_level INTEGER NOT NULL DEFAULT 0,
        last_transition_at TEXT NOT NULL DEFAULT '',
        last_flap_alert_at TEXT NOT NULL DEFAULT '',
        last_flap_count INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS system_health_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        checked_at TEXT NOT NULL,
        overall_status TEXT NOT NULL,
        checks_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_system_health_time ON system_health_history(id DESC);
    CREATE TABLE IF NOT EXISTS backup_verifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        checked_at TEXT NOT NULL,
        kind TEXT NOT NULL,
        path TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_backup_verifications_time ON backup_verifications(id DESC);
    """)


def _m10(conn):
    """Resource anomaly state and operator audit history."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_resource_alerts (
        router_id INTEGER NOT NULL,
        metric TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 0,
        first_seen_at TEXT NOT NULL DEFAULT '',
        last_seen_at TEXT NOT NULL DEFAULT '',
        last_value TEXT NOT NULL DEFAULT '',
        PRIMARY KEY(router_id,metric),
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS operator_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_at TEXT NOT NULL,
        actor TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL,
        method TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '',
        source_ip TEXT NOT NULL DEFAULT '',
        status_code INTEGER,
        details TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_operator_audit_time ON operator_audit_log(id DESC);
    CREATE INDEX IF NOT EXISTS idx_operator_audit_actor_time ON operator_audit_log(actor,id DESC);
    """)


def _m11(conn):
    """RBAC/incident-analysis metadata."""
    for name, definition in {
        "focus_start": "TEXT NOT NULL DEFAULT ''",
        "focus_end": "TEXT NOT NULL DEFAULT ''",
        "focus_note": "TEXT NOT NULL DEFAULT ''",
    }.items():
        if not _has_column(conn, "router_ai_analyses", name):
            conn.execute(f"ALTER TABLE router_ai_analyses ADD COLUMN {name} {definition}")


def _m12(conn):
    """Public-IP/ISP enrichment history."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_public_ip_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        public_ip TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        lookup_at TEXT NOT NULL DEFAULT '',
        isp TEXT NOT NULL DEFAULT '',
        organization TEXT NOT NULL DEFAULT '',
        asn TEXT NOT NULL DEFAULT '',
        country TEXT NOT NULL DEFAULT '',
        region TEXT NOT NULL DEFAULT '',
        city TEXT NOT NULL DEFAULT '',
        lookup_status TEXT NOT NULL DEFAULT '',
        lookup_error TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE,
        UNIQUE(router_id,public_ip)
    );
    CREATE INDEX IF NOT EXISTS idx_router_public_ip_router_time
      ON router_public_ip_history(router_id,last_seen_at DESC);
    CREATE INDEX IF NOT EXISTS idx_router_public_ip_ip
      ON router_public_ip_history(public_ip);
    """)


def _m13(conn):
    """Golden-policy compliance and LTE observability."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_policy_compliance (
        router_id INTEGER PRIMARY KEY,
        checked_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'unknown',
        passed INTEGER NOT NULL DEFAULT 0,
        warnings INTEGER NOT NULL DEFAULT 0,
        failed INTEGER NOT NULL DEFAULT 0,
        details_json TEXT NOT NULL DEFAULT '[]',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS router_lte_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        interface TEXT NOT NULL DEFAULT '',
        registered INTEGER,
        operator TEXT NOT NULL DEFAULT '',
        access_technology TEXT NOT NULL DEFAULT '',
        band TEXT NOT NULL DEFAULT '',
        ca_band TEXT NOT NULL DEFAULT '',
        cell_id TEXT NOT NULL DEFAULT '',
        enb_id TEXT NOT NULL DEFAULT '',
        sector_id TEXT NOT NULL DEFAULT '',
        phy_cell_id TEXT NOT NULL DEFAULT '',
        rsrp REAL,
        rsrq REAL,
        sinr REAL,
        rssi REAL,
        raw TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_lte_router_time
      ON router_lte_history(router_id,captured_at DESC);
    """)


MIGRATIONS = [_m1, _m2, _m3, _m4, _m5, _m6, _m7, _m8, _m9, _m10, _m11, _m12, _m13]


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
