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


def _m14(conn):
    """Interface health, outage classification and site/customer metadata."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_interface_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        name TEXT NOT NULL,
        interface_type TEXT NOT NULL DEFAULT '',
        running INTEGER,
        disabled INTEGER,
        rx_bytes INTEGER,
        tx_bytes INTEGER,
        rx_packets INTEGER,
        tx_packets INTEGER,
        rx_errors INTEGER,
        tx_errors INTEGER,
        rx_drops INTEGER,
        tx_drops INTEGER,
        link_downs INTEGER,
        rate TEXT NOT NULL DEFAULT '',
        full_duplex INTEGER,
        auto_negotiation TEXT NOT NULL DEFAULT '',
        poe_out TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_interface_router_time
      ON router_interface_history(router_id,captured_at DESC);
    CREATE INDEX IF NOT EXISTS idx_router_interface_name_time
      ON router_interface_history(router_id,name,captured_at DESC);

    CREATE TABLE IF NOT EXISTS router_outage_assessment (
        router_id INTEGER PRIMARY KEY,
        assessed_at TEXT NOT NULL,
        classification TEXT NOT NULL DEFAULT 'unknown',
        confidence TEXT NOT NULL DEFAULT 'low',
        summary TEXT NOT NULL DEFAULT '',
        evidence TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS router_site_metadata (
        router_id INTEGER PRIMARY KEY,
        customer_name TEXT NOT NULL DEFAULT '',
        site_code TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL DEFAULT '',
        contact_name TEXT NOT NULL DEFAULT '',
        contact_phone TEXT NOT NULL DEFAULT '',
        contact_email TEXT NOT NULL DEFAULT '',
        circuit_type TEXT NOT NULL DEFAULT '',
        circuit_reference TEXT NOT NULL DEFAULT '',
        install_date TEXT NOT NULL DEFAULT '',
        ticket_reference TEXT NOT NULL DEFAULT '',
        support_notes TEXT NOT NULL DEFAULT '',
        updated_by TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    """)


def _m15(conn):
    """Protected-object ownership and recovery metadata."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_object_protection (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        object_type TEXT NOT NULL,
        selector TEXT NOT NULL,
        ownership TEXT NOT NULL DEFAULT 'customer-owned',
        protected INTEGER NOT NULL DEFAULT 1,
        notes TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_object_protection_router
      ON router_object_protection(router_id,protected,object_type);
    """)


def _m16(conn):
    """Lifecycle, maintenance work log and staged upgrade campaigns."""
    if not _has_column(conn, "routers", "lifecycle_state"):
        conn.execute("ALTER TABLE routers ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'production'")
    if not _has_column(conn, "routers", "lifecycle_updated_at"):
        conn.execute("ALTER TABLE routers ADD COLUMN lifecycle_updated_at TEXT NOT NULL DEFAULT ''")
    if not _has_column(conn, "routers", "lifecycle_updated_by"):
        conn.execute("ALTER TABLE routers ADD COLUMN lifecycle_updated_by TEXT NOT NULL DEFAULT ''")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_maintenance_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        occurred_at TEXT NOT NULL,
        technician TEXT NOT NULL DEFAULT '',
        work_type TEXT NOT NULL DEFAULT 'service',
        ticket_reference TEXT NOT NULL DEFAULT '',
        issue TEXT NOT NULL DEFAULT '',
        work_performed TEXT NOT NULL DEFAULT '',
        result TEXT NOT NULL DEFAULT '',
        follow_up TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_maintenance_history_router_time
      ON router_maintenance_history(router_id,occurred_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS upgrade_campaigns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        target_version TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        approved_by TEXT NOT NULL DEFAULT '',
        approved_at TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS upgrade_campaign_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id INTEGER NOT NULL,
        router_id INTEGER NOT NULL,
        stage TEXT NOT NULL DEFAULT 'rollout',
        status TEXT NOT NULL DEFAULT 'pending',
        job_id INTEGER,
        last_error TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(campaign_id) REFERENCES upgrade_campaigns(id) ON DELETE CASCADE,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE,
        UNIQUE(campaign_id,router_id)
    );
    CREATE INDEX IF NOT EXISTS idx_upgrade_campaign_members_campaign
      ON upgrade_campaign_members(campaign_id,stage,status,id);
    """)


def _m17(conn):
    """Change calendar, hardware inventory and certificate observability."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS planned_changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER,
        title TEXT NOT NULL,
        change_type TEXT NOT NULL DEFAULT 'maintenance',
        start_at TEXT NOT NULL,
        end_at TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'planned',
        ticket_reference TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        completed_at TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_planned_changes_start ON planned_changes(start_at,status,id);

    CREATE TABLE IF NOT EXISTS hardware_inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        category TEXT NOT NULL DEFAULT 'other',
        manufacturer TEXT NOT NULL DEFAULT '',
        model TEXT NOT NULL DEFAULT '',
        serial TEXT NOT NULL DEFAULT '',
        asset_tag TEXT NOT NULL DEFAULT '',
        location TEXT NOT NULL DEFAULT '',
        installed_at TEXT NOT NULL DEFAULT '',
        warranty_until TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'installed',
        notes TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_hardware_inventory_router ON hardware_inventory(router_id,status,category,id);

    CREATE TABLE IF NOT EXISTS router_certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        name TEXT NOT NULL,
        common_name TEXT NOT NULL DEFAULT '',
        issuer TEXT NOT NULL DEFAULT '',
        fingerprint TEXT NOT NULL DEFAULT '',
        key_usage TEXT NOT NULL DEFAULT '',
        trusted INTEGER,
        expires_at TEXT NOT NULL DEFAULT '',
        days_remaining INTEGER,
        status TEXT NOT NULL DEFAULT 'unknown',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_certificates_router_time
      ON router_certificates(router_id,captured_at DESC);
    """)


def _m18(conn):
    """Security exposure, RouterOS automation inventory and traffic history."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_security_audit (
        router_id INTEGER PRIMARY KEY,
        checked_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'unknown',
        critical_count INTEGER NOT NULL DEFAULT 0,
        warning_count INTEGER NOT NULL DEFAULT 0,
        passed_count INTEGER NOT NULL DEFAULT 0,
        details_json TEXT NOT NULL DEFAULT '[]',
        fingerprint TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS router_automation_inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        object_type TEXT NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        enabled INTEGER,
        managed INTEGER NOT NULL DEFAULT 0,
        schedule TEXT NOT NULL DEFAULT '',
        target TEXT NOT NULL DEFAULT '',
        metadata TEXT NOT NULL DEFAULT '',
        fingerprint TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_automation_router_time
      ON router_automation_inventory(router_id,captured_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS router_traffic_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        interface TEXT NOT NULL,
        rx_bytes INTEGER,
        tx_bytes INTEGER,
        interval_seconds REAL,
        rx_bps REAL,
        tx_bps REAL,
        rx_delta_bytes INTEGER,
        tx_delta_bytes INTEGER,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_traffic_router_time
      ON router_traffic_history(router_id,captured_at DESC,id DESC);
    CREATE INDEX IF NOT EXISTS idx_router_traffic_interface_time
      ON router_traffic_history(router_id,interface,captured_at DESC,id DESC);
    """)


def _m19(conn):
    """Capacity trends, customer reports and cross-object operator notes."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_capacity_forecast (
        router_id INTEGER PRIMARY KEY,
        assessed_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'insufficient_data',
        cpu_trend_per_day REAL,
        memory_free_trend_per_day REAL,
        traffic_trend_per_day REAL,
        interface_error_trend_per_day REAL,
        lte_rsrp_trend_per_day REAL,
        horizon_days INTEGER NOT NULL DEFAULT 30,
        summary TEXT NOT NULL DEFAULT '',
        details_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS operator_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER,
        object_type TEXT NOT NULL,
        object_id INTEGER,
        ticket_reference TEXT NOT NULL DEFAULT '',
        visibility TEXT NOT NULL DEFAULT 'internal',
        note TEXT NOT NULL,
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_operator_notes_router_time
      ON operator_notes(router_id,created_at DESC,id DESC);
    CREATE INDEX IF NOT EXISTS idx_operator_notes_object
      ON operator_notes(object_type,object_id,id DESC);

    CREATE TABLE IF NOT EXISTS customer_report_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        period_start TEXT NOT NULL,
        period_end TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        generated_by TEXT NOT NULL DEFAULT '',
        title TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_customer_reports_router_time
      ON customer_report_history(router_id,generated_at DESC,id DESC);
    """)


def _m20(conn):
    """Topology, multi-target WAN probes and desired-state intent."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_topology_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        source TEXT NOT NULL,
        device_type TEXT NOT NULL DEFAULT 'unknown',
        vendor TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL DEFAULT '',
        ip_address TEXT NOT NULL DEFAULT '',
        mac_address TEXT NOT NULL DEFAULT '',
        local_interface TEXT NOT NULL DEFAULT '',
        confidence TEXT NOT NULL DEFAULT 'low',
        inventory_id INTEGER,
        fingerprint TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_topology_router_time
      ON router_topology_devices(router_id,captured_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS router_wan_probe_config (
        router_id INTEGER PRIMARY KEY,
        profile TEXT NOT NULL DEFAULT 'standard',
        targets_json TEXT NOT NULL DEFAULT '[]',
        dns_name TEXT NOT NULL DEFAULT '',
        latency_warn_ms REAL,
        packet_loss_warn_percent REAL,
        updated_by TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS router_wan_probe_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        profile TEXT NOT NULL DEFAULT 'standard',
        gateway TEXT NOT NULL DEFAULT '',
        gateway_ok INTEGER,
        target1 TEXT NOT NULL DEFAULT '',
        target1_ok INTEGER,
        target1_loss REAL,
        target1_avg_ms REAL,
        target2 TEXT NOT NULL DEFAULT '',
        target2_ok INTEGER,
        target2_loss REAL,
        target2_avg_ms REAL,
        dns_name TEXT NOT NULL DEFAULT '',
        dns_ok INTEGER,
        classification TEXT NOT NULL DEFAULT 'unknown',
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_wan_probe_router_time
      ON router_wan_probe_history(router_id,captured_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS router_desired_state (
        router_id INTEGER PRIMARY KEY,
        profile TEXT NOT NULL DEFAULT 'standard',
        intent_json TEXT NOT NULL DEFAULT '{}',
        updated_by TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS router_desired_state_status (
        router_id INTEGER PRIMARY KEY,
        checked_at TEXT NOT NULL,
        profile TEXT NOT NULL DEFAULT 'standard',
        status TEXT NOT NULL DEFAULT 'unknown',
        passed INTEGER NOT NULL DEFAULT 0,
        warnings INTEGER NOT NULL DEFAULT 0,
        failed INTEGER NOT NULL DEFAULT 0,
        details_json TEXT NOT NULL DEFAULT '[]',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    """)


def _m21(conn):
    """Router replacement, post-change automation and persistent alert queue."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_replacements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_router_id INTEGER NOT NULL,
        target_router_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'planned',
        copy_site_metadata INTEGER NOT NULL DEFAULT 1,
        copy_protection INTEGER NOT NULL DEFAULT 1,
        copy_desired_state INTEGER NOT NULL DEFAULT 1,
        copy_wan_profile INTEGER NOT NULL DEFAULT 1,
        move_hardware INTEGER NOT NULL DEFAULT 1,
        move_future_changes INTEGER NOT NULL DEFAULT 1,
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        completed_by TEXT NOT NULL DEFAULT '',
        completed_at TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(source_router_id) REFERENCES routers(id),
        FOREIGN KEY(target_router_id) REFERENCES routers(id)
    );
    CREATE INDEX IF NOT EXISTS idx_router_replacements_source ON router_replacements(source_router_id,id DESC);
    CREATE INDEX IF NOT EXISTS idx_router_replacements_target ON router_replacements(target_router_id,id DESC);

    CREATE TABLE IF NOT EXISTS maintenance_automation_settings (
        id INTEGER PRIMARY KEY CHECK(id=1),
        enabled INTEGER NOT NULL DEFAULT 1,
        run_on_upgrades INTEGER NOT NULL DEFAULT 1,
        run_on_routerboot INTEGER NOT NULL DEFAULT 1,
        run_on_all_changes INTEGER NOT NULL DEFAULT 0,
        capture_backup INTEGER NOT NULL DEFAULT 1,
        run_compliance INTEGER NOT NULL DEFAULT 1,
        run_security INTEGER NOT NULL DEFAULT 1,
        run_wan_probe INTEGER NOT NULL DEFAULT 1,
        run_interfaces INTEGER NOT NULL DEFAULT 1,
        run_desired_state INTEGER NOT NULL DEFAULT 1
    );
    INSERT OR IGNORE INTO maintenance_automation_settings(id) VALUES(1);

    CREATE TABLE IF NOT EXISTS maintenance_automation_runs (
        job_id INTEGER PRIMARY KEY,
        router_id INTEGER NOT NULL,
        job_kind TEXT NOT NULL,
        processed_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'completed',
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(job_id) REFERENCES router_jobs(id) ON DELETE CASCADE,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS alert_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_key TEXT NOT NULL UNIQUE,
        router_id INTEGER,
        severity TEXT NOT NULL DEFAULT 'warning',
        title TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '',
        link TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'new',
        assigned_to TEXT NOT NULL DEFAULT '',
        ticket_reference TEXT NOT NULL DEFAULT '',
        resolution_note TEXT NOT NULL DEFAULT '',
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        acknowledged_at TEXT NOT NULL DEFAULT '',
        resolved_at TEXT NOT NULL DEFAULT '',
        updated_by TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_alert_queue_status ON alert_queue(status,severity,last_seen_at DESC);
    CREATE INDEX IF NOT EXISTS idx_alert_queue_router ON alert_queue(router_id,status,id DESC);
    """)


def _m22(conn):
    """Tikcentral database/storage health history."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS database_health_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        checked_at TEXT NOT NULL,
        db_bytes INTEGER NOT NULL DEFAULT 0,
        wal_bytes INTEGER NOT NULL DEFAULT 0,
        shm_bytes INTEGER NOT NULL DEFAULT 0,
        total_sqlite_bytes INTEGER NOT NULL DEFAULT 0,
        filesystem_total_bytes INTEGER NOT NULL DEFAULT 0,
        filesystem_free_bytes INTEGER NOT NULL DEFAULT 0,
        growth_bytes_per_day REAL,
        estimated_days_to_80_percent REAL,
        status TEXT NOT NULL DEFAULT 'unknown',
        summary TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_database_health_time
      ON database_health_history(checked_at DESC,id DESC);
    """)


def _m23(conn):
    """Fleet config search support, retention policy and commissioning checklist."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS retention_settings (
        id INTEGER PRIMARY KEY CHECK(id=1),
        telemetry_days INTEGER NOT NULL DEFAULT 90,
        traffic_days INTEGER NOT NULL DEFAULT 90,
        lte_days INTEGER NOT NULL DEFAULT 180,
        interface_days INTEGER NOT NULL DEFAULT 180,
        wan_days INTEGER NOT NULL DEFAULT 180,
        certificate_days INTEGER NOT NULL DEFAULT 365,
        automation_days INTEGER NOT NULL DEFAULT 180,
        topology_days INTEGER NOT NULL DEFAULT 180,
        event_days INTEGER NOT NULL DEFAULT 730,
        operator_audit_days INTEGER NOT NULL DEFAULT 365,
        database_health_days INTEGER NOT NULL DEFAULT 90,
        resolved_alert_days INTEGER NOT NULL DEFAULT 730,
        snapshot_days INTEGER NOT NULL DEFAULT 0,
        updated_by TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL DEFAULT ''
    );
    INSERT OR IGNORE INTO retention_settings(id) VALUES(1);

    CREATE TABLE IF NOT EXISTS retention_cleanup_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ran_at TEXT NOT NULL,
        deleted_rows INTEGER NOT NULL DEFAULT 0,
        details TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_retention_cleanup_time
      ON retention_cleanup_history(ran_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS commissioning_checklist_settings (
        id INTEGER PRIMARY KEY CHECK(id=1),
        require_site_metadata INTEGER NOT NULL DEFAULT 1,
        require_customer INTEGER NOT NULL DEFAULT 1,
        require_management INTEGER NOT NULL DEFAULT 1,
        require_wan INTEGER NOT NULL DEFAULT 1,
        require_desired_state INTEGER NOT NULL DEFAULT 1,
        require_security INTEGER NOT NULL DEFAULT 1,
        require_backup INTEGER NOT NULL DEFAULT 1,
        require_hardware INTEGER NOT NULL DEFAULT 1,
        require_baseline INTEGER NOT NULL DEFAULT 1,
        auto_promote INTEGER NOT NULL DEFAULT 1
    );
    INSERT OR IGNORE INTO commissioning_checklist_settings(id) VALUES(1);

    CREATE TABLE IF NOT EXISTS commissioning_checklist_status (
        router_id INTEGER PRIMARY KEY,
        checked_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'incomplete',
        passed INTEGER NOT NULL DEFAULT 0,
        required INTEGER NOT NULL DEFAULT 0,
        details_json TEXT NOT NULL DEFAULT '[]',
        promoted_at TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    """)


def _m24(conn):
    """Expand retention policy to access, WAN probe and public-IP history."""
    for name,definition in {
        "access_days":"INTEGER NOT NULL DEFAULT 180",
        "wan_probe_days":"INTEGER NOT NULL DEFAULT 180",
        "public_ip_days":"INTEGER NOT NULL DEFAULT 365",
    }.items():
        if not _has_column(conn,"retention_settings",name):
            conn.execute(f"ALTER TABLE retention_settings ADD COLUMN {name} {definition}")


def _m25(conn):
    """Router time/NTP health and path-MTU diagnostics."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_time_health (
        router_id INTEGER PRIMARY KEY,
        checked_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'unknown',
        router_time TEXT NOT NULL DEFAULT '',
        timezone_name TEXT NOT NULL DEFAULT '',
        utc_offset TEXT NOT NULL DEFAULT '',
        ntp_enabled INTEGER,
        ntp_status TEXT NOT NULL DEFAULT '',
        ntp_servers TEXT NOT NULL DEFAULT '',
        drift_seconds REAL,
        summary TEXT NOT NULL DEFAULT '',
        details_json TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS router_mtu_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '1.1.1.1',
        largest_payload INTEGER,
        estimated_path_mtu INTEGER,
        recommended_tcp_mss INTEGER,
        status TEXT NOT NULL DEFAULT 'unknown',
        summary TEXT NOT NULL DEFAULT '',
        results_json TEXT NOT NULL DEFAULT '[]',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_mtu_router_time
      ON router_mtu_history(router_id,captured_at DESC,id DESC);
    """)


def _m26(conn):
    """Add MTU diagnostic history to configurable retention."""
    if not _has_column(conn,"retention_settings","mtu_days"):
        conn.execute("ALTER TABLE retention_settings ADD COLUMN mtu_days INTEGER NOT NULL DEFAULT 365")


def _m27(conn):
    """Fleet/network intelligence: public-IP churn, identity collisions, LAN utilization, model capabilities and log patterns."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_public_ip_analysis (
        router_id INTEGER PRIMARY KEY,
        assessed_at TEXT NOT NULL,
        current_ip TEXT NOT NULL DEFAULT '',
        unique_ips_30d INTEGER NOT NULL DEFAULT 0,
        changes_7d INTEGER NOT NULL DEFAULT 0,
        changes_30d INTEGER NOT NULL DEFAULT 0,
        changes_90d INTEGER NOT NULL DEFAULT 0,
        avg_days_between_changes REAL,
        status TEXT NOT NULL DEFAULT 'stable',
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS router_identity_collisions (
        identity TEXT PRIMARY KEY,
        checked_at TEXT NOT NULL,
        router_count INTEGER NOT NULL DEFAULT 0,
        router_ids_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'collision',
        summary TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS router_local_utilization (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        confidence TEXT NOT NULL DEFAULT 'low',
        wan_interfaces TEXT NOT NULL DEFAULT '',
        lan_interfaces TEXT NOT NULL DEFAULT '',
        estimated_rx_bps REAL,
        estimated_tx_bps REAL,
        estimated_total_bps REAL,
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_local_utilization_time
      ON router_local_utilization(router_id,captured_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS router_model_capability_observations (
        router_id INTEGER PRIMARY KEY,
        observed_at TEXT NOT NULL,
        model TEXT NOT NULL DEFAULT '',
        architecture TEXT NOT NULL DEFAULT '',
        cpu TEXT NOT NULL DEFAULT '',
        cpu_count INTEGER,
        total_memory_bytes INTEGER,
        total_storage_bytes INTEGER,
        ethernet_ports INTEGER,
        sfp_ports INTEGER,
        lte_interfaces INTEGER,
        wifi_interfaces INTEGER,
        wireguard_interfaces INTEGER,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS router_model_capability_catalog (
        model TEXT PRIMARY KEY,
        updated_at TEXT NOT NULL,
        observed_routers INTEGER NOT NULL DEFAULT 0,
        architecture TEXT NOT NULL DEFAULT '',
        cpu TEXT NOT NULL DEFAULT '',
        max_cpu_count INTEGER,
        max_memory_bytes INTEGER,
        max_storage_bytes INTEGER,
        max_ethernet_ports INTEGER,
        max_sfp_ports INTEGER,
        max_lte_interfaces INTEGER,
        max_wifi_interfaces INTEGER,
        wireguard_observed INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS router_log_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        pattern_hash TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'other',
        severity TEXT NOT NULL DEFAULT 'info',
        normalized_pattern TEXT NOT NULL,
        sample TEXT NOT NULL DEFAULT '',
        occurrences INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_log_patterns_router_time
      ON router_log_patterns(router_id,captured_at DESC,id DESC);
    CREATE INDEX IF NOT EXISTS idx_router_log_patterns_hash
      ON router_log_patterns(router_id,pattern_hash,captured_at DESC);
    """)
    if not _has_column(conn,"retention_settings","local_utilization_days"):
        conn.execute("ALTER TABLE retention_settings ADD COLUMN local_utilization_days INTEGER NOT NULL DEFAULT 180")
    if not _has_column(conn,"retention_settings","log_pattern_days"):
        conn.execute("ALTER TABLE retention_settings ADD COLUMN log_pattern_days INTEGER NOT NULL DEFAULT 180")


def _m28(conn):
    """Record actual public-IP transitions for churn analysis."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_public_ip_sightings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        observed_at TEXT NOT NULL,
        public_ip TEXT NOT NULL,
        changed INTEGER NOT NULL DEFAULT 0,
        previous_ip TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_public_ip_sightings_time
      ON router_public_ip_sightings(router_id,observed_at DESC,id DESC);
    """)
    if not _has_column(conn,"retention_settings","public_ip_sighting_days"):
        conn.execute("ALTER TABLE retention_settings ADD COLUMN public_ip_sighting_days INTEGER NOT NULL DEFAULT 365")


def _m29(conn):
    """Add link-capacity context to local utilization estimates."""
    if not _has_column(conn,"router_local_utilization","estimated_capacity_bps"):
        conn.execute("ALTER TABLE router_local_utilization ADD COLUMN estimated_capacity_bps REAL")
    if not _has_column(conn,"router_local_utilization","utilization_percent"):
        conn.execute("ALTER TABLE router_local_utilization ADD COLUMN utilization_percent REAL")


def _m30(conn):
    """Hardware lifecycle intelligence and operator replacement notes."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_hardware_lifecycle (
        router_id INTEGER PRIMARY KEY,
        assessed_at TEXT NOT NULL,
        first_seen_at TEXT NOT NULL DEFAULT '',
        observed_days INTEGER NOT NULL DEFAULT 0,
        model_first_seen_at TEXT NOT NULL DEFAULT '',
        model_observed_days INTEGER NOT NULL DEFAULT 0,
        reboot_count INTEGER NOT NULL DEFAULT 0,
        total_memory_bytes INTEGER,
        total_storage_bytes INTEGER,
        installed_at TEXT NOT NULL DEFAULT '',
        warranty_until TEXT NOT NULL DEFAULT '',
        lifecycle_state TEXT NOT NULL DEFAULT '',
        replacement_notes TEXT NOT NULL DEFAULT '',
        notes_updated_by TEXT NOT NULL DEFAULT '',
        notes_updated_at TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    """)


def _m31(conn):
    """Network-quality intelligence and change-impact correlation."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS router_dns_health (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        resolver TEXT NOT NULL DEFAULT '',
        test_name TEXT NOT NULL DEFAULT 'cloudflare.com',
        ok INTEGER,
        latency_ms REAL,
        source TEXT NOT NULL DEFAULT 'configured',
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_dns_health_time
      ON router_dns_health(router_id,captured_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS router_interface_negotiation (
        router_id INTEGER NOT NULL,
        interface TEXT NOT NULL,
        checked_at TEXT NOT NULL,
        current_rate TEXT NOT NULL DEFAULT '',
        current_full_duplex INTEGER,
        current_auto_negotiation TEXT NOT NULL DEFAULT '',
        previous_rate TEXT NOT NULL DEFAULT '',
        previous_full_duplex INTEGER,
        previous_auto_negotiation TEXT NOT NULL DEFAULT '',
        changed INTEGER NOT NULL DEFAULT 0,
        downgrade INTEGER NOT NULL DEFAULT 0,
        flaps_24h INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'unknown',
        summary TEXT NOT NULL DEFAULT '',
        PRIMARY KEY(router_id,interface),
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS router_wan_quality (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        wan_interface TEXT NOT NULL DEFAULT '',
        capacity_source TEXT NOT NULL DEFAULT 'unknown',
        down_capacity_bps REAL,
        up_capacity_bps REAL,
        rx_bps REAL,
        tx_bps REAL,
        rx_utilization_percent REAL,
        tx_utilization_percent REAL,
        idle_latency_ms REAL,
        observed_latency_ms REAL,
        latency_increase_ms REAL,
        saturation INTEGER NOT NULL DEFAULT 0,
        bufferbloat_status TEXT NOT NULL DEFAULT 'unknown',
        status TEXT NOT NULL DEFAULT 'unknown',
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_wan_quality_time
      ON router_wan_quality(router_id,captured_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS router_pppoe_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        interface TEXT NOT NULL DEFAULT '',
        running INTEGER,
        disabled INTEGER,
        uptime TEXT NOT NULL DEFAULT '',
        service_name TEXT NOT NULL DEFAULT '',
        ac_name TEXT NOT NULL DEFAULT '',
        local_address TEXT NOT NULL DEFAULT '',
        remote_address TEXT NOT NULL DEFAULT '',
        mtu INTEGER,
        mru INTEGER,
        status TEXT NOT NULL DEFAULT 'unknown',
        fingerprint TEXT NOT NULL DEFAULT '',
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_pppoe_time
      ON router_pppoe_history(router_id,captured_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS router_isp_gateway_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        router_id INTEGER NOT NULL,
        captured_at TEXT NOT NULL,
        gateway TEXT NOT NULL DEFAULT '',
        interface TEXT NOT NULL DEFAULT '',
        reachable INTEGER,
        latency_ms REAL,
        mac_address TEXT NOT NULL DEFAULT '',
        changed INTEGER NOT NULL DEFAULT 0,
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_router_isp_gateway_time
      ON router_isp_gateway_history(router_id,captured_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS fleet_cross_site_anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detected_at TEXT NOT NULL,
        anomaly_key TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT 'wan',
        router_count INTEGER NOT NULL DEFAULT 0,
        router_ids_json TEXT NOT NULL DEFAULT '[]',
        status TEXT NOT NULL DEFAULT 'active',
        summary TEXT NOT NULL DEFAULT '',
        resolved_at TEXT NOT NULL DEFAULT '',
        UNIQUE(anomaly_key,status)
    );
    CREATE INDEX IF NOT EXISTS idx_cross_site_anomaly_status
      ON fleet_cross_site_anomalies(status,detected_at DESC,id DESC);

    CREATE TABLE IF NOT EXISTS change_impact_analysis (
        transaction_id INTEGER PRIMARY KEY,
        router_id INTEGER NOT NULL,
        assessed_at TEXT NOT NULL,
        window_before_minutes INTEGER NOT NULL DEFAULT 30,
        window_after_minutes INTEGER NOT NULL DEFAULT 30,
        status TEXT NOT NULL DEFAULT 'insufficient_data',
        impact_json TEXT NOT NULL DEFAULT '{}',
        summary TEXT NOT NULL DEFAULT '',
        FOREIGN KEY(transaction_id) REFERENCES change_transactions(id) ON DELETE CASCADE,
        FOREIGN KEY(router_id) REFERENCES routers(id) ON DELETE CASCADE
    );
    """)
    for name,definition in {
        "circuit_down_mbps":"REAL",
        "circuit_up_mbps":"REAL",
    }.items():
        if not _has_column(conn,"router_site_metadata",name):
            conn.execute(f"ALTER TABLE router_site_metadata ADD COLUMN {name} {definition}")
    for name,default in {
        "dns_health_days":180,
        "wan_quality_days":180,
        "pppoe_days":365,
        "isp_gateway_days":365,
    }.items():
        if not _has_column(conn,"retention_settings",name):
            conn.execute(f"ALTER TABLE retention_settings ADD COLUMN {name} INTEGER NOT NULL DEFAULT {default}")


MIGRATIONS = [_m1, _m2, _m3, _m4, _m5, _m6, _m7, _m8, _m9, _m10, _m11, _m12, _m13, _m14, _m15, _m16, _m17, _m18, _m19, _m20, _m21, _m22, _m23, _m24, _m25, _m26, _m27, _m28, _m29, _m30, _m31]


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
