"""Tikcentral operations control plane.

All automation here runs from the VPS. Nothing installs RouterOS Netwatch,
schedulers, or persistent recovery scripts on managed routers.
"""

import hashlib
import html
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events
from app import fleet
from app import guardian
from app import main as core
from app import provisioning

SCHEMA = """
CREATE TABLE IF NOT EXISTS operations_settings (
    id INTEGER PRIMARY KEY CHECK(id=1),
    telemetry_interval_seconds INTEGER NOT NULL DEFAULT 300,
    drift_interval_seconds INTEGER NOT NULL DEFAULT 1800,
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
CREATE INDEX IF NOT EXISTS idx_router_telemetry_router_time
    ON router_telemetry(router_id, captured_at DESC);

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

CREATE TABLE IF NOT EXISTS router_upgrade_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER NOT NULL,
    target_version TEXT NOT NULL DEFAULT '',
    stage TEXT NOT NULL DEFAULT 'routeros',
    status TEXT NOT NULL DEFAULT 'queued',
    canary INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_router_upgrade_jobs_status
    ON router_upgrade_jobs(status, id);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_schema():
    events.ensure_schema()
    with core.db() as conn:
        conn.executescript(SCHEMA)


def _router(router_id: int):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,model,routeros_version,routerboot_version,vpn_ip,public_key,enabled FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _seconds_since(value: str) -> float:
    if not value:
        return 10**12
    try:
        return max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(value)).total_seconds())
    except Exception:
        return 10**12


TELEMETRY_COMMAND = r'''
:put ("TC|uptime|" . [/system/resource get uptime]);
:put ("TC|version|" . [/system/resource get version]);
:put ("TC|cpu_load|" . [/system/resource get cpu-load]);
:put ("TC|free_memory|" . [/system/resource get free-memory]);
:put ("TC|total_memory|" . [/system/resource get total-memory]);
:put ("TC|routerboot_current|" . [/system/routerboard get current-firmware]);
:put ("TC|routerboot_upgrade|" . [/system/routerboard get upgrade-firmware]);
:put ("TC|fasttrack_enabled|" . [/ip/firewall/filter print count-only where comment="Opticable FastTrack" disabled=no]);
:put ("TC|qos_enabled|" . [/queue/tree print count-only where name~"^OPT-QOS-" disabled=no]);
:put ("TC|tenant_queues_enabled|" . [/queue/simple print count-only where comment~"Opticable tenant cap" disabled=no]);
:put ("TC|raw_rule_count|" . [/ip/firewall/raw print count-only where comment~"^Opticable RAW"]);
:put ("TC|mss_clamp_enabled|" . [/ip/firewall/mangle print count-only where comment="Opticable MSS clamp" disabled=no]);
'''.strip()


def _markers(output: str):
    result = {}
    for line in (output or "").splitlines():
        if line.startswith("TC|"):
            parts = line.split("|", 2)
            if len(parts) == 3:
                result[parts[1].strip()] = parts[2].strip()
    return result


def _int(value, default=0):
    try:
        return int(str(value).replace("%", "").strip())
    except Exception:
        return default


def collect_telemetry(router_id: int, record_event: bool = False):
    ensure_schema()
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    output = fleet.ssh_exec(router["vpn_ip"], TELEMETRY_COMMAND, timeout=45)
    m = _markers(output)
    if "version" not in m:
        raise RuntimeError("router telemetry response was incomplete")
    captured = now_iso()
    fasttrack = _int(m.get("fasttrack_enabled")) > 0
    qos = _int(m.get("qos_enabled")) > 0
    profile = "fairness" if qos and not fasttrack else "throughput"
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_telemetry
               (router_id,captured_at,cpu_load,free_memory,total_memory,uptime,routeros_version,
                routerboot_current,routerboot_upgrade,fasttrack_enabled,qos_enabled,
                tenant_queues_enabled,raw_rule_count,mss_clamp_enabled)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (router_id, captured, _int(m.get("cpu_load")), m.get("free_memory", ""),
             m.get("total_memory", ""), m.get("uptime", ""), m.get("version", ""),
             m.get("routerboot_current", ""), m.get("routerboot_upgrade", ""), int(fasttrack),
             int(qos), int(_int(m.get("tenant_queues_enabled")) > 0),
             _int(m.get("raw_rule_count")), int(_int(m.get("mss_clamp_enabled")) > 0)),
        )
        conn.execute(
            "UPDATE routers SET routeros_version=?,routerboot_version=? WHERE id=?",
            (m.get("version", ""), m.get("routerboot_current", ""), router_id),
        )
        expected = conn.execute(
            "SELECT expected_profile FROM router_expected_state WHERE router_id=?", (router_id,)
        ).fetchone()
    if expected and expected["expected_profile"] and expected["expected_profile"] != profile:
        events.record(router_id, "drift", f"Performance profile drift: expected {expected['expected_profile']}, found {profile}", severity="warning")
    if record_event:
        events.record(router_id, "telemetry", f"Telemetry collected: CPU {_int(m.get('cpu_load'))}% · RouterOS {m.get('version','')}")
    return {**m, "profile": profile, "captured_at": captured}


def latest_telemetry(router_id: int):
    ensure_schema()
    with core.db() as conn:
        return conn.execute(
            "SELECT * FROM router_telemetry WHERE router_id=? ORDER BY id DESC LIMIT 1", (router_id,)
        ).fetchone()


def _access_ok(router) -> bool:
    result = guardian.probe_router(router)
    return bool(result["management_ok"])


def backup_router(router_id: int, tier: str, created_by: str):
    if tier not in {"daily", "pre-change", "commissioning"}:
        raise ValueError("invalid backup tier")
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    result = fleet._backup_one(router, stamp, tier=tier)
    with core.db() as conn:
        conn.execute(
            "INSERT INTO router_backup_records(router_id,created_at,tier,created_by,result) VALUES(?,?,?,?,?)",
            (router_id, now_iso(), tier, created_by, result),
        )
    events.record(router_id, "backup", f"{tier} backup completed", result)
    return result


def _export_hash(router):
    content = fleet.ssh_exec(router["vpn_ip"], "/export show-sensitive=no terse", timeout=90)
    return hashlib.sha256(content.encode()).hexdigest(), content


def accept_baseline(router_id: int, created_by: str):
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    digest, _ = _export_hash(router)
    telem = collect_telemetry(router_id)
    profile = telem["profile"]
    now = now_iso()
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_expected_state(router_id,expected_profile,baseline_sha256,baseline_at,last_drift_check_at,drifted)
               VALUES(?,?,?,?,?,0)
               ON CONFLICT(router_id) DO UPDATE SET expected_profile=excluded.expected_profile,
                 baseline_sha256=excluded.baseline_sha256,baseline_at=excluded.baseline_at,
                 last_drift_check_at=excluded.last_drift_check_at,drifted=0""",
            (router_id, profile, digest, now, now),
        )
    events.record(router_id, "baseline", f"Configuration accepted as baseline by {created_by}", digest)
    return digest


def check_drift(router_id: int):
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    with core.db() as conn:
        expected = conn.execute(
            "SELECT baseline_sha256,drifted FROM router_expected_state WHERE router_id=?", (router_id,)
        ).fetchone()
    if not expected or not expected["baseline_sha256"]:
        return None
    digest, _ = _export_hash(router)
    drifted = digest != expected["baseline_sha256"]
    changed = bool(drifted) != bool(expected["drifted"])
    with core.db() as conn:
        conn.execute(
            "UPDATE router_expected_state SET last_drift_check_at=?,drifted=? WHERE router_id=?",
            (now_iso(), int(drifted), router_id),
        )
    if changed:
        events.record(router_id, "drift", "Configuration drift detected" if drifted else "Configuration returned to baseline", digest, "warning" if drifted else "info")
    return drifted


def switch_profile(router_id: int, profile: str, created_by: str):
    if profile not in {"throughput", "fairness"}:
        raise ValueError("invalid profile")
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    if not _access_ok(router):
        raise RuntimeError("Guardian access preflight failed; profile change blocked")
    backup_router(router_id, "pre-change", created_by)
    if profile == "fairness":
        command = r'''
/ip/firewall/filter set [find where comment="Opticable FastTrack"] disabled=yes;
/ip/firewall/mangle set [find where comment="Opticable QoS mark upload"] disabled=no;
/ip/firewall/mangle set [find where comment="Opticable QoS mark download"] disabled=no;
/ip/firewall/mangle set [find where comment~"^Opticable QoS " and comment!="Opticable QoS mark upload" and comment!="Opticable QoS mark download"] disabled=no;
/queue/tree set [find where name~"^OPT-QOS-"] disabled=no;
/queue/simple set [find where comment~"Opticable tenant cap"] disabled=no;
:put "Tikcentral profile=fairness"
'''.strip()
    else:
        command = r'''
/ip/firewall/filter set [find where comment="Opticable FastTrack"] disabled=no;
/ip/firewall/mangle set [find where comment~"^Opticable QoS "] disabled=yes;
/queue/tree set [find where name~"^OPT-QOS-"] disabled=yes;
/queue/simple set [find where comment~"Opticable tenant cap"] disabled=yes;
:put "Tikcentral profile=throughput"
'''.strip()
    output = fleet.ssh_exec(router["vpn_ip"], command, timeout=60)
    if not _access_ok(router):
        events.record(router_id, "profile", f"Profile change to {profile} completed but management verification failed", output, "critical")
        raise RuntimeError("profile changed, but Guardian verification failed; inspect router immediately")
    telem = collect_telemetry(router_id)
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_expected_state(router_id,expected_profile)
               VALUES(?,?) ON CONFLICT(router_id) DO UPDATE SET expected_profile=excluded.expected_profile""",
            (router_id, profile),
        )
    events.record(router_id, "profile", f"Performance profile changed to {profile}", json.dumps(telem))
    return output


UPDATE_CHECK_COMMAND = '/system/package/update check-for-updates once; :delay 5s; /system/package/update print'


def _field(output: str, name: str):
    m = re.search(rf"(?mi)^\s*{re.escape(name)}:\s*(.+?)\s*$", output or "")
    return m.group(1).strip() if m else ""


def check_update(router_id: int):
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    if not _access_ok(router):
        raise RuntimeError("Guardian access preflight failed")
    output = fleet.ssh_exec(router["vpn_ip"], UPDATE_CHECK_COMMAND, timeout=90)
    current = _field(output, "installed-version") or router["routeros_version"]
    latest = _field(output, "latest-version")
    status = _field(output, "status")
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_update_status(router_id,checked_at,current_version,latest_version,update_status,last_error)
               VALUES(?,?,?,?,?,'') ON CONFLICT(router_id) DO UPDATE SET checked_at=excluded.checked_at,
                 current_version=excluded.current_version,latest_version=excluded.latest_version,
                 update_status=excluded.update_status,last_error=''""",
            (router_id, now_iso(), current, latest, status),
        )
    events.record(router_id, "upgrade", f"Update check: {status or 'completed'}", output)
    return current, latest, status


def approve_current_version(router_id: int, created_by: str):
    router = _router(router_id)
    if not router or not router["model"]:
        raise RuntimeError("router model is unknown")
    telem = collect_telemetry(router_id)
    version = telem.get("version", "")
    if not version:
        raise RuntimeError("RouterOS version unavailable")
    with core.db() as conn:
        conn.execute(
            """INSERT INTO approved_versions(model,version,approved_at,approved_by) VALUES(?,?,?,?)
               ON CONFLICT(model) DO UPDATE SET version=excluded.version,approved_at=excluded.approved_at,approved_by=excluded.approved_by""",
            (router["model"], version, now_iso(), created_by),
        )
    events.record(router_id, "upgrade", f"RouterOS {version} approved for model {router['model']} by {created_by}")
    return version


def queue_upgrade(router_id: int, canary: bool, created_by: str):
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    with core.db() as conn:
        status = conn.execute("SELECT * FROM router_update_status WHERE router_id=?", (router_id,)).fetchone()
        active = conn.execute(
            "SELECT id FROM router_upgrade_jobs WHERE status IN ('queued','running','rebooting','routerboot_queued','routerboot_rebooting') LIMIT 1"
        ).fetchone()
        approved = conn.execute("SELECT version FROM approved_versions WHERE model=?", (router["model"],)).fetchone()
    if active:
        raise RuntimeError("another router upgrade is already active; Tikcentral serializes upgrades")
    if not status or not status["latest_version"]:
        raise RuntimeError("check for updates first")
    target = status["latest_version"]
    if not canary and (not approved or approved["version"] != target):
        raise RuntimeError(f"{target} is not approved for model {router['model']}; run it as a canary first")
    if not _access_ok(router):
        raise RuntimeError("Guardian access preflight failed; upgrade blocked")
    with core.db() as conn:
        cur = conn.execute(
            "INSERT INTO router_upgrade_jobs(router_id,target_version,stage,status,canary,created_by,created_at) VALUES(?,?,'routeros','queued',?,?,?)",
            (router_id, target, int(canary), created_by, now_iso()),
        )
    events.record(router_id, "upgrade", f"{'Canary' if canary else 'Approved'} RouterOS upgrade queued to {target}")
    return cur.lastrowid


def queue_routerboot(router_id: int, created_by: str):
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    telem = collect_telemetry(router_id)
    if not telem.get("routerboot_upgrade") or telem.get("routerboot_upgrade") == telem.get("routerboot_current"):
        raise RuntimeError("RouterBOOT is already current")
    with core.db() as conn:
        active = conn.execute(
            "SELECT id FROM router_upgrade_jobs WHERE status IN ('queued','running','rebooting','routerboot_queued','routerboot_rebooting') LIMIT 1"
        ).fetchone()
        if active:
            raise RuntimeError("another router upgrade is already active")
        cur = conn.execute(
            "INSERT INTO router_upgrade_jobs(router_id,target_version,stage,status,canary,created_by,created_at) VALUES(?,?,'routerboot','routerboot_queued',0,?,?)",
            (router_id, telem.get("routerboot_upgrade", ""), created_by, now_iso()),
        )
    events.record(router_id, "upgrade", f"RouterBOOT upgrade queued to {telem.get('routerboot_upgrade','')}")
    return cur.lastrowid


def _process_upgrade_job():
    ensure_schema()
    with core.db() as conn:
        job = conn.execute(
            """SELECT * FROM router_upgrade_jobs
               WHERE status IN ('queued','rebooting','routerboot_queued','routerboot_rebooting')
               ORDER BY id LIMIT 1"""
        ).fetchone()
    if not job:
        return None
    router = _router(job["router_id"])
    if not router:
        with core.db() as conn:
            conn.execute("UPDATE router_upgrade_jobs SET status='failed',finished_at=?,last_error='router missing' WHERE id=?", (now_iso(), job["id"]))
        return job["id"]

    if job["status"] == "queued":
        if not _access_ok(router):
            return job["id"]
        try:
            backup_router(router["id"], "pre-change", "upgrade")
            with core.db() as conn:
                conn.execute("UPDATE router_upgrade_jobs SET status='running',started_at=? WHERE id=?", (now_iso(), job["id"]))
            p = subprocess.run(
                fleet.ssh_base(router["vpn_ip"]) + ["/system/package/update install"],
                capture_output=True, text=True, timeout=900,
            )
            details = (p.stdout or "") + "\n" + (p.stderr or "")
            with core.db() as conn:
                conn.execute("UPDATE router_upgrade_jobs SET status='rebooting',last_error=? WHERE id=?", (details[-4000:], job["id"]))
            events.record(router["id"], "upgrade", f"RouterOS upgrade dispatched to {job['target_version']}", details)
        except subprocess.TimeoutExpired:
            with core.db() as conn:
                conn.execute("UPDATE router_upgrade_jobs SET status='rebooting',last_error='SSH command timed out during expected upgrade/reboot' WHERE id=?", (job["id"],))
        except Exception as exc:
            with core.db() as conn:
                conn.execute("UPDATE router_upgrade_jobs SET status='failed',finished_at=?,last_error=? WHERE id=?", (now_iso(), str(exc), job["id"]))
            events.record(router["id"], "upgrade", "RouterOS upgrade dispatch failed", str(exc), "critical")
        return job["id"]

    if job["status"] == "rebooting":
        if not _access_ok(router):
            if _seconds_since(job["started_at"]) > 1200:
                with core.db() as conn:
                    conn.execute("UPDATE router_upgrade_jobs SET status='failed',finished_at=?,last_error='router did not return healthy within 20 minutes' WHERE id=?", (now_iso(), job["id"]))
                events.record(router["id"], "upgrade", "Router did not return healthy after RouterOS upgrade", severity="critical")
            return job["id"]
        try:
            telem = collect_telemetry(router["id"])
            current = telem.get("version", "")
            ok = bool(job["target_version"] and job["target_version"] in current)
            final_status = "routerboot_required" if ok and telem.get("routerboot_upgrade") != telem.get("routerboot_current") else ("success" if ok else "failed")
            err = "" if ok else f"expected {job['target_version']}, found {current}"
            with core.db() as conn:
                conn.execute("UPDATE router_upgrade_jobs SET status=?,finished_at=?,last_error=? WHERE id=?", (final_status, now_iso(), err, job["id"]))
            events.record(router["id"], "upgrade", f"RouterOS upgrade {'verified' if ok else 'verification failed'}: {current}", json.dumps(telem), "info" if ok else "critical")
        except Exception as exc:
            events.record(router["id"], "upgrade", "Post-upgrade verification failed", str(exc), "warning")
        return job["id"]

    if job["status"] == "routerboot_queued":
        if not _access_ok(router):
            return job["id"]
        try:
            backup_router(router["id"], "pre-change", "routerboot-upgrade")
            with core.db() as conn:
                conn.execute("UPDATE router_upgrade_jobs SET started_at=? WHERE id=?", (now_iso(), job["id"]))
            p = subprocess.run(
                fleet.ssh_base(router["vpn_ip"]) + ['/system/routerboard upgrade; :delay 3s; /system/reboot'],
                capture_output=True, text=True, timeout=90,
            )
            details = (p.stdout or "") + "\n" + (p.stderr or "")
            with core.db() as conn:
                conn.execute("UPDATE router_upgrade_jobs SET status='routerboot_rebooting',last_error=? WHERE id=?", (details[-4000:], job["id"]))
            events.record(router["id"], "upgrade", f"RouterBOOT upgrade dispatched to {job['target_version']}", details)
        except subprocess.TimeoutExpired:
            with core.db() as conn:
                conn.execute("UPDATE router_upgrade_jobs SET status='routerboot_rebooting',last_error='SSH command timed out during expected reboot' WHERE id=?", (job["id"],))
        except Exception as exc:
            with core.db() as conn:
                conn.execute("UPDATE router_upgrade_jobs SET status='failed',finished_at=?,last_error=? WHERE id=?", (now_iso(), str(exc), job["id"]))
            events.record(router["id"], "upgrade", "RouterBOOT upgrade dispatch failed", str(exc), "critical")
        return job["id"]

    if job["status"] == "routerboot_rebooting":
        if not _access_ok(router):
            if _seconds_since(job["started_at"]) > 900:
                with core.db() as conn:
                    conn.execute("UPDATE router_upgrade_jobs SET status='failed',finished_at=?,last_error='router did not return after RouterBOOT reboot' WHERE id=?", (now_iso(), job["id"]))
            return job["id"]
        telem = collect_telemetry(router["id"])
        ok = telem.get("routerboot_current") == telem.get("routerboot_upgrade")
        with core.db() as conn:
            conn.execute("UPDATE router_upgrade_jobs SET status=?,finished_at=?,last_error=? WHERE id=?", ("success" if ok else "failed", now_iso(), "" if ok else "RouterBOOT versions still differ", job["id"]))
        events.record(router["id"], "upgrade", "RouterBOOT upgrade verified" if ok else "RouterBOOT verification failed", json.dumps(telem), "info" if ok else "critical")
        return job["id"]
    return job["id"]


VALIDATE_BASE = r'''
:put ("TC|wg|" . [/interface/wireguard print count-only where name="opticable-wg"]);
:put ("TC|tikcentral_user|" . [/user print count-only where name="tikcentral" disabled=no]);
:put ("TC|winbox|" . [/ip/service print count-only where name="winbox" disabled=no]);
:put ("TC|ssh|" . [/ip/service print count-only where name="ssh" disabled=no]);
:put ("TC|api|" . [/ip/service print count-only where name="api" disabled=no]);
:put ("TC|wan_dhcp|" . [/ip/dhcp-client print count-only where interface=ether1 disabled=no]);
:put ("TC|pppoe|" . [/interface/pppoe-client print count-only where name="PPPOE-OUT-01"]);
:put ("TC|vlans|" . [/interface/vlan print count-only where name~"^VLAN"]);
:put ("TC|dhcp_servers|" . [/ip/dhcp-server print count-only where disabled=no]);
:put ("TC|raw|" . [/ip/firewall/raw print count-only where comment~"^Opticable RAW"]);
:put ("TC|mss|" . [/ip/firewall/mangle print count-only where comment="Opticable MSS clamp" disabled=no]);
:put ("TC|qos_staged|" . [/queue/tree print count-only where name~"^OPT-QOS-"]);
'''.strip()


def validate_commissioning(router_id: int, created_by: str):
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    access = guardian.probe_router(router)
    admin_user, admin_password = provisioning.get_admin_credentials()
    extra = ""
    if admin_user and admin_password:
        safe = admin_user.replace('"', '')
        extra = f'; :put ("TC|personal_admin|" . [/user print count-only where name="{safe}" disabled=no])'
    output = fleet.ssh_exec(router["vpn_ip"], VALIDATE_BASE + extra, timeout=60)
    m = _markers(output)
    checks = {
        "guardian_access": bool(access["management_ok"]),
        "wireguard": _int(m.get("wg")) > 0,
        "tikcentral_user": _int(m.get("tikcentral_user")) > 0,
        "winbox": _int(m.get("winbox")) > 0,
        "ssh": _int(m.get("ssh")) > 0,
        "api": _int(m.get("api")) > 0,
        "wan_dhcp": _int(m.get("wan_dhcp")) > 0,
        "pppoe_prepared": _int(m.get("pppoe")) > 0,
        "raw_baseline": _int(m.get("raw")) >= 4,
        "mss_clamp": _int(m.get("mss")) > 0,
        "qos_staged": _int(m.get("qos_staged")) >= 2,
        "personal_admin": True if not admin_user else _int(m.get("personal_admin")) > 0,
    }
    passed = all(checks.values())
    telem = collect_telemetry(router_id)
    report = {"passed": passed, "checks": checks, "observed": m, "telemetry": telem}
    status = "passed" if passed else "failed"
    now = now_iso()
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_expected_state(router_id,expected_profile,commissioning_status,commissioning_at,commissioning_report)
               VALUES(?,?,?,?,?) ON CONFLICT(router_id) DO UPDATE SET commissioning_status=excluded.commissioning_status,
                 commissioning_at=excluded.commissioning_at,commissioning_report=excluded.commissioning_report""",
            (router_id, telem["profile"], status, now, json.dumps(report)),
        )
    if passed:
        backup_router(router_id, "commissioning", created_by)
        accept_baseline(router_id, created_by)
    events.record(router_id, "commissioning", f"Commissioning validation {status}", json.dumps(report), "info" if passed else "warning")
    return report


def scheduled_tick():
    ensure_schema()
    _process_upgrade_job()
    with core.db() as conn:
        s = conn.execute("SELECT * FROM operations_settings WHERE id=1").fetchone()
        routers = conn.execute(
            """SELECT r.id FROM routers r
               JOIN router_access_state a ON a.router_id=r.id
               WHERE r.enabled=1 AND a.management_ok=1 ORDER BY r.id"""
        ).fetchall()
    now = now_iso()
    if _seconds_since(s["last_telemetry_at"]) >= int(s["telemetry_interval_seconds"]):
        ids = [r["id"] for r in routers]
        with ThreadPoolExecutor(max_workers=max(1, min(fleet.MAX_WORKERS, len(ids) or 1))) as pool:
            futures = {pool.submit(collect_telemetry, rid): rid for rid in ids}
            for fut in as_completed(futures):
                rid = futures[fut]
                try:
                    fut.result()
                except Exception as exc:
                    events.record(rid, "telemetry", "Telemetry collection failed", str(exc), "warning")
        with core.db() as conn:
            conn.execute("UPDATE operations_settings SET last_telemetry_at=? WHERE id=1", (now,))
    if _seconds_since(s["last_drift_at"]) >= int(s["drift_interval_seconds"]):
        with core.db() as conn:
            due = conn.execute(
                """SELECT e.router_id FROM router_expected_state e
                   JOIN router_access_state a ON a.router_id=e.router_id
                   WHERE e.baseline_sha256<>'' AND a.management_ok=1 ORDER BY e.router_id"""
            ).fetchall()
        ids = [r["router_id"] for r in due]
        with ThreadPoolExecutor(max_workers=max(1, min(4, len(ids) or 1))) as pool:
            futures = {pool.submit(check_drift, rid): rid for rid in ids}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as exc:
                    events.record(futures[fut], "drift", "Drift check failed", str(exc), "warning")
        with core.db() as conn:
            conn.execute("UPDATE operations_settings SET last_drift_at=? WHERE id=1", (now,))


def _csrf(request):
    return core.csrf_token(request)


def _admin(request):
    return core.require_web_admin(request)


def _post_button(action, csrf, label, danger=False, confirm=""):
    cls = ' class="danger"' if danger else ''
    oc = f' onclick="return confirm(\'{html.escape(confirm)}\')"' if confirm else ''
    return f'<form method="post" action="{action}" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><button{cls}{oc}>{html.escape(label)}</button></form>'


def register(app, page_func):
    ensure_schema()

    @app.get("/operations", response_class=HTMLResponse)
    def operations_index(request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        with core.db() as conn:
            rows = conn.execute(
                """SELECT r.id,r.site_name,r.model,r.routeros_version,r.vpn_ip,
                          a.management_ok,a.last_good_at,
                          t.cpu_load,t.free_memory,t.uptime,t.fasttrack_enabled,t.qos_enabled,t.captured_at,
                          e.expected_profile,e.drifted,e.commissioning_status,
                          v.version approved_version
                   FROM routers r
                   LEFT JOIN router_access_state a ON a.router_id=r.id
                   LEFT JOIN router_telemetry t ON t.id=(SELECT id FROM router_telemetry WHERE router_id=r.id ORDER BY id DESC LIMIT 1)
                   LEFT JOIN router_expected_state e ON e.router_id=r.id
                   LEFT JOIN approved_versions v ON v.model=r.model
                   ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()
        body_rows = []
        for r in rows:
            profile = "Fairness/QoS" if r["qos_enabled"] and not r["fasttrack_enabled"] else "Throughput"
            drift = "DRIFT" if r["drifted"] else "OK"
            body_rows.append(f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')} · <code>{html.escape(r['vpn_ip'])}</code></div></td><td>{'Healthy' if r['management_ok'] else 'Degraded'}</td><td>{html.escape(r['routeros_version'] or '-')}<div class="muted">Approved: {html.escape(r['approved_version'] or '-')}</div></td><td>{html.escape(profile)}</td><td>{str(r['cpu_load'])+'%' if r['cpu_load'] is not None else '-'}<div class="muted">{html.escape(r['free_memory'] or '')}</div></td><td>{html.escape(r['commissioning_status'] or 'not_checked')}</td><td>{drift}</td><td><a href="/operations/{r['id']}"><button>Open</button></a></td></tr>''')
        body = f'''<div class="panel pad"><h2>Operations</h2><div class="muted">VPS-side control plane for commissioning, telemetry, drift, performance profiles, backups and serialized upgrades. No RouterOS Netwatch or persistent router-side automation is installed.</div></div><div class="panel"><table><thead><tr><th>Router</th><th>Access</th><th>RouterOS</th><th>Profile</th><th>CPU / RAM</th><th>Commissioning</th><th>Config</th><th></th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="8">No routers.</td></tr>'}</tbody></table></div>'''
        return page_func("Operations", body, user, "operations")

    @app.get("/operations/{router_id}", response_class=HTMLResponse)
    def operations_router(router_id: int, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        router = _router(router_id)
        if not router:
            raise HTTPException(status_code=404, detail="router not found")
        csrf = _csrf(request)
        telem = latest_telemetry(router_id)
        with core.db() as conn:
            access = conn.execute("SELECT * FROM router_access_state WHERE router_id=?", (router_id,)).fetchone()
            expected = conn.execute("SELECT * FROM router_expected_state WHERE router_id=?", (router_id,)).fetchone()
            update = conn.execute("SELECT * FROM router_update_status WHERE router_id=?", (router_id,)).fetchone()
            approved = conn.execute("SELECT * FROM approved_versions WHERE model=?", (router["model"],)).fetchone()
            upgrade = conn.execute("SELECT * FROM router_upgrade_jobs WHERE router_id=? ORDER BY id DESC LIMIT 1", (router_id,)).fetchone()
            backups = conn.execute("SELECT * FROM router_backup_records WHERE router_id=? ORDER BY id DESC LIMIT 8", (router_id,)).fetchall()
        evs = events.recent(router_id, 80)
        profile = "fairness" if telem and telem["qos_enabled"] and not telem["fasttrack_enabled"] else "throughput"
        telemetry_text = "No telemetry yet" if not telem else f"CPU {telem['cpu_load']}% · RAM {html.escape(telem['free_memory'])}/{html.escape(telem['total_memory'])} · uptime {html.escape(telem['uptime'])} · RouterOS {html.escape(telem['routeros_version'])} · RouterBOOT {html.escape(telem['routerboot_current'])}/{html.escape(telem['routerboot_upgrade'])}"
        profile_buttons = _post_button(f"/operations/{router_id}/profile/throughput", csrf, "Use maximum throughput") + " " + _post_button(f"/operations/{router_id}/profile/fairness", csrf, "Use Fairness/QoS")
        upgrade_buttons = _post_button(f"/operations/{router_id}/update/check", csrf, "Check for RouterOS update")
        if update and update["latest_version"]:
            upgrade_buttons += " " + _post_button(f"/operations/{router_id}/upgrade/canary", csrf, f"Canary upgrade to {update['latest_version']}", True, "Start a one-router canary upgrade? A pre-change backup will be taken first.")
            if approved and approved["version"] == update["latest_version"]:
                upgrade_buttons += " " + _post_button(f"/operations/{router_id}/upgrade/approved", csrf, f"Upgrade approved {approved['version']}", True, "Upgrade this router to the approved version?")
        if telem and telem["routerboot_upgrade"] and telem["routerboot_upgrade"] != telem["routerboot_current"]:
            upgrade_buttons += " " + _post_button(f"/operations/{router_id}/routerboot", csrf, "Upgrade RouterBOOT", True, "Upgrade RouterBOOT and reboot this router?")
        approve = _post_button(f"/operations/{router_id}/approve-version", csrf, "Approve current version for this model")
        drift_status = "No baseline" if not expected or not expected["baseline_sha256"] else ("DRIFT DETECTED" if expected["drifted"] else "Matches baseline")
        commissioning = expected["commissioning_status"] if expected else "not_checked"
        backup_rows = ''.join(f"<tr><td>{html.escape(b['tier'])}</td><td>{html.escape(b['created_at'])}</td><td>{html.escape(b['created_by'])}</td></tr>" for b in backups) or '<tr><td colspan="3">No tracked backups.</td></tr>'
        event_rows = ''.join(f"<tr><td>{html.escape(e['event_at'])}</td><td>{html.escape(e['severity'])}</td><td>{html.escape(e['category'])}</td><td>{html.escape(e['summary'])}<div class=\"muted\">{html.escape((e['details'] or '')[-600:])}</div></td></tr>" for e in evs) or '<tr><td colspan="4">No events.</td></tr>'
        body = f'''<div class="panel pad"><h2>{html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['model'] or '')} · <code>{html.escape(router['vpn_ip'])}</code> · Access {'Healthy' if access and access['management_ok'] else 'Degraded'}</div></div>
<div class="panel pad"><h3>Commissioning</h3><div>Status: <strong>{html.escape(commissioning)}</strong></div><div class="inline" style="margin-top:10px">{_post_button(f'/operations/{router_id}/commission', csrf, 'Run commissioning validation')} {_post_button(f'/operations/{router_id}/backup/commissioning', csrf, 'Create commissioning backup')}</div></div>
<div class="panel pad"><h3>Performance</h3><div>Current profile: <strong>{html.escape(profile)}</strong></div><div class="muted">{telemetry_text}</div><div class="inline" style="margin-top:10px">{profile_buttons} {_post_button(f'/operations/{router_id}/telemetry', csrf, 'Refresh telemetry')}</div></div>
<div class="panel pad"><h3>Configuration drift</h3><div>{html.escape(drift_status)}</div><div class="inline" style="margin-top:10px">{_post_button(f'/operations/{router_id}/drift/check', csrf, 'Check drift now')} {_post_button(f'/operations/{router_id}/baseline', csrf, 'Accept current config as baseline', True, 'Replace the expected configuration baseline with the router current configuration?')}</div></div>
<div class="panel pad"><h3>RouterOS / RouterBOOT</h3><div class="muted">Current {html.escape(router['routeros_version'] or '-')} · approved for {html.escape(router['model'] or 'model')}: {html.escape(approved['version'] if approved else '-')} · update check: {html.escape(update['update_status'] if update else 'not checked')} {html.escape(update['latest_version'] if update else '')}</div><div class="inline" style="margin-top:10px">{upgrade_buttons} {approve}</div><div class="muted" style="margin-top:8px">Latest upgrade job: {html.escape(upgrade['status'] if upgrade else 'none')} {html.escape(upgrade['last_error'] if upgrade else '')}</div></div>
<div class="panel pad"><h3>Backups</h3><div class="inline">{_post_button(f'/operations/{router_id}/backup/pre-change', csrf, 'Create pre-change backup')}</div><table><thead><tr><th>Tier</th><th>Time</th><th>By</th></tr></thead><tbody>{backup_rows}</tbody></table></div>
<div class="panel pad"><h3>Event timeline</h3><table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Event</th></tr></thead><tbody>{event_rows}</tbody></table></div>'''
        return page_func("Router Operations", body, user, "operations")

    @app.post("/operations/{router_id}/telemetry")
    async def route_telemetry(router_id: int, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        collect_telemetry(router_id, True)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/profile/{profile}")
    async def route_profile(router_id: int, profile: str, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        switch_profile(router_id, profile, user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/commission")
    async def route_commission(router_id: int, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        validate_commissioning(router_id, user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/backup/{tier}")
    async def route_backup(router_id: int, tier: str, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        backup_router(router_id, tier, user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/baseline")
    async def route_baseline(router_id: int, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        accept_baseline(router_id, user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/drift/check")
    async def route_drift(router_id: int, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        check_drift(router_id)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/update/check")
    async def route_update_check(router_id: int, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        check_update(router_id)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/upgrade/{mode}")
    async def route_upgrade(router_id: int, mode: str, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        if mode not in {"canary", "approved"}:
            raise HTTPException(status_code=400, detail="invalid upgrade mode")
        queue_upgrade(router_id, mode == "canary", user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/routerboot")
    async def route_routerboot(router_id: int, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        queue_routerboot(router_id, user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/approve-version")
    async def route_approve(router_id: int, request: Request):
        user = _admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        data = await core.form_data(request); core.require_csrf(request, data.get("csrf", ""))
        approve_current_version(router_id, user["email"] if "email" in user.keys() else "admin")
        return RedirectResponse(f"/operations/{router_id}", status_code=303)
