"""Tikcentral Operations control plane.

One implementation owns telemetry, commissioning, drift, backups, performance
profiles and upgrade jobs. Router-side Netwatch/schedulers are intentionally not
installed; the VPS remains the control plane.
"""

import hashlib
import html
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from app import capabilities
from app import change_control
from app import errors
from app import events
from app import fleet
from app import guardian
from app import jobs
from app import main as core
from app import migrations
from app import provisioning
from app import resource_monitor
from app import router_exec
from app import settings
from app import state_capture


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_schema():
    migrations.migrate()
    fleet.ensure_schema()
    events.ensure_schema()


def _router(router_id: int):
    with core.db() as conn:
        return conn.execute(
            "SELECT id,site_name,identity,model,routeros_version,routerboot_version,vpn_ip,public_key,enabled,lifecycle_state,lifecycle_updated_at,lifecycle_updated_by FROM routers WHERE id=?",
            (router_id,),
        ).fetchone()


def _seconds_since(value: str) -> float:
    if not value:
        return 10**12
    try:
        return max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(value)).total_seconds())
    except Exception:
        return 10**12


def _field(output: str, name: str) -> str:
    match = re.search(rf"(?mi)^\s*{re.escape(name)}:\s*(.+?)\s*$", output or "")
    return match.group(1).strip() if match else ""


def _int(value, default=0):
    try:
        return int(str(value).replace("%", "").strip())
    except Exception:
        return default


def _count_value(output: str):
    for line in reversed((output or "").splitlines()):
        line = line.strip()
        if re.fullmatch(r"\d+", line):
            return int(line)
    return None


def _probe_count(ip: str, command: str, label: str, timeout: int = 8):
    try:
        out = router_exec.read(ip, command, timeout=timeout, label=label)
        value = _count_value(out)
        if value is None:
            return None, f"{label}: unexpected response"
        return value, ""
    except Exception as exc:
        return None, errors.short(exc)


def _access_ok(router) -> bool:
    try:
        return bool(guardian.probe_router(router)["management_ok"])
    except Exception:
        return False


def _require_router(router_id: int):
    router = _router(router_id)
    if not router or not router["enabled"]:
        raise errors.OperationError("ROUTER_NOT_FOUND", "Enabled router not found")
    if (router["lifecycle_state"] or "production") == "retired":
        raise errors.OperationError("ROUTER_RETIRED", "Retired routers cannot receive operational mutations")
    return router


def _version_number(value: str) -> str:
    return (value or "").strip().split()[0] if (value or "").strip() else ""


# ---- Telemetry -----------------------------------------------------------------

def collect_telemetry(router_id: int, record_event: bool = False):
    ensure_schema()
    router = _require_router(router_id)
    previous = latest_telemetry(router_id)
    probe_errors = []

    try:
        resource = router_exec.read(router["vpn_ip"], "/system resource print without-paging", timeout=12, label="Core telemetry")
    except Exception as exc:
        if previous is None:
            raise errors.from_exception(exc, "TELEMETRY_UNAVAILABLE", "Core telemetry is unavailable")
        resource = ""
        probe_errors.append(errors.short(exc))

    version = _field(resource, "version") or (previous["routeros_version"] if previous else router["routeros_version"] or "")
    uptime = _field(resource, "uptime") or (previous["uptime"] if previous else "")
    free_memory = _field(resource, "free-memory") or (previous["free_memory"] if previous else "")
    total_memory = _field(resource, "total-memory") or (previous["total_memory"] if previous else "")
    cpu = _int(_field(resource, "cpu-load"), previous["cpu_load"] if previous and previous["cpu_load"] is not None else 0)

    try:
        rb = router_exec.read(router["vpn_ip"], "/system routerboard print without-paging", timeout=8, label="RouterBOOT telemetry")
    except Exception as exc:
        rb = ""
        probe_errors.append(errors.short(exc))
    rb_current = _field(rb, "current-firmware") or (previous["routerboot_current"] if previous else "")
    rb_upgrade = _field(rb, "upgrade-firmware") or (previous["routerboot_upgrade"] if previous else "")

    fasttrack_count, err = _probe_count(router["vpn_ip"], ':put [/ip firewall filter print count-only where comment="Opticable FastTrack" disabled=no]', "FastTrack probe")
    if err: probe_errors.append(err)
    raw_count, err = _probe_count(router["vpn_ip"], ':put [/ip firewall raw print count-only where comment~"^Opticable RAW"]', "RAW probe")
    if err: probe_errors.append(err)
    mss_count, err = _probe_count(router["vpn_ip"], ':put [/ip firewall mangle print count-only where comment="Opticable MSS clamp" disabled=no]', "MSS probe")
    if err: probe_errors.append(err)
    qos_count, err = _probe_count(router["vpn_ip"], ':put [/queue tree print count-only where name~"^OPT-QOS-" disabled=no]', "QoS probe")
    if err: probe_errors.append(err)
    tenant_count, err = _probe_count(router["vpn_ip"], ':put [/queue simple print count-only where comment~"Opticable tenant cap" disabled=no]', "Tenant queue probe")
    if err: probe_errors.append(err)

    def prior(name, default=0):
        return previous[name] if previous is not None else default

    fasttrack = bool(fasttrack_count) if fasttrack_count is not None else bool(prior("fasttrack_enabled", 0))
    qos = bool(qos_count) if qos_count is not None else bool(prior("qos_enabled", 0))
    tenant = bool(tenant_count) if tenant_count is not None else bool(prior("tenant_queues_enabled", 0))
    raw_rules = raw_count if raw_count is not None else int(prior("raw_rule_count", 0) or 0)
    mss = bool(mss_count) if mss_count is not None else bool(prior("mss_clamp_enabled", 0))
    profile = "fairness" if qos and not fasttrack else "throughput"
    captured = now_iso()

    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_telemetry
               (router_id,captured_at,cpu_load,free_memory,total_memory,uptime,routeros_version,
                routerboot_current,routerboot_upgrade,fasttrack_enabled,qos_enabled,
                tenant_queues_enabled,raw_rule_count,mss_clamp_enabled)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (router_id, captured, cpu, free_memory, total_memory, uptime, version,
             rb_current, rb_upgrade, int(fasttrack), int(qos), int(tenant), raw_rules, int(mss)),
        )
        conn.execute(
            "UPDATE routers SET routeros_version=COALESCE(NULLIF(?,''),routeros_version),routerboot_version=COALESCE(NULLIF(?,''),routerboot_version) WHERE id=?",
            (version, rb_current, router_id),
        )
        conn.execute(
            """DELETE FROM router_telemetry WHERE router_id=? AND id NOT IN
               (SELECT id FROM router_telemetry WHERE router_id=? ORDER BY id DESC LIMIT ?)""",
            (router_id, router_id, settings.TELEMETRY_RETENTION_ROWS),
        )
        expected = conn.execute("SELECT expected_profile FROM router_expected_state WHERE router_id=?", (router_id,)).fetchone()

    cap = capabilities.get(router_id)
    if cap and cap["supports_performance_profiles"] and not any("FastTrack" in x or "QoS" in x for x in probe_errors):
        if expected and expected["expected_profile"] and expected["expected_profile"] != profile:
            events.record(router_id, "drift", f"Performance profile drift: expected {expected['expected_profile']}, found {profile}", severity="warning")

    current_sample = {
        "cpu_load": cpu,
        "free_memory": free_memory,
        "total_memory": total_memory,
        "uptime": uptime,
        "routeros_version": version,
    }
    try:
        resource_monitor.evaluate(router_id, current_sample, previous)
    except Exception as exc:
        probe_errors.append("resource monitor: " + errors.short(exc))

    if record_event:
        events.record(router_id, "telemetry", f"Telemetry collected: CPU {cpu}% · RouterOS {version or 'unknown'}", "; ".join(probe_errors), "warning" if probe_errors else "info")

    return {
        "captured_at": captured, "cpu_load": cpu, "version": version, "uptime": uptime,
        "free_memory": free_memory, "total_memory": total_memory,
        "routerboot_current": rb_current, "routerboot_upgrade": rb_upgrade,
        "fasttrack_enabled": int(fasttrack), "qos_enabled": int(qos),
        "tenant_queues_enabled": int(tenant), "raw_rule_count": raw_rules,
        "mss_clamp_enabled": int(mss), "profile": profile, "probe_errors": probe_errors,
    }


def latest_telemetry(router_id: int):
    ensure_schema()
    with core.db() as conn:
        return conn.execute("SELECT * FROM router_telemetry WHERE router_id=? ORDER BY id DESC LIMIT 1", (router_id,)).fetchone()


# ---- Backups / drift ------------------------------------------------------------

def _backup_impl(router_id: int, tier: str, created_by: str):
    if tier not in {"daily", "pre-change", "post-change", "commissioning"}:
        raise errors.OperationError("INVALID_BACKUP_TIER", "Invalid backup tier")
    router = _require_router(router_id)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    result = fleet._backup_one(router, stamp, tier=tier)
    with core.db() as conn:
        conn.execute(
            "INSERT INTO router_backup_records(router_id,created_at,tier,created_by,result) VALUES(?,?,?,?,?)",
            (router_id, now_iso(), tier, created_by, result),
        )
    events.record(router_id, "backup", f"{tier} backup completed", result)
    return result


def backup_router(router_id: int, tier: str, created_by: str, *, track_job: bool = True):
    job_id = None
    if track_job:
        job_id = jobs.create(router_id, "backup", created_by, tier, serialize_router=True)
        jobs.running(job_id)
    try:
        result = _backup_impl(router_id, tier, created_by)
        if job_id: jobs.succeeded(job_id)
        return result
    except Exception as exc:
        if job_id: jobs.failed(job_id, exc, code="BACKUP_FAILED", message="Router backup failed")
        raise


def _export_hash(router):
    content = router_exec.read(router["vpn_ip"], "/export terse", timeout=90, label="Configuration drift export")
    return hashlib.sha256(content.encode()).hexdigest(), content


def accept_baseline(router_id: int, created_by: str):
    router = _require_router(router_id)
    digest, content = _export_hash(router)
    state_capture.store_config_snapshot_content(router_id, content, source_kind="baseline", actor=created_by)
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
    router = _require_router(router_id)
    with core.db() as conn:
        expected = conn.execute("SELECT baseline_sha256,drifted FROM router_expected_state WHERE router_id=?", (router_id,)).fetchone()
    if not expected or not expected["baseline_sha256"]:
        return None
    digest, content = _export_hash(router)
    drifted = digest != expected["baseline_sha256"]
    if drifted:
        state_capture.store_config_snapshot_content(router_id, content, source_kind="drift", actor="scheduler")
    changed = bool(drifted) != bool(expected["drifted"])
    with core.db() as conn:
        conn.execute("UPDATE router_expected_state SET last_drift_check_at=?,drifted=? WHERE router_id=?", (now_iso(), int(drifted), router_id))
    if changed:
        events.record(router_id, "drift", "Configuration drift detected" if drifted else "Configuration returned to baseline", digest, "warning" if drifted else "info")
    return drifted


# ---- Commissioning / capabilities ----------------------------------------------
MANAGEMENT_PROBES = {
    "wireguard": ':put [/interface wireguard print count-only where name="opticable-wg"]',
    "tikcentral_user": ':put [/user print count-only where name="tikcentral" disabled=no]',
    "winbox": ':put [/ip service print count-only where name="winbox" disabled=no]',
    "ssh": ':put [/ip service print count-only where name="ssh" disabled=no]',
    "api": ':put [/ip service print count-only where name="api" disabled=no]',
}
BASELINE_PROBES = {
    "wan_dhcp": ':put [/ip dhcp-client print count-only where interface=ether1 disabled=no]',
    "pppoe_prepared": ':put [/interface pppoe-client print count-only where name="PPPOE-OUT-01"]',
    "raw_baseline": ':put [/ip firewall raw print count-only where comment~"^Opticable RAW"]',
    "mss_clamp": ':put [/ip firewall mangle print count-only where comment="Opticable MSS clamp" disabled=no]',
    "qos_staged": ':put [/queue tree print count-only where name~"^OPT-QOS-"]',
}


def validate_commissioning(router_id: int, created_by: str):
    ensure_schema()
    router = _require_router(router_id)
    job_id = jobs.create(router_id, "commissioning", created_by, serialize_router=True)
    jobs.running(job_id)
    try:
        access = guardian.probe_router(router)
        checks = {"guardian_access": bool(access["management_ok"])}
        observed = {}
        probe_errors = []
        for name, command in MANAGEMENT_PROBES.items():
            value, err = _probe_count(router["vpn_ip"], command, f"Commissioning {name}")
            observed[name] = value
            checks[name] = bool(value) if value is not None else False
            if err: probe_errors.append(err)

        baseline_values = {}
        for name, command in BASELINE_PROBES.items():
            value, err = _probe_count(router["vpn_ip"], command, f"Commissioning {name}")
            baseline_values[name] = value
            observed[name] = value
            if err: probe_errors.append(err)
        baseline_objects = int(baseline_values.get("raw_baseline") or 0) + int(baseline_values.get("mss_clamp") or 0) + int(baseline_values.get("qos_staged") or 0)
        existing_cap = capabilities.get(router_id)
        mode = existing_cap["mode"] if existing_cap else (capabilities.OPTICABLE_DEFAULT if baseline_objects > 0 else capabilities.TIKCENTRAL_ONLY)
        capabilities.set_mode(router_id, mode, now_iso(), "commissioning")

        if mode == capabilities.OPTICABLE_DEFAULT:
            checks.update({
                "wan_dhcp": int(baseline_values.get("wan_dhcp") or 0) > 0,
                "pppoe_prepared": int(baseline_values.get("pppoe_prepared") or 0) > 0,
                "raw_baseline": int(baseline_values.get("raw_baseline") or 0) >= 4,
                "mss_clamp": int(baseline_values.get("mss_clamp") or 0) > 0,
                "qos_staged": int(baseline_values.get("qos_staged") or 0) >= 2,
            })

        admin_user, admin_password = provisioning.get_admin_credentials()
        if admin_user and admin_password:
            safe = provisioning._ros(admin_user)
            value, err = _probe_count(router["vpn_ip"], f':put [/user print count-only where name="{safe}" disabled=no]', "Personal admin probe")
            observed["personal_admin"] = value
            checks["personal_admin"] = bool(value) if value is not None else False
            if err: probe_errors.append(err)
        else:
            checks["personal_admin"] = True

        telem = collect_telemetry(router_id)
        passed = all(checks.values())
        status = "passed" if passed else ("partial" if any(checks.values()) else "failed")
        report = {"passed": passed, "status": status, "mode": mode, "checks": checks, "observed": observed, "probe_errors": probe_errors, "telemetry": telem}
        with core.db() as conn:
            conn.execute(
                """INSERT INTO router_expected_state(router_id,expected_profile,commissioning_status,commissioning_at,commissioning_report)
                   VALUES(?,?,?,?,?) ON CONFLICT(router_id) DO UPDATE SET
                     expected_profile=excluded.expected_profile,commissioning_status=excluded.commissioning_status,
                     commissioning_at=excluded.commissioning_at,commissioning_report=excluded.commissioning_report""",
                (router_id, telem["profile"], status, now_iso(), json.dumps(report)),
            )
        if passed:
            try:
                _backup_impl(router_id, "commissioning", created_by)
                accept_baseline(router_id, created_by)
            except Exception as exc:
                report["passed"] = False
                report["status"] = "partial"
                report.setdefault("post_errors", []).append(errors.short(exc))
                with core.db() as conn:
                    conn.execute("UPDATE router_expected_state SET commissioning_status='partial',commissioning_report=? WHERE router_id=?", (json.dumps(report), router_id))
        events.record(router_id, "commissioning", f"Commissioning validation {report['status']} · {'Opticable default' if mode == capabilities.OPTICABLE_DEFAULT else 'Tikcentral only'}", json.dumps({"checks": checks, "errors": probe_errors}), "info" if report["passed"] else "warning")
        jobs.succeeded(job_id) if report["passed"] else jobs.transition(job_id, "succeeded")
        return report
    except Exception as exc:
        jobs.failed(job_id, exc, code="COMMISSIONING_FAILED", message="Commissioning validation failed")
        raise


# ---- Performance profile --------------------------------------------------------
def switch_profile(router_id: int, profile: str, created_by: str):
    if profile not in {"throughput", "fairness"}:
        raise errors.OperationError("INVALID_PROFILE", "Invalid performance profile")
    router = _require_router(router_id)
    if not capabilities.supports_profiles(router_id):
        raise errors.OperationError("CAPABILITY_UNSUPPORTED", "This router was not provisioned with the Opticable performance baseline")
    pre_access = change_control.require_management(router, "Performance profile change")
    job_id = jobs.create(router_id, "profile", created_by, profile, serialize_router=True)
    jobs.running(job_id)
    tx_id = change_control.begin(router_id, "profile", created_by, job_id=job_id, pre_access=pre_access)
    try:
        change_control.step(tx_id, "backup", "info", "Creating retained pre-change backup")
        _backup_impl(router_id, "pre-change", created_by)
        change_control.step(tx_id, "backup", "ok", "Pre-change backup completed")
        if profile == "fairness":
            command = r'''
/ip/firewall/filter set [find where comment="Opticable FastTrack"] disabled=yes;
/ip/firewall/mangle set [find where comment~"^Opticable QoS "] disabled=no;
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
        output = router_exec.mutate(router["vpn_ip"], command, timeout=60, label="Performance profile change")
        jobs.verifying(job_id)
        change_control.step(tx_id, "verify", "info", "Verifying management access and requested profile")
        post_access = change_control.verify_management(router, "Performance profile change", transaction_id=tx_id)
        telem = collect_telemetry(router_id)
        if telem["profile"] != profile:
            raise errors.OperationError("PROFILE_VERIFY_FAILED", "Router did not report the requested performance profile", f"requested={profile} observed={telem['profile']}")
        with core.db() as conn:
            conn.execute("""INSERT INTO router_expected_state(router_id,expected_profile) VALUES(?,?)
                          ON CONFLICT(router_id) DO UPDATE SET expected_profile=excluded.expected_profile""", (router_id, profile))
        events.record(router_id, "profile", f"Performance profile changed to {profile}", json.dumps({"cpu": telem["cpu_load"], "profile": profile}))
        change_control.finish(tx_id, post_access=post_access)
        jobs.succeeded(job_id)
        return output
    except Exception as exc:
        try:
            change_control.fail(tx_id, exc, post_access=guardian.probe_router(router))
        except Exception:
            pass
        jobs.failed(job_id, exc, code="PROFILE_CHANGE_FAILED", message="Performance profile change failed")
        events.record(router_id, "profile", "Performance profile change failed", errors.short(exc), "critical" if isinstance(exc, errors.OperationError) and exc.severity == "critical" else "warning")
        raise


# ---- RouterOS / RouterBOOT upgrades --------------------------------------------
UPDATE_CHECK_COMMAND = '/system/package/update check-for-updates once; :delay 5s; /system/package/update print'


def _size_bytes(value: str):
    match = re.match(r"(?i)^\s*([0-9.]+)\s*(B|KiB|MiB|GiB|KB|MB|GB)?", value or "")
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or "B").lower()
    scale = {"b": 1, "kib": 1024, "kb": 1000, "mib": 1024**2, "mb": 1000**2, "gib": 1024**3, "gb": 1000**3}[unit]
    return int(number * scale)


def _upgrade_preflight(router):
    access = change_control.require_management(router, "Router upgrade")
    resource = router_exec.read(router["vpn_ip"], "/system resource print without-paging", timeout=20, label="Upgrade preflight")
    free_hdd = _field(resource, "free-hdd-space")
    architecture = _field(resource, "architecture-name")
    version = _version_number(_field(resource, "version") or router["routeros_version"])
    free_bytes = _size_bytes(free_hdd)
    warnings = []
    if free_bytes is not None and free_bytes < 16 * 1024 * 1024:
        warnings.append(f"Low free storage reported: {free_hdd}")
    if not version:
        raise errors.OperationError("UPGRADE_PREFLIGHT_FAILED", "RouterOS version could not be verified before upgrade")
    if not router["model"]:
        warnings.append("Router model is not recorded")
    return {
        "access": access,
        "version": version,
        "architecture": architecture,
        "free_hdd_space": free_hdd,
        "warnings": warnings,
    }


def check_update(router_id: int):
    router = _require_router(router_id)
    if not _access_ok(router):
        raise errors.OperationError("GUARDIAN_UNHEALTHY", "Guardian access preflight failed")
    output = router_exec.read(router["vpn_ip"], UPDATE_CHECK_COMMAND, timeout=90, label="RouterOS update check")
    current = _version_number(_field(output, "installed-version") or router["routeros_version"])
    latest = _version_number(_field(output, "latest-version"))
    status = _field(output, "status")
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_update_status(router_id,checked_at,current_version,latest_version,update_status,last_error)
               VALUES(?,?,?,?,?,'') ON CONFLICT(router_id) DO UPDATE SET checked_at=excluded.checked_at,
                 current_version=excluded.current_version,latest_version=excluded.latest_version,
                 update_status=excluded.update_status,last_error=''""",
            (router_id, now_iso(), current, latest, status),
        )
    events.record(router_id, "upgrade", f"Update check: {status or 'completed'}", f"installed={current} latest={latest}")
    return current, latest, status


def approve_current_version(router_id: int, created_by: str):
    router = _require_router(router_id)
    if not router["model"]:
        raise errors.OperationError("MODEL_UNKNOWN", "Router model is unknown")
    telem = collect_telemetry(router_id)
    version = _version_number(telem.get("version", ""))
    if not version:
        raise errors.OperationError("VERSION_UNKNOWN", "RouterOS version is unavailable")
    with core.db() as conn:
        conn.execute(
            """INSERT INTO approved_versions(model,version,approved_at,approved_by) VALUES(?,?,?,?)
               ON CONFLICT(model) DO UPDATE SET version=excluded.version,approved_at=excluded.approved_at,approved_by=excluded.approved_by""",
            (router["model"], version, now_iso(), created_by),
        )
    events.record(router_id, "upgrade", f"RouterOS {version} approved for model {router['model']} by {created_by}")
    return version


def queue_upgrade(router_id: int, canary: bool, created_by: str):
    router = _require_router(router_id)
    change_control.require_management(router, "RouterOS upgrade")
    with core.db() as conn:
        status = conn.execute("SELECT * FROM router_update_status WHERE router_id=?", (router_id,)).fetchone()
        approved = conn.execute("SELECT version FROM approved_versions WHERE model=?", (router["model"],)).fetchone()
    if not status or not status["latest_version"]:
        raise errors.OperationError("UPDATE_NOT_CHECKED", "Check for RouterOS updates first")
    target = _version_number(status["latest_version"])
    approved_version = _version_number(approved["version"]) if approved else ""
    if not canary and approved_version != target:
        raise errors.OperationError("VERSION_NOT_APPROVED", f"RouterOS {target} is not approved for {router['model']}")
    job_id = jobs.create(router_id, "upgrade_routeros", created_by, target, {"canary": bool(canary)}, serialize_router=True, serialize_global_kind="upgrade_")
    events.record(router_id, "upgrade", f"{'Canary' if canary else 'Approved'} RouterOS upgrade queued to {target}")
    return job_id


def queue_routerboot(router_id: int, created_by: str):
    router = _require_router(router_id)
    change_control.require_management(router, "RouterBOOT upgrade")
    telem = collect_telemetry(router_id)
    target = telem.get("routerboot_upgrade") or ""
    if not target or target == telem.get("routerboot_current"):
        raise errors.OperationError("ROUTERBOOT_CURRENT", "RouterBOOT is already current")
    job_id = jobs.create(router_id, "upgrade_routerboot", created_by, target, {}, serialize_router=True, serialize_global_kind="upgrade_")
    events.record(router_id, "upgrade", f"RouterBOOT upgrade queued to {target}")
    return job_id


def _active_upgrade_job():
    with core.db() as conn:
        return conn.execute(
            """SELECT * FROM router_jobs WHERE kind LIKE 'upgrade_%' AND status IN ('queued','running','verifying') ORDER BY id LIMIT 1"""
        ).fetchone()


def _process_upgrade_job():
    job = _active_upgrade_job()
    if not job:
        return None
    router = _router(job["router_id"])
    if not router:
        jobs.failed(job["id"], errors.OperationError("ROUTER_NOT_FOUND", "Router disappeared during upgrade"))
        return job["id"]
    kind = job["kind"]
    if job["status"] == "queued":
        if not router["enabled"] or (router["lifecycle_state"] or "production") == "retired":
            err = errors.OperationError("ROUTER_INACTIVE", "Queued upgrade cancelled because the router is disabled or retired")
            jobs.failed(job["id"], err)
            events.record(router["id"], "upgrade", "Queued upgrade cancelled", err.message, "warning")
            return job["id"]
        if not _access_ok(router):
            return job["id"]
        tx_id = None
        try:
            jobs.running(job["id"])
            preflight = _upgrade_preflight(router)
            tx_id = change_control.begin(router["id"], kind, job["actor"] or "upgrade", job_id=job["id"], pre_access=preflight["access"])
            change_control.step(tx_id, "preflight", "warning" if preflight["warnings"] else "ok", "Upgrade preflight completed", json.dumps(preflight, default=str))
            pre_hash, _ = _export_hash(router)
            jobs.update_payload(job["id"], {"pre_hash": pre_hash, "healthy_checks": 0, "transaction_id": tx_id, "preflight": preflight})
            change_control.step(tx_id, "backup", "info", "Creating pre-upgrade backup")
            _backup_impl(router["id"], "pre-change", "upgrade")
            change_control.step(tx_id, "backup", "ok", "Pre-upgrade backup completed", pre_hash)
            if kind == "upgrade_routeros":
                detail = router_exec.dispatch_reboot(router["vpn_ip"], "/system/package/update install", timeout=900, label="RouterOS upgrade")
            else:
                detail = router_exec.dispatch_reboot(router["vpn_ip"], "/system/routerboard upgrade; :delay 3s; /system/reboot", timeout=90, label="RouterBOOT upgrade")
            change_control.step(tx_id, "apply", "ok", "Upgrade/reboot dispatched", detail)
            jobs.verifying(job["id"])
            events.record(router["id"], "upgrade", f"{kind.replace('_',' ')} dispatched to {job['target']}", detail)
        except Exception as exc:
            if tx_id is not None:
                try: change_control.fail(tx_id, exc)
                except Exception: pass
            jobs.failed(job["id"], exc, code="UPGRADE_DISPATCH_FAILED", message="Upgrade dispatch failed")
            events.record(router["id"], "upgrade", "Upgrade dispatch failed", errors.short(exc), "critical")
        return job["id"]

    if job["status"] == "running":
        # A restart can interrupt the short dispatch phase after the job has
        # become running. Never re-dispatch an upgrade blindly; resume at
        # verification so an already-sent reboot can complete safely, while an
        # upgrade that was never dispatched will fail version verification.
        jobs.verifying(job["id"])
        events.record(router["id"], "upgrade", "Recovered interrupted upgrade job", f"job {job['id']} resumed at verification after an interrupted dispatch phase", "warning")
        job = jobs.get(job["id"])

    if job["status"] == "verifying":
        timeout = 1200 if kind == "upgrade_routeros" else 900
        payload = jobs.payload(job["id"])
        tx_id = int(payload.get("transaction_id") or 0)
        if not _access_ok(router):
            if _seconds_since(job["started_at"]) > timeout:
                err = errors.OperationError("UPGRADE_RETURN_TIMEOUT", "Router did not return healthy after upgrade", severity="critical")
                jobs.failed(job["id"], err)
                events.record(router["id"], "upgrade", err.message, severity="critical")
            return job["id"]
        try:
            post_access = change_control.verify_management(router, "Upgrade", transaction_id=tx_id or None)
            telem = collect_telemetry(router["id"])
            if kind == "upgrade_routeros":
                current = _version_number(telem.get("version", ""))
                if current != _version_number(job["target"]):
                    raise errors.OperationError("UPGRADE_VERIFY_FAILED", "RouterOS version verification failed", f"expected={job['target']} observed={current}")
            else:
                if not (telem.get("routerboot_current") and telem.get("routerboot_current") == telem.get("routerboot_upgrade")):
                    raise errors.OperationError("ROUTERBOOT_VERIFY_FAILED", "RouterBOOT versions still differ", f"current={telem.get('routerboot_current')} available={telem.get('routerboot_upgrade')}")

            healthy_checks = int(payload.get("healthy_checks", 0)) + 1
            jobs.update_payload(job["id"], {"healthy_checks": healthy_checks, "last_verified_at": now_iso()})
            if tx_id:
                change_control.step(tx_id, "verify", "ok", f"Post-upgrade health sample {healthy_checks}/2", json.dumps({"access": post_access, "version": telem.get("version", "")}, default=str))
            if healthy_checks < 2:
                events.record(router["id"], "upgrade", f"Post-upgrade health sample {healthy_checks}/2 passed", "Waiting for a second healthy Guardian sample before committing upgrade")
                return job["id"]

            jobs.succeeded(job["id"])
            if tx_id:
                change_control.finish(tx_id, post_access=post_access)
            events.record(router["id"], "upgrade", f"{'RouterOS ' + _version_number(telem.get('version','')) if kind == 'upgrade_routeros' else 'RouterBOOT'} upgrade verified", "Two consecutive healthy management checks passed")
        except Exception as exc:
            payload = jobs.payload(job["id"])
            tx_id = int(payload.get("transaction_id") or 0)
            if tx_id:
                try: change_control.fail(tx_id, exc, post_access=guardian.probe_router(router))
                except Exception: pass
            jobs.failed(job["id"], exc, code="UPGRADE_VERIFY_FAILED", message="Upgrade verification failed")
            events.record(router["id"], "upgrade", "Upgrade verification failed", errors.short(exc), "critical")
        return job["id"]
    return job["id"]


# ---- Scheduler -----------------------------------------------------------------
def scheduled_tick():
    ensure_schema()
    _process_upgrade_job()
    with core.db() as conn:
        s = conn.execute("SELECT * FROM operations_settings WHERE id=1").fetchone()
        routers = conn.execute(
            """SELECT r.id FROM routers r JOIN router_access_state a ON a.router_id=r.id
               WHERE r.enabled=1 AND a.management_ok=1 ORDER BY r.id"""
        ).fetchall()
    now = now_iso()
    if _seconds_since(s["last_telemetry_at"]) >= int(s["telemetry_interval_seconds"]):
        ids = [r["id"] for r in routers]
        with ThreadPoolExecutor(max_workers=max(1, min(settings.MAX_WORKERS, len(ids) or 1))) as pool:
            futures = {pool.submit(collect_telemetry, rid, False): rid for rid in ids}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as exc:
                    events.record(futures[fut], "telemetry", "Telemetry collection failed", errors.short(exc), "warning")
        with core.db() as conn:
            conn.execute("UPDATE operations_settings SET last_telemetry_at=? WHERE id=1", (now,))
    if _seconds_since(s["last_drift_at"]) >= int(s["drift_interval_seconds"]):
        with core.db() as conn:
            due = conn.execute(
                """SELECT e.router_id FROM router_expected_state e JOIN router_access_state a ON a.router_id=e.router_id
                   WHERE e.baseline_sha256<>'' AND a.management_ok=1 ORDER BY e.router_id"""
            ).fetchall()
        ids = [r["router_id"] for r in due]
        with ThreadPoolExecutor(max_workers=max(1, min(4, len(ids) or 1))) as pool:
            futures = {pool.submit(check_drift, rid): rid for rid in ids}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as exc:
                    events.record(futures[fut], "drift", "Drift check failed", errors.short(exc), "warning")
        with core.db() as conn:
            conn.execute("UPDATE operations_settings SET last_drift_at=? WHERE id=1", (now,))


# ---- UI ------------------------------------------------------------------------
def _actor(user):
    try:
        return user["email"]
    except Exception:
        return "admin"


def _post_button(action, csrf, label, danger=False, confirm=""):
    cls = ' class="danger"' if danger else ''
    oc = f' onclick="return confirm(\'{html.escape(confirm)}\')"' if confirm else ''
    return f'<form method="post" action="{action}" style="display:inline"><input type="hidden" name="csrf" value="{csrf}"><button{cls}{oc}>{html.escape(label)}</button></form>'


def _health_state(row):
    if not row["management_ok"]:
        return "Access degraded"
    if row["drifted"]:
        return "Config drift"
    if (row["commissioning_status"] or "") in {"failed", "partial"}:
        return "Commissioning issue"
    if row["latest_version"] and _version_number(row["latest_version"]) != _version_number(row["routeros_version"]):
        return "Upgrade pending"
    return "Healthy"


def _error_page(page_func, user, router_id: int, title: str, exc: Exception):
    err = errors.from_exception(exc)
    try:
        events.record(router_id, "operation", f"{title} failed", f"{err.code}: {err.detail}", err.severity)
    except Exception:
        pass
    body = f'''<div class="panel pad"><h2>{html.escape(title)}</h2><div class="error"><strong>{html.escape(err.code)}</strong><div style="margin-top:6px">{html.escape(err.message)}</div>{f'<div class="muted" style="margin-top:6px">{html.escape(err.detail)}</div>' if err.detail else ''}</div><div style="margin-top:14px"><a href="/operations/{router_id}"><button class="primary">Back to router</button></a></div></div>'''
    return page_func("Operations", body, user, "operations")


def register(app, page_func):
    ensure_schema()

    @app.get("/operations", response_class=HTMLResponse)
    def operations_index(request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        with core.db() as conn:
            rows = conn.execute(
                """SELECT r.id,r.site_name,r.model,r.routeros_version,r.vpn_ip,
                          a.management_ok,a.last_good_at,
                          t.cpu_load,t.free_memory,t.fasttrack_enabled,t.qos_enabled,t.captured_at,
                          e.expected_profile,e.drifted,e.commissioning_status,
                          c.mode capability_mode,c.supports_performance_profiles,
                          u.latest_version,
                          v.version approved_version
                   FROM routers r
                   LEFT JOIN router_access_state a ON a.router_id=r.id
                   LEFT JOIN router_telemetry t ON t.id=(SELECT id FROM router_telemetry WHERE router_id=r.id ORDER BY id DESC LIMIT 1)
                   LEFT JOIN router_expected_state e ON e.router_id=r.id
                   LEFT JOIN router_capabilities c ON c.router_id=r.id
                   LEFT JOIN router_update_status u ON u.router_id=r.id
                   LEFT JOIN approved_versions v ON v.model=r.model
                   WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired' ORDER BY r.site_name COLLATE NOCASE,r.id"""
            ).fetchall()
        body_rows = []
        counts = {"Healthy":0,"Access degraded":0,"Config drift":0,"Commissioning issue":0,"Upgrade pending":0}
        for r in rows:
            health = _health_state(r); counts[health] = counts.get(health,0)+1
            profile = "N/A" if not r["supports_performance_profiles"] else ("Fairness/QoS" if r["qos_enabled"] and not r["fasttrack_enabled"] else "Maximum throughput")
            body_rows.append(f'''<tr><td><strong>{html.escape(r['site_name'])}</strong><div class="muted">{html.escape(r['model'] or '')} · <code>{html.escape(r['vpn_ip'])}</code></div></td><td>{health}</td><td>{html.escape(r['capability_mode'] or 'tikcentral_only')}</td><td>{html.escape(r['routeros_version'] or '-')}<div class="muted">Approved: {html.escape(r['approved_version'] or '-')}</div></td><td>{html.escape(profile)}</td><td>{str(r['cpu_load'])+'%' if r['cpu_load'] is not None else '-'}<div class="muted">{html.escape(r['free_memory'] or '')}</div></td><td>{html.escape(r['commissioning_status'] or 'not_checked')}</td><td><a href="/operations/{r['id']}"><button>Open</button></a></td></tr>''')
        cards = ''.join(f'<div class="card"><div class="muted">{html.escape(k)}</div><div class="value">{v}</div></div>' for k,v in counts.items())
        body = f'''<div class="panel pad"><h2>Operations</h2><div class="muted">Access-first control plane. Optional telemetry/drift failures do not affect Guardian or remote management.</div></div><div class="cards">{cards}</div><div class="panel"><table><thead><tr><th>Router</th><th>Health</th><th>Capability</th><th>RouterOS</th><th>Profile</th><th>CPU / RAM</th><th>Commissioning</th><th></th></tr></thead><tbody>{''.join(body_rows) or '<tr><td colspan="8">No routers.</td></tr>'}</tbody></table></div>'''
        return page_func("Operations", body, user, "operations")

    @app.get("/operations/{router_id}", response_class=HTMLResponse)
    def operations_router(router_id: int, request: Request):
        user = core.require_web_admin(request)
        if not user:
            return RedirectResponse("/login", status_code=303)
        router = _router(router_id)
        if not router:
            return RedirectResponse("/operations", status_code=303)
        csrf = core.csrf_token(request)
        telem = latest_telemetry(router_id)
        cap = capabilities.get(router_id)
        with core.db() as conn:
            access = conn.execute("SELECT * FROM router_access_state WHERE router_id=?", (router_id,)).fetchone()
            expected = conn.execute("SELECT * FROM router_expected_state WHERE router_id=?", (router_id,)).fetchone()
            update = conn.execute("SELECT * FROM router_update_status WHERE router_id=?", (router_id,)).fetchone()
            approved = conn.execute("SELECT * FROM approved_versions WHERE model=?", (router["model"],)).fetchone()
            backups = conn.execute("SELECT * FROM router_backup_records WHERE router_id=? ORDER BY id DESC LIMIT 12", (router_id,)).fetchall()
            compliance_row = conn.execute("SELECT * FROM router_policy_compliance WHERE router_id=?", (router_id,)).fetchone()
            lte_latest = conn.execute("SELECT * FROM router_lte_history WHERE router_id=? ORDER BY id DESC LIMIT 1", (router_id,)).fetchone()
            outage = conn.execute("SELECT * FROM router_outage_assessment WHERE router_id=?", (router_id,)).fetchone()
            site_meta = conn.execute("SELECT * FROM router_site_metadata WHERE router_id=?", (router_id,)).fetchone()
            interface_latest = conn.execute(
                "SELECT captured_at,name,running,disabled,rx_errors,tx_errors,rx_drops,tx_drops,link_downs,rate,full_duplex,poe_out FROM router_interface_history WHERE router_id=? ORDER BY id DESC LIMIT 1",
                (router_id,),
            ).fetchone()
            security_row = conn.execute("SELECT * FROM router_security_audit WHERE router_id=?", (router_id,)).fetchone()
            automation_time = conn.execute("SELECT MAX(captured_at) t FROM router_automation_inventory WHERE router_id=?", (router_id,)).fetchone()["t"]
            unmanaged_count = conn.execute(
                "SELECT COUNT(*) c FROM router_automation_inventory WHERE router_id=? AND captured_at=? AND enabled=1 AND managed=0",
                (router_id, automation_time or ""),
            ).fetchone()["c"] if automation_time else 0
            traffic_latest = conn.execute(
                "SELECT interface,rx_bps,tx_bps,captured_at FROM router_traffic_history WHERE router_id=? AND rx_bps IS NOT NULL ORDER BY id DESC LIMIT 1",
                (router_id,),
            ).fetchone()
            capacity_row = conn.execute("SELECT * FROM router_capacity_forecast WHERE router_id=?", (router_id,)).fetchone()
            recent_notes = conn.execute(
                "SELECT * FROM operator_notes WHERE router_id=? ORDER BY id DESC LIMIT 8",
                (router_id,),
            ).fetchall()
            wan_probe_latest = conn.execute(
                "SELECT * FROM router_wan_probe_history WHERE router_id=? ORDER BY id DESC LIMIT 1",
                (router_id,),
            ).fetchone()
            desired_state_row = conn.execute("SELECT * FROM router_desired_state_status WHERE router_id=?", (router_id,)).fetchone()
            checklist_row = conn.execute("SELECT * FROM commissioning_checklist_status WHERE router_id=?", (router_id,)).fetchone()
            time_health_row = conn.execute("SELECT * FROM router_time_health WHERE router_id=?", (router_id,)).fetchone()
            mtu_latest = conn.execute("SELECT * FROM router_mtu_history WHERE router_id=? ORDER BY id DESC LIMIT 1", (router_id,)).fetchone()
            public_ip_analysis_row = conn.execute("SELECT * FROM router_public_ip_analysis WHERE router_id=?", (router_id,)).fetchone()
            local_utilization_row = conn.execute("SELECT * FROM router_local_utilization WHERE router_id=? ORDER BY id DESC LIMIT 1", (router_id,)).fetchone()
            model_capability_row = conn.execute("SELECT * FROM router_model_capability_observations WHERE router_id=?", (router_id,)).fetchone()
            log_pattern_time = conn.execute("SELECT MAX(captured_at) t FROM router_log_patterns WHERE router_id=?", (router_id,)).fetchone()["t"]
            log_warning_count = conn.execute(
                "SELECT COUNT(*) c FROM router_log_patterns WHERE router_id=? AND captured_at=? AND severity='warning'",
                (router_id, log_pattern_time or ""),
            ).fetchone()["c"] if log_pattern_time else 0
            hardware_lifecycle_row = conn.execute("SELECT * FROM router_hardware_lifecycle WHERE router_id=?", (router_id,)).fetchone()
            network_quality_row = conn.execute("SELECT * FROM router_wan_quality WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
            gateway_quality_row = conn.execute("SELECT * FROM router_isp_gateway_history WHERE router_id=? ORDER BY id DESC LIMIT 1",(router_id,)).fetchone()
            dns_quality_time = conn.execute("SELECT MAX(captured_at) t FROM router_dns_health WHERE router_id=?",(router_id,)).fetchone()["t"]
            dns_failures = conn.execute("SELECT COUNT(*) c FROM router_dns_health WHERE router_id=? AND captured_at=? AND ok=0",(router_id,dns_quality_time or "")).fetchone()["c"] if dns_quality_time else 0
            topology_time = conn.execute("SELECT MAX(captured_at) t FROM router_topology_devices WHERE router_id=?", (router_id,)).fetchone()["t"]
            topology_count = conn.execute(
                "SELECT COUNT(*) c FROM router_topology_devices WHERE router_id=? AND captured_at=?",
                (router_id, topology_time or ""),
            ).fetchone()["c"] if topology_time else 0
        recent_jobs = jobs.latest(router_id, 15)
        txs = change_control.latest(router_id, 15)
        tx_by_job = {int(t["job_id"]): t for t in txs if t["job_id"] is not None}
        evs = events.recent(router_id, 80)
        profile = "fairness" if telem and telem["qos_enabled"] and not telem["fasttrack_enabled"] else "throughput"
        telemetry_text = "No telemetry yet" if not telem else f"CPU {telem['cpu_load']}% · RAM {html.escape(telem['free_memory'])}/{html.escape(telem['total_memory'])} · uptime {html.escape(telem['uptime'])} · RouterOS {html.escape(telem['routeros_version'])} · RouterBOOT {html.escape(telem['routerboot_current'])}/{html.escape(telem['routerboot_upgrade'])}"
        profile_buttons = ""
        if cap and cap["supports_performance_profiles"]:
            profile_buttons = _post_button(f"/operations/{router_id}/profile/throughput", csrf, "Use maximum throughput") + " " + _post_button(f"/operations/{router_id}/profile/fairness", csrf, "Use Fairness/QoS")
        upgrade_buttons = _post_button(f"/operations/{router_id}/update/check", csrf, "Check RouterOS update")
        if update and update["latest_version"]:
            upgrade_buttons += " " + _post_button(f"/operations/{router_id}/upgrade/canary", csrf, f"Canary upgrade to {update['latest_version']}", True, "Start one-router canary upgrade?")
            if approved and _version_number(approved["version"]) == _version_number(update["latest_version"]):
                upgrade_buttons += " " + _post_button(f"/operations/{router_id}/upgrade/approved", csrf, f"Upgrade approved {approved['version']}", True, "Upgrade this router?")
        if telem and telem["routerboot_upgrade"] and telem["routerboot_upgrade"] != telem["routerboot_current"]:
            upgrade_buttons += " " + _post_button(f"/operations/{router_id}/routerboot", csrf, "Upgrade RouterBOOT", True, "Upgrade RouterBOOT and reboot?")
        approve = _post_button(f"/operations/{router_id}/approve-version", csrf, "Approve current version for model")
        drift_status = "No baseline" if not expected or not expected["baseline_sha256"] else ("DRIFT DETECTED" if expected["drifted"] else "Matches baseline")
        commissioning = expected["commissioning_status"] if expected else "not_checked"
        backup_rows = ''.join(f"<tr><td>{html.escape(b['tier'])}</td><td>{html.escape(b['created_at'])}</td><td>{html.escape(b['created_by'])}</td><td>{html.escape((b['result'] or '')[-180:])}</td></tr>" for b in backups) or '<tr><td colspan="4">No tracked backups.</td></tr>'
        job_rows_parts = []
        for j in recent_jobs:
            tx = tx_by_job.get(int(j["id"]))
            transcript = f'<div><a href="/reliability#tx-{tx["id"]}">Transaction #{tx["id"]}</a> · <a href="/notes/{router_id}?type=change&id={tx["id"]}">Add change note</a></div>' if tx else ""
            note_link = f'<div><a href="/notes/{router_id}?type=job&id={j["id"]}">Add note</a></div>'
            job_rows_parts.append(f"<tr><td>{html.escape(j['created_at'])}</td><td>{html.escape(j['kind'])}{transcript}{note_link}</td><td>{html.escape(j['status'])}</td><td>{html.escape(j['target'] or '-')}</td><td>{html.escape(j['error_code'] or '')} {html.escape(j['error_message'] or '')}</td></tr>")
        job_rows = ''.join(job_rows_parts) or '<tr><td colspan="5">No jobs.</td></tr>'
        event_rows = ''.join(f"<tr><td>{html.escape(e['event_at'])}</td><td>{html.escape(e['severity'])}</td><td>{html.escape(e['category'])}</td><td>{html.escape(e['summary'])}<div class=\"muted\">{html.escape((e['details'] or '')[-600:])}</div></td></tr>" for e in evs) or '<tr><td colspan="4">No events.</td></tr>'
        compliance_text = "Not checked" if not compliance_row else f'{compliance_row["status"]} · {compliance_row["passed"]} pass / {compliance_row["warnings"]} warn / {compliance_row["failed"]} fail'
        lte_text = "No LTE history" if not lte_latest else f'{lte_latest["band"] or "-"} · RSRP {lte_latest["rsrp"] if lte_latest["rsrp"] is not None else "—"} dBm · SINR {lte_latest["sinr"] if lte_latest["sinr"] is not None else "—"} dB'
        outage_text = "No assessment yet" if not outage else f'{outage["summary"]} · confidence {outage["confidence"]}'
        site_text = "No customer/site metadata" if not site_meta else " · ".join(x for x in (site_meta["customer_name"],site_meta["site_code"],site_meta["circuit_type"]) if x) or "Metadata saved"
        interface_text = "No interface samples" if not interface_latest else f'{interface_latest["name"]} · {"up" if interface_latest["running"] else "down"} · {interface_latest["rate"] or "-"}'
        security_text = "Not checked" if not security_row else f'{security_row["status"]} · {security_row["critical_count"]} critical / {security_row["warning_count"]} warning'
        automation_text = f'{unmanaged_count} enabled unmanaged object(s)' if automation_time else "Not inventoried"
        traffic_text = "No traffic rate yet" if not traffic_latest else f'{traffic_latest["interface"]} · RX {(traffic_latest["rx_bps"] or 0)/1e6:.2f} Mbps / TX {(traffic_latest["tx_bps"] or 0)/1e6:.2f} Mbps'
        capacity_text = "Not assessed" if not capacity_row else f'{capacity_row["status"]} · {capacity_row["summary"]}'
        wan_probe_text = "No multi-target probe yet" if not wan_probe_latest else f'{wan_probe_latest["classification"]} · {wan_probe_latest["summary"]}'
        desired_text = "Not checked" if not desired_state_row else f'{desired_state_row["status"]} · {desired_state_row["failed"]} fail / {desired_state_row["warnings"]} warning / {desired_state_row["passed"]} pass'
        checklist_text = "Not evaluated" if not checklist_row else f'{checklist_row["status"]} · {checklist_row["passed"]}/{checklist_row["required"]} required'
        time_health_text = "Not checked" if not time_health_row else f'{time_health_row["status"]} · {time_health_row["summary"]}'
        mtu_text = "Not tested" if not mtu_latest else f'{mtu_latest["status"]} · {mtu_latest["summary"]}'
        public_ip_text = "No transition history" if not public_ip_analysis_row else f'{public_ip_analysis_row["status"]} · {public_ip_analysis_row["summary"]}'
        local_utilization_text = "No estimate yet" if not local_utilization_row else f'{local_utilization_row["summary"]}'
        model_capability_text = "Not observed yet" if not model_capability_row else f'{model_capability_row["model"]} · {model_capability_row["architecture"] or "-"} · {model_capability_row["ethernet_ports"] or 0} Ethernet / {model_capability_row["sfp_ports"] or 0} SFP / {model_capability_row["lte_interfaces"] or 0} LTE'
        log_pattern_text = "No log-pattern sample yet" if not log_pattern_time else f'{log_warning_count} warning pattern(s) in latest sample'
        hardware_lifecycle_text = "Not assessed" if not hardware_lifecycle_row else f'{hardware_lifecycle_row["summary"]}'
        network_quality_text = "Not assessed" if not network_quality_row else f'{network_quality_row["status"]} · {network_quality_row["summary"]}'
        gateway_quality_text = "Not assessed" if not gateway_quality_row else gateway_quality_row["summary"]
        dns_quality_text = "No DNS sample yet" if not dns_quality_time else f'{dns_failures} resolver failure(s) in latest sample'
        topology_text = f'{topology_count} external switch/AP device(s) observed or inventoried' if topology_time else "No topology evidence yet"
        notes_rows = ''.join(
            f'<tr><td>{html.escape(n["created_at"])}</td><td>{html.escape(n["object_type"])} {("#"+str(n["object_id"])) if n["object_id"] else ""}</td><td>{html.escape(n["ticket_reference"] or "-")}</td><td>{html.escape(n["visibility"])}</td><td>{html.escape(n["note"])}</td></tr>'
            for n in recent_notes
        ) or '<tr><td colspan="5">No operator notes.</td></tr>'
        body = f'''<div class="panel pad"><h2>{html.escape(router['site_name'])}</h2><div class="muted">{html.escape(router['model'] or '')} · <code>{html.escape(router['vpn_ip'])}</code> · capability: {html.escape(cap['mode'] if cap else 'tikcentral_only')}</div><div class="inline" style="margin-top:12px"><a href="/timeline/{router_id}"><button>Full timeline</button></a><a href="/timeline/{router_id}/before"><button>What changed before failure?</button></a><a href="/incidents/{router_id}"><button>Build incident</button></a><a href="/compliance/{router_id}"><button>Compliance</button></a><a href="/lte/{router_id}"><button>LTE</button></a><a href="/interfaces/{router_id}"><button>Interfaces</button></a><a href="/site/{router_id}"><button>Site / customer</button></a><a href="/diagnostics/{router_id}"><button>Safe diagnostics</button></a><a href="/protection/{router_id}"><button>Protected objects</button></a><a href="/recovery/{router_id}"><button>Recovery</button></a><a href="/lifecycle/{router_id}"><button>Lifecycle</button></a><a href="/maintenance-history/{router_id}"><button>Maintenance history</button></a><a href="/hardware/{router_id}"><button>Hardware</button></a><a href="/certificates/{router_id}"><button>Certificates</button></a><a href="/change-calendar"><button>Calendar</button></a><a href="/security-audit/{router_id}"><button>Security exposure</button></a><a href="/automation-inventory/{router_id}"><button>RouterOS automation</button></a><a href="/traffic/{router_id}"><button>Traffic</button></a><a href="/capacity/{router_id}"><button>Capacity trends</button></a><a href="/notes/{router_id}"><button>Operator notes</button></a><a href="/customer-report/{router_id}"><button>Customer report</button></a><a href="/topology/{router_id}"><button>Topology</button></a><a href="/wan-probe/{router_id}"><button>WAN probe</button></a><a href="/desired-state/{router_id}"><button>Desired state</button></a><a href="/replacements?source={router_id}"><button>Replace router</button></a><a href="/alerts"><button>Alert queue</button></a><a href="/commissioning-checklist/{router_id}"><button>Commissioning checklist</button></a><a href="/time-health/{router_id}"><button>Time / NTP</button></a><a href="/mtu/{router_id}"><button>MTU / MSS</button></a><a href="/public-ip-analysis/{router_id}"><button>Public IP churn</button></a><a href="/local-utilization/{router_id}"><button>Local utilization</button></a><a href="/log-patterns/{router_id}"><button>Log patterns</button></a><a href="/model-capabilities"><button>Model capabilities</button></a><a href="/identity-collisions"><button>Identity collisions</button></a><a href="/hardware-lifecycle/{router_id}"><button>Hardware lifecycle</button></a><a href="/network-quality/{router_id}"><button>Network quality</button></a><a href="/cross-site-anomalies"><button>Cross-site anomalies</button></a></div></div>
<div class="panel pad"><h3>Lifecycle</h3><div>{html.escape(router["lifecycle_state"] or "production").title()}</div><div class="muted">{html.escape(router["lifecycle_updated_at"] or "")} {html.escape(router["lifecycle_updated_by"] or "")}</div></div>
<div class="panel pad"><h3>Site / customer</h3><div>{html.escape(site_text)}</div></div>
<div class="panel pad"><h3>Outage domain</h3><div>{html.escape(outage_text)}</div><div class="muted">{html.escape(outage["evidence"] if outage else "")}</div></div>
<div class="panel pad"><h3>Interface health</h3><div>{html.escape(interface_text)}</div></div>
<div class="panel pad"><h3>Security exposure</h3><div>{html.escape(security_text)}</div></div>
<div class="panel pad"><h3>RouterOS automation</h3><div>{html.escape(automation_text)}</div></div>
<div class="panel pad"><h3>Traffic</h3><div>{html.escape(traffic_text)}</div></div>
<div class="panel pad"><h3>Capacity trends</h3><div>{html.escape(capacity_text)}</div></div>
<div class="panel pad"><h3>Topology</h3><div>{html.escape(topology_text)}</div></div>
<div class="panel pad"><h3>WAN probe</h3><div>{html.escape(wan_probe_text)}</div></div>
<div class="panel pad"><h3>Desired state</h3><div>{html.escape(desired_text)}</div></div>
<div class="panel pad"><h3>Commissioning checklist</h3><div>{html.escape(checklist_text)}</div><div style="margin-top:10px"><a href="/commissioning-checklist/{router_id}"><button>Open checklist</button></a></div></div>
<div class="panel pad"><h3>Time / NTP</h3><div>{html.escape(time_health_text)}</div></div>
<div class="panel pad"><h3>MTU / MSS</h3><div>{html.escape(mtu_text)}</div></div>
<div class="panel pad"><h3>Public IP churn</h3><div>{html.escape(public_ip_text)}</div></div>
<div class="panel pad"><h3>Local network utilization</h3><div>{html.escape(local_utilization_text)}</div></div>
<div class="panel pad"><h3>Model capabilities</h3><div>{html.escape(model_capability_text)}</div></div>
<div class="panel pad"><h3>Router log patterns</h3><div>{html.escape(log_pattern_text)}</div></div>
<div class="panel pad"><h3>Hardware lifecycle</h3><div>{html.escape(hardware_lifecycle_text)}</div></div>
<div class="panel pad"><h3>Network quality</h3><div>{html.escape(network_quality_text)}</div><div class="muted">DNS: {html.escape(dns_quality_text)} · Gateway: {html.escape(gateway_quality_text)}</div></div>
<div class="panel pad"><h3>Golden policy</h3><div>{html.escape(compliance_text)}</div></div>
<div class="panel pad"><h3>LTE</h3><div>{html.escape(lte_text)}</div></div>
<div class="panel pad"><h3>Access / commissioning</h3><div>{'Healthy' if access and access['management_ok'] else 'Degraded'} · commissioning {html.escape(commissioning)} · config {html.escape(drift_status)}</div><div class="inline" style="margin-top:12px">{_post_button(f'/operations/{router_id}/commission',csrf,'Run commissioning validation')} {_post_button(f'/operations/{router_id}/baseline',csrf,'Accept current baseline')} {_post_button(f'/operations/{router_id}/drift/check',csrf,'Check drift')}</div></div>
<div class="panel pad"><h3>Telemetry</h3><div>{telemetry_text}</div><div class="inline" style="margin-top:12px">{_post_button(f'/operations/{router_id}/telemetry',csrf,'Refresh telemetry')} {_post_button(f'/operations/{router_id}/backup/pre-change',csrf,'Take retained backup')}</div></div>
<div class="panel pad"><h3>Performance</h3><div>Current: {html.escape(profile if cap and cap['supports_performance_profiles'] else 'N/A')}</div><div class="inline" style="margin-top:12px">{profile_buttons or '<span class="muted">Performance profiles are not enabled for this router capability.</span>'}</div></div>
<div class="panel pad"><h3>RouterOS / RouterBOOT</h3><div class="inline">{upgrade_buttons} {approve}</div></div>
<div class="panel"><table><thead><tr><th>Backup tier</th><th>Time</th><th>By</th><th>Result</th></tr></thead><tbody>{backup_rows}</tbody></table></div>
<div class="panel"><table><thead><tr><th>Time</th><th>Job</th><th>Status</th><th>Target</th><th>Error</th></tr></thead><tbody>{job_rows}</tbody></table></div>
<div class="panel"><div class="pad"><h3>Recent operator notes</h3></div><table><thead><tr><th>Time</th><th>Attached</th><th>Ticket</th><th>Visibility</th><th>Note</th></tr></thead><tbody>{notes_rows}</tbody></table></div>
<div class="panel"><table><thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Event</th></tr></thead><tbody>{event_rows}</tbody></table></div>'''
        return page_func("Router Operations", body, user, "operations")

    async def auth(request):
        user = core.require_web_admin(request)
        if not user:
            return None
        data = await core.form_data(request)
        core.require_csrf(request, data.get("csrf", ""))
        return user

    @app.post("/operations/{router_id}/telemetry", response_class=HTMLResponse)
    async def telemetry_action(router_id: int, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try: await run_in_threadpool(collect_telemetry, router_id, True)
        except Exception as exc: return _error_page(page_func,user,router_id,"Refresh telemetry",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/commission", response_class=HTMLResponse)
    async def commission_action(router_id: int, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try: await run_in_threadpool(validate_commissioning, router_id, _actor(user))
        except Exception as exc: return _error_page(page_func,user,router_id,"Commissioning validation",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/profile/{profile}", response_class=HTMLResponse)
    async def profile_action(router_id: int, profile: str, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try: await run_in_threadpool(switch_profile, router_id, profile, _actor(user))
        except Exception as exc: return _error_page(page_func,user,router_id,"Performance profile change",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/backup/{tier}", response_class=HTMLResponse)
    async def backup_action(router_id: int, tier: str, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try: await run_in_threadpool(backup_router, router_id, tier, _actor(user))
        except Exception as exc: return _error_page(page_func,user,router_id,"Router backup",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/drift/check", response_class=HTMLResponse)
    async def drift_action(router_id: int, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try: await run_in_threadpool(check_drift, router_id)
        except Exception as exc: return _error_page(page_func,user,router_id,"Configuration drift check",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/baseline", response_class=HTMLResponse)
    async def baseline_action(router_id: int, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try: await run_in_threadpool(accept_baseline, router_id, _actor(user))
        except Exception as exc: return _error_page(page_func,user,router_id,"Accept configuration baseline",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/update/check", response_class=HTMLResponse)
    async def update_action(router_id: int, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try: await run_in_threadpool(check_update, router_id)
        except Exception as exc: return _error_page(page_func,user,router_id,"RouterOS update check",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/upgrade/{mode}", response_class=HTMLResponse)
    async def upgrade_action(router_id: int, mode: str, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try:
            if mode not in {"canary","approved"}: raise errors.OperationError("INVALID_UPGRADE_MODE","Invalid upgrade mode")
            queue_upgrade(router_id,mode=="canary",_actor(user))
        except Exception as exc: return _error_page(page_func,user,router_id,"Queue RouterOS upgrade",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/routerboot", response_class=HTMLResponse)
    async def routerboot_action(router_id: int, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try: queue_routerboot(router_id,_actor(user))
        except Exception as exc: return _error_page(page_func,user,router_id,"Queue RouterBOOT upgrade",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)

    @app.post("/operations/{router_id}/approve-version", response_class=HTMLResponse)
    async def approve_action(router_id: int, request: Request):
        user = await auth(request)
        if not user: return RedirectResponse("/login", status_code=303)
        try: approve_current_version(router_id,_actor(user))
        except Exception as exc: return _error_page(page_func,user,router_id,"Approve RouterOS version",exc)
        return RedirectResponse(f"/operations/{router_id}", status_code=303)
