"""Failure-tolerant Operations probes.

Router-side command failures are operational state, not web application failures.
Keep individual probes small, preserve last-known optional telemetry, and make
commissioning return a report even when one or more RouterOS checks fail.
"""

import json
import re
import subprocess

from app import events
from app import fleet
from app import guardian
from app import main as core
from app import operations
from app import provisioning


def _short_error(exc) -> str:
    if isinstance(exc, subprocess.TimeoutExpired):
        return "probe timed out"
    text = str(exc).strip()
    if not text:
        text = exc.__class__.__name__
    # subprocess timeout messages can include the complete RouterOS command.
    if "timed out after" in text.lower():
        return "probe timed out"
    line = text.splitlines()[-1].strip()
    return line[:220] + ("..." if len(line) > 220 else "")


def _exec(ip: str, command: str, timeout: int = 10):
    try:
        return fleet.ssh_exec(ip, command, timeout=timeout), ""
    except Exception as exc:
        return "", _short_error(exc)


def _field(output: str, name: str) -> str:
    m = re.search(rf"(?mi)^\s*{re.escape(name)}:\s*(.+?)\s*$", output or "")
    return m.group(1).strip() if m else ""


def _count_value(output: str):
    for line in reversed((output or "").splitlines()):
        line = line.strip()
        if re.fullmatch(r"\d+", line):
            return int(line)
    return None


def _probe_count(ip: str, command: str, timeout: int = 8):
    output, error = _exec(ip, command, timeout)
    if error:
        return None, error
    value = _count_value(output)
    if value is None:
        return None, "unexpected RouterOS response"
    return value, ""


def collect_telemetry(router_id: int, record_event: bool = False):
    operations.ensure_schema()
    router = operations._router(router_id)
    if not router or not router["enabled"]:
        return {"profile": "unknown", "captured_at": operations.now_iso(), "probe_errors": ["router not enabled"]}

    latest = operations.latest_telemetry(router_id)
    errors = []

    resource_out, resource_err = _exec(router["vpn_ip"], "/system resource print without-paging", 12)
    if resource_err:
        errors.append("resource: " + resource_err)

    version = _field(resource_out, "version") or (latest["routeros_version"] if latest else router["routeros_version"] or "")
    uptime = _field(resource_out, "uptime") or (latest["uptime"] if latest else "")
    free_memory = _field(resource_out, "free-memory") or (latest["free_memory"] if latest else "")
    total_memory = _field(resource_out, "total-memory") or (latest["total_memory"] if latest else "")
    cpu_text = _field(resource_out, "cpu-load")
    cpu_load = operations._int(cpu_text, latest["cpu_load"] if latest and latest["cpu_load"] is not None else 0)

    rb_out, rb_err = _exec(router["vpn_ip"], "/system routerboard print without-paging", 8)
    if rb_err:
        errors.append("RouterBOOT: " + rb_err)
    routerboot_current = _field(rb_out, "current-firmware") or (latest["routerboot_current"] if latest else "")
    routerboot_upgrade = _field(rb_out, "upgrade-firmware") or (latest["routerboot_upgrade"] if latest else "")

    fasttrack_count, err = _probe_count(
        router["vpn_ip"], ':put [/ip firewall filter print count-only where comment="Opticable FastTrack" disabled=no]', 8
    )
    if err:
        errors.append("FastTrack: " + err)
    raw_count, err = _probe_count(
        router["vpn_ip"], ':put [/ip firewall raw print count-only where comment~"^Opticable RAW"]', 8
    )
    if err:
        errors.append("RAW: " + err)
    mss_count, err = _probe_count(
        router["vpn_ip"], ':put [/ip firewall mangle print count-only where comment="Opticable MSS clamp" disabled=no]', 8
    )
    if err:
        errors.append("MSS: " + err)
    qos_count, err = _probe_count(
        router["vpn_ip"], ':put [/queue tree print count-only where name~"^OPT-QOS-" disabled=no]', 8
    )
    if err:
        errors.append("QoS: " + err)
    tenant_count, err = _probe_count(
        router["vpn_ip"], ':put [/queue simple print count-only where comment~"Opticable tenant cap" disabled=no]', 8
    )
    if err:
        errors.append("tenant queues: " + err)

    # Missing optional data retains last-known state instead of inventing OFF.
    fasttrack = bool(fasttrack_count) if fasttrack_count is not None else bool(latest["fasttrack_enabled"] if latest else 0)
    qos = bool(qos_count) if qos_count is not None else bool(latest["qos_enabled"] if latest else 0)
    tenant_enabled = bool(tenant_count) if tenant_count is not None else bool(latest["tenant_queues_enabled"] if latest else 0)
    raw_rule_count = raw_count if raw_count is not None else int(latest["raw_rule_count"] if latest else 0)
    mss_enabled = bool(mss_count) if mss_count is not None else bool(latest["mss_clamp_enabled"] if latest else 0)
    profile = "fairness" if qos and not fasttrack else "throughput"
    captured = operations.now_iso()

    # If even the core resource query failed and there is no previous sample,
    # don't create a misleading all-zero telemetry row.
    if resource_err and not latest:
        if record_event:
            events.record(router_id, "telemetry", "Telemetry unavailable", "; ".join(errors), "warning")
        return {"profile": "unknown", "captured_at": captured, "probe_errors": errors, "version": version}

    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_telemetry
               (router_id,captured_at,cpu_load,free_memory,total_memory,uptime,routeros_version,
                routerboot_current,routerboot_upgrade,fasttrack_enabled,qos_enabled,
                tenant_queues_enabled,raw_rule_count,mss_clamp_enabled)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (router_id, captured, cpu_load, free_memory, total_memory, uptime, version,
             routerboot_current, routerboot_upgrade, int(fasttrack), int(qos), int(tenant_enabled),
             raw_rule_count, int(mss_enabled)),
        )
        if version or routerboot_current:
            conn.execute(
                "UPDATE routers SET routeros_version=COALESCE(NULLIF(?,''),routeros_version), routerboot_version=COALESCE(NULLIF(?,''),routerboot_version) WHERE id=?",
                (version, routerboot_current, router_id),
            )
        expected = conn.execute("SELECT expected_profile FROM router_expected_state WHERE router_id=?", (router_id,)).fetchone()

    if expected and expected["expected_profile"] and expected["expected_profile"] != profile and fasttrack_count is not None and qos_count is not None:
        events.record(router_id, "drift", f"Performance profile drift: expected {expected['expected_profile']}, found {profile}", severity="warning")

    if record_event:
        severity = "warning" if errors else "info"
        summary = f"Telemetry collected: CPU {cpu_load}% · RouterOS {version or 'unknown'}"
        events.record(router_id, "telemetry", summary, "; ".join(errors), severity)

    return {
        "uptime": uptime, "version": version, "cpu_load": str(cpu_load),
        "free_memory": free_memory, "total_memory": total_memory,
        "routerboot_current": routerboot_current, "routerboot_upgrade": routerboot_upgrade,
        "fasttrack_enabled": str(int(fasttrack)), "qos_enabled": str(int(qos)),
        "tenant_queues_enabled": str(int(tenant_enabled)), "raw_rule_count": str(raw_rule_count),
        "mss_clamp_enabled": str(int(mss_enabled)), "profile": profile,
        "captured_at": captured, "probe_errors": errors,
    }


COMMISSION_PROBES = {
    "wireguard": ':put [/interface wireguard print count-only where name="opticable-wg"]',
    "tikcentral_user": ':put [/user print count-only where name="tikcentral" disabled=no]',
    "winbox": ':put [/ip service print count-only where name="winbox" disabled=no]',
    "ssh": ':put [/ip service print count-only where name="ssh" disabled=no]',
    "api": ':put [/ip service print count-only where name="api" disabled=no]',
    "wan_dhcp": ':put [/ip dhcp-client print count-only where interface=ether1 disabled=no]',
    "pppoe_prepared": ':put [/interface pppoe-client print count-only where name="PPPOE-OUT-01"]',
    "raw_baseline": ':put [/ip firewall raw print count-only where comment~"^Opticable RAW"]',
    "mss_clamp": ':put [/ip firewall mangle print count-only where comment="Opticable MSS clamp" disabled=no]',
    "qos_staged": ':put [/queue tree print count-only where name~"^OPT-QOS-"]',
}


def validate_commissioning(router_id: int, created_by: str):
    operations.ensure_schema()
    router = operations._router(router_id)
    now = operations.now_iso()
    if not router or not router["enabled"]:
        report = {"passed": False, "checks": {}, "errors": ["router not enabled"]}
        return report

    try:
        access = guardian.probe_router(router)
        management_ok = bool(access.get("management_ok"))
    except Exception as exc:
        management_ok = False
        access = {}
        access_error = _short_error(exc)
    else:
        access_error = ""

    observed = {}
    errors = []
    checks = {"guardian_access": management_ok}
    if access_error:
        errors.append("Guardian: " + access_error)

    for name, command in COMMISSION_PROBES.items():
        value, error = _probe_count(router["vpn_ip"], command, 8)
        observed[name] = value
        if error:
            errors.append(f"{name}: {error}")
            checks[name] = False
        elif name == "raw_baseline":
            checks[name] = value >= 4
        elif name == "qos_staged":
            checks[name] = value >= 2
        else:
            checks[name] = value > 0

    admin_user, admin_password = provisioning.get_admin_credentials()
    if admin_user and admin_password:
        safe_user = admin_user.replace('"', "")
        value, error = _probe_count(router["vpn_ip"], f':put [/user print count-only where name="{safe_user}" disabled=no]', 8)
        observed["personal_admin"] = value
        checks["personal_admin"] = bool(value) if value is not None else False
        if error:
            errors.append("personal_admin: " + error)
    else:
        checks["personal_admin"] = True

    telemetry = collect_telemetry(router_id, False)
    telemetry_errors = telemetry.get("probe_errors", [])
    errors.extend("telemetry: " + e for e in telemetry_errors)
    profile = telemetry.get("profile", "unknown")

    passed = all(checks.values()) and management_ok
    status = "passed" if passed else ("partial" if any(checks.values()) else "failed")
    report = {
        "passed": passed, "status": status, "checks": checks,
        "observed": observed, "access": access, "telemetry": telemetry,
        "errors": errors,
    }

    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_expected_state(router_id,expected_profile,commissioning_status,commissioning_at,commissioning_report)
               VALUES(?,?,?,?,?) ON CONFLICT(router_id) DO UPDATE SET
                 expected_profile=CASE WHEN excluded.expected_profile='unknown' THEN router_expected_state.expected_profile ELSE excluded.expected_profile END,
                 commissioning_status=excluded.commissioning_status,
                 commissioning_at=excluded.commissioning_at,
                 commissioning_report=excluded.commissioning_report""",
            (router_id, profile, status, now, json.dumps(report)),
        )

    # Only create retained backups/baselines after a clean pass. Backup failures
    # are reported, but do not turn the web request into an HTTP 500.
    if passed:
        try:
            operations.backup_router(router_id, "commissioning", created_by)
            operations.accept_baseline(router_id, created_by)
        except Exception as exc:
            errors.append("post-commission backup/baseline: " + _short_error(exc))
            report["errors"] = errors
            report["passed"] = False
            report["status"] = "partial"
            with core.db() as conn:
                conn.execute(
                    "UPDATE router_expected_state SET commissioning_status='partial', commissioning_report=? WHERE router_id=?",
                    (json.dumps(report), router_id),
                )

    events.record(
        router_id, "commissioning", f"Commissioning validation {report['status']}",
        json.dumps({"checks": checks, "errors": errors}),
        "info" if report["passed"] else "warning",
    )
    return report


def install():
    operations.collect_telemetry = collect_telemetry
    operations.validate_commissioning = validate_commissioning
    events.ensure_schema()
    # Remove command dumps left by the older timeout handler.
    with core.db() as conn:
        conn.execute(
            """UPDATE router_events
               SET details='Legacy router probe timeout; verbose command text removed.'
               WHERE (category='telemetry' OR category='commissioning')
                 AND (details LIKE '%timed out after%' OR length(details) > 1500)"""
        )
