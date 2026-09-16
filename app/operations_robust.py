"""Resilient telemetry collection for RouterOS.

Core resource telemetry is required. Optional RouterBOOT/firewall/queue probes are
split into separate short SSH calls so one slow RouterOS query cannot stall the
entire sample. Errors exposed to the event timeline are intentionally concise.
"""

import subprocess

from app import events
from app import fleet
from app import main as core
from app import operations


CORE_COMMAND = r'''
:put ("TC|uptime|" . [/system/resource get uptime]);
:put ("TC|version|" . [/system/resource get version]);
:put ("TC|cpu_load|" . [/system/resource get cpu-load]);
:put ("TC|free_memory|" . [/system/resource get free-memory]);
:put ("TC|total_memory|" . [/system/resource get total-memory]);
'''.strip()

ROUTERBOOT_COMMAND = r'''
:put ("TC|routerboot_current|" . [/system/routerboard get current-firmware]);
:put ("TC|routerboot_upgrade|" . [/system/routerboard get upgrade-firmware]);
'''.strip()

FIREWALL_COMMAND = r'''
:put ("TC|fasttrack_enabled|" . [/ip/firewall/filter print count-only where comment="Opticable FastTrack" disabled=no]);
:put ("TC|raw_rule_count|" . [/ip/firewall/raw print count-only where comment~"^Opticable RAW"]);
:put ("TC|mss_clamp_enabled|" . [/ip/firewall/mangle print count-only where comment="Opticable MSS clamp" disabled=no]);
'''.strip()

QOS_COMMAND = r'''
:put ("TC|qos_enabled|" . [/queue/tree print count-only where name~"^OPT-QOS-" disabled=no]);
:put ("TC|tenant_queues_enabled|" . [/queue/simple print count-only where comment~"Opticable tenant cap" disabled=no]);
'''.strip()


def _exec(ip: str, command: str, timeout: int, label: str, required: bool = False):
    try:
        return fleet.ssh_exec(ip, command, timeout=timeout), ""
    except subprocess.TimeoutExpired:
        if required:
            raise RuntimeError(f"{label} telemetry timed out after {timeout} seconds")
        return "", f"{label} probe timed out"
    except Exception as exc:
        msg = str(exc).strip().splitlines()[-1] if str(exc).strip() else exc.__class__.__name__
        if len(msg) > 180:
            msg = msg[:177] + "..."
        if required:
            raise RuntimeError(f"{label} telemetry failed: {msg}")
        return "", f"{label} probe failed: {msg}"


def collect_telemetry(router_id: int, record_event: bool = False):
    operations.ensure_schema()
    router = operations._router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")

    core_out, _ = _exec(router["vpn_ip"], CORE_COMMAND, 15, "Core", required=True)
    rb_out, rb_err = _exec(router["vpn_ip"], ROUTERBOOT_COMMAND, 10, "RouterBOOT")
    fw_out, fw_err = _exec(router["vpn_ip"], FIREWALL_COMMAND, 12, "Firewall")
    qos_out, qos_err = _exec(router["vpn_ip"], QOS_COMMAND, 12, "QoS")

    m = operations._markers("\n".join(x for x in (core_out, rb_out, fw_out, qos_out) if x))
    if "version" not in m:
        raise RuntimeError("core telemetry response was incomplete")

    with core.db() as conn:
        previous = conn.execute(
            "SELECT * FROM router_telemetry WHERE router_id=? ORDER BY id DESC LIMIT 1",
            (router_id,),
        ).fetchone()

    def prev(name, default=""):
        return previous[name] if previous is not None and name in previous.keys() else default

    fasttrack = operations._int(m["fasttrack_enabled"]) > 0 if "fasttrack_enabled" in m else bool(prev("fasttrack_enabled", 0))
    qos = operations._int(m["qos_enabled"]) > 0 if "qos_enabled" in m else bool(prev("qos_enabled", 0))
    tenant_queues = operations._int(m["tenant_queues_enabled"]) > 0 if "tenant_queues_enabled" in m else bool(prev("tenant_queues_enabled", 0))
    raw_count = operations._int(m["raw_rule_count"]) if "raw_rule_count" in m else int(prev("raw_rule_count", 0) or 0)
    mss = operations._int(m["mss_clamp_enabled"]) > 0 if "mss_clamp_enabled" in m else bool(prev("mss_clamp_enabled", 0))
    rb_current = m.get("routerboot_current", prev("routerboot_current", ""))
    rb_upgrade = m.get("routerboot_upgrade", prev("routerboot_upgrade", ""))
    profile = "fairness" if qos and not fasttrack else "throughput"
    captured = operations.now_iso()

    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_telemetry
               (router_id,captured_at,cpu_load,free_memory,total_memory,uptime,routeros_version,
                routerboot_current,routerboot_upgrade,fasttrack_enabled,qos_enabled,
                tenant_queues_enabled,raw_rule_count,mss_clamp_enabled)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (router_id, captured, operations._int(m.get("cpu_load")), m.get("free_memory", ""),
             m.get("total_memory", ""), m.get("uptime", ""), m.get("version", ""),
             rb_current, rb_upgrade, int(fasttrack), int(qos), int(tenant_queues), raw_count, int(mss)),
        )
        conn.execute(
            "UPDATE routers SET routeros_version=?,routerboot_version=? WHERE id=?",
            (m.get("version", ""), rb_current, router_id),
        )
        expected = conn.execute(
            "SELECT expected_profile FROM router_expected_state WHERE router_id=?", (router_id,)
        ).fetchone()

    # Only evaluate profile drift when both policy probes succeeded. Partial data
    # should never create a false configuration warning.
    if not fw_err and not qos_err and expected and expected["expected_profile"] and expected["expected_profile"] != profile:
        events.record(router_id, "drift", f"Performance profile drift: expected {expected['expected_profile']}, found {profile}", severity="warning")

    probe_errors = [x for x in (rb_err, fw_err, qos_err) if x]
    if record_event:
        summary = f"Telemetry collected: CPU {operations._int(m.get('cpu_load'))}% · RouterOS {m.get('version','')}"
        details = "; ".join(probe_errors)
        events.record(router_id, "telemetry", summary, details, "warning" if probe_errors else "info")

    return {**m, "profile": profile, "captured_at": captured, "probe_errors": probe_errors,
            "routerboot_current": rb_current, "routerboot_upgrade": rb_upgrade}


def install():
    operations.collect_telemetry = collect_telemetry
    events.ensure_schema()
    with core.db() as conn:
        conn.execute(
            """UPDATE router_events
               SET details='Legacy telemetry timeout; detailed command text removed after telemetry hardening.'
               WHERE category='telemetry' AND summary='Telemetry collection failed'
                 AND (details LIKE '%timed out after%' OR length(details) > 800)"""
        )
