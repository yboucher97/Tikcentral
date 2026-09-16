"""Compatibility layer for commissioning existing and freshly provisioned routers.

Tikcentral-only enrollment must not fail commissioning because the router does not
contain the Opticable E50 RAW/MSS/QoS baseline. Fresh-provisioned routers are
recognized by presence of one or more Opticable baseline objects and validated
against the full baseline.
"""

import json

from app import events
from app import main as core
from app import operations
from app import provisioning


VALIDATE_COMMAND = r'''
:put ("TC|wg|" . [/interface/wireguard print count-only where name="opticable-wg"]);
:put ("TC|tikcentral_user|" . [/user print count-only where name="tikcentral" disabled=no]);
:put ("TC|winbox|" . [/ip/service print count-only where name="winbox" disabled=no]);
:put ("TC|ssh|" . [/ip/service print count-only where name="ssh" disabled=no]);
:put ("TC|api|" . [/ip/service print count-only where name="api" disabled=no]);
:put ("TC|wan_dhcp|" . [/ip/dhcp-client print count-only where interface=ether1 disabled=no]);
:put ("TC|pppoe|" . [/interface/pppoe-client print count-only where name="PPPOE-OUT-01"]);
:put ("TC|raw|" . [/ip/firewall/raw print count-only where comment~"^Opticable RAW"]);
:put ("TC|mss|" . [/ip/firewall/mangle print count-only where comment="Opticable MSS clamp" disabled=no]);
:put ("TC|qos_staged|" . [/queue/tree print count-only where name~"^OPT-QOS-"]);
'''.strip()


def validate_commissioning(router_id: int, created_by: str):
    router = operations._router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")

    access = operations.guardian.probe_router(router)
    admin_user, admin_password = provisioning.get_admin_credentials()
    extra = ""
    if admin_user and admin_password:
        safe = admin_user.replace('"', '')
        extra = f'; :put ("TC|personal_admin|" . [/user print count-only where name="{safe}" disabled=no])'

    output = operations.fleet.ssh_exec(router["vpn_ip"], VALIDATE_COMMAND + extra, timeout=35)
    m = operations._markers(output)

    baseline_objects = (
        operations._int(m.get("raw"))
        + operations._int(m.get("mss"))
        + operations._int(m.get("qos_staged"))
    )
    mode = "opticable_default" if baseline_objects > 0 else "tikcentral_only"

    checks = {
        "guardian_access": bool(access["management_ok"]),
        "wireguard": operations._int(m.get("wg")) > 0,
        "tikcentral_user": operations._int(m.get("tikcentral_user")) > 0,
        "winbox": operations._int(m.get("winbox")) > 0,
        "ssh": operations._int(m.get("ssh")) > 0,
        "api": operations._int(m.get("api")) > 0,
        "personal_admin": True if not admin_user else operations._int(m.get("personal_admin")) > 0,
    }

    if mode == "opticable_default":
        checks.update({
            "wan_dhcp": operations._int(m.get("wan_dhcp")) > 0,
            "pppoe_prepared": operations._int(m.get("pppoe")) > 0,
            "raw_baseline": operations._int(m.get("raw")) >= 4,
            "mss_clamp": operations._int(m.get("mss")) > 0,
            "qos_staged": operations._int(m.get("qos_staged")) >= 2,
        })

    passed = all(checks.values())
    telem = operations.collect_telemetry(router_id)
    report = {
        "passed": passed,
        "mode": mode,
        "checks": checks,
        "observed": m,
        "telemetry": telem,
    }
    status = "passed" if passed else "failed"
    now = operations.now_iso()

    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_expected_state(router_id,expected_profile,commissioning_status,commissioning_at,commissioning_report)
               VALUES(?,?,?,?,?) ON CONFLICT(router_id) DO UPDATE SET commissioning_status=excluded.commissioning_status,
                 commissioning_at=excluded.commissioning_at,commissioning_report=excluded.commissioning_report""",
            (router_id, telem["profile"], status, now, json.dumps(report)),
        )

    backup_error = ""
    if passed:
        try:
            operations.backup_router(router_id, "commissioning", created_by)
        except Exception as exc:
            backup_error = str(exc)
            events.record(router_id, "operation", "commissioning backup failed", backup_error, "warning")
        try:
            operations.accept_baseline(router_id, created_by)
        except Exception as exc:
            events.record(router_id, "operation", "commissioning baseline capture failed", str(exc), "warning")

    summary = f"Commissioning validation {status} · {'Tikcentral only' if mode == 'tikcentral_only' else 'Opticable default'}"
    details = {"mode": mode, "checks": checks}
    if backup_error:
        details["backup_error"] = backup_error
    events.record(router_id, "commissioning", summary, json.dumps(details), "info" if passed else "warning")
    return report


def install():
    operations.validate_commissioning = validate_commissioning


install()
