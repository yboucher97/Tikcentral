"""Small safety/compatibility patches for the Operations control plane."""

import json

from app import events
from app import main as core
from app import operations
from app import fleet

_installed = False


def _version_number(value: str) -> str:
    return (value or "").strip().split()[0] if (value or "").strip() else ""


def _approve_current_version(router_id: int, created_by: str):
    router = operations._router(router_id)
    if not router or not router["model"]:
        raise RuntimeError("router model is unknown")
    telem = operations.collect_telemetry(router_id)
    version = _version_number(telem.get("version", ""))
    if not version:
        raise RuntimeError("RouterOS version unavailable")
    with core.db() as conn:
        conn.execute(
            """INSERT INTO approved_versions(model,version,approved_at,approved_by) VALUES(?,?,?,?)
               ON CONFLICT(model) DO UPDATE SET version=excluded.version,approved_at=excluded.approved_at,approved_by=excluded.approved_by""",
            (router["model"], version, operations.now_iso(), created_by),
        )
    events.record(router_id, "upgrade", f"RouterOS {version} approved for model {router['model']} by {created_by}")
    return version


def _queue_upgrade(router_id: int, canary: bool, created_by: str):
    router = operations._router(router_id)
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
    target = _version_number(status["latest_version"])
    approved_version = _version_number(approved["version"]) if approved else ""
    if not canary and approved_version != target:
        raise RuntimeError(f"{target} is not approved for model {router['model']}; run it as a canary first")
    if not operations._access_ok(router):
        raise RuntimeError("Guardian access preflight failed; upgrade blocked")
    with core.db() as conn:
        cur = conn.execute(
            "INSERT INTO router_upgrade_jobs(router_id,target_version,stage,status,canary,created_by,created_at) VALUES(?,?,'routeros','queued',?,?,?)",
            (router_id, target, int(canary), created_by, operations.now_iso()),
        )
    events.record(router_id, "upgrade", f"{'Canary' if canary else 'Approved'} RouterOS upgrade queued to {target}")
    return cur.lastrowid


def _switch_profile(router_id: int, profile: str, created_by: str):
    if profile not in {"throughput", "fairness"}:
        raise ValueError("invalid profile")
    router = operations._router(router_id)
    if not router or not router["enabled"]:
        raise RuntimeError("enabled router not found")
    if not operations._access_ok(router):
        raise RuntimeError("Guardian access preflight failed; profile change blocked")
    operations.backup_router(router_id, "pre-change", created_by)
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
    output = fleet.ssh_exec(router["vpn_ip"], command, timeout=60)
    if not operations._access_ok(router):
        events.record(router_id, "profile", f"Profile change to {profile} completed but management verification failed", output, "critical")
        raise RuntimeError("profile changed, but Guardian verification failed; inspect router immediately")
    telem = operations.collect_telemetry(router_id)
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_expected_state(router_id,expected_profile)
               VALUES(?,?) ON CONFLICT(router_id) DO UPDATE SET expected_profile=excluded.expected_profile""",
            (router_id, profile),
        )
    events.record(router_id, "profile", f"Performance profile changed to {profile}", json.dumps(telem))
    return output


def install():
    global _installed
    if _installed:
        return
    operations.approve_current_version = _approve_current_version
    operations.queue_upgrade = _queue_upgrade
    operations.switch_profile = _switch_profile
    _installed = True


install()
