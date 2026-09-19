"""One deterministic fleet-health read model.

Health is derived from persisted authoritative state. This module never probes a
router, mutates configuration, or becomes a second source of truth.
"""

from dataclasses import dataclass

from app import jobs, main as core, migrations

HEALTHY = "Healthy"
OFFLINE = "Offline"
ACCESS_DEGRADED = "Access degraded"
CHANGE_IN_PROGRESS = "Change in progress"
CONFIG_DRIFT = "Config drift"
COMMISSIONING_ISSUE = "Commissioning issue"
UPGRADE_PENDING = "Upgrade pending"
UNKNOWN = "Unknown"


@dataclass(frozen=True)
class FleetHealth:
    router_id: int
    state: str
    detail: str = ""


def ensure_schema():
    migrations.migrate()


def _version(value: str) -> str:
    return (value or "").strip().split()[0] if (value or "").strip() else ""


def get(router_id: int) -> FleetHealth:
    ensure_schema()
    with core.db() as conn:
        row = conn.execute(
            """SELECT r.id,r.enabled,r.lifecycle_state,r.routeros_version,
                      a.wg_online,a.management_ok,a.last_error,
                      e.drifted,e.commissioning_status,
                      u.latest_version
               FROM routers r
               LEFT JOIN router_access_state a ON a.router_id=r.id
               LEFT JOIN router_expected_state e ON e.router_id=r.id
               LEFT JOIN router_update_status u ON u.router_id=r.id
               WHERE r.id=?""",
            (router_id,),
        ).fetchone()
    if not row:
        return FleetHealth(router_id, UNKNOWN, "Router not found")
    if (row["lifecycle_state"] or "production") == "retired":
        return FleetHealth(router_id, UNKNOWN, "Router is retired")
    if not row["enabled"]:
        return FleetHealth(router_id, UNKNOWN, "Router is not enabled")
    if row["management_ok"] is None:
        return FleetHealth(router_id, UNKNOWN, "Guardian has not checked this router yet")
    if not row["wg_online"]:
        return FleetHealth(router_id, OFFLINE, row["last_error"] or "WireGuard peer is offline")
    if not row["management_ok"]:
        return FleetHealth(router_id, ACCESS_DEGRADED, row["last_error"] or "Management path is degraded")
    active = jobs.active_for_router(router_id)
    if active:
        return FleetHealth(router_id, CHANGE_IN_PROGRESS, f"{active['kind']} · {active['status']}")
    if row["drifted"]:
        return FleetHealth(router_id, CONFIG_DRIFT, "Configuration differs from accepted baseline")
    if (row["commissioning_status"] or "") in {"failed", "partial"}:
        return FleetHealth(router_id, COMMISSIONING_ISSUE, row["commissioning_status"])
    if _version(row["latest_version"]) and _version(row["latest_version"]) != _version(row["routeros_version"]):
        return FleetHealth(router_id, UPGRADE_PENDING, f"RouterOS {_version(row['latest_version'])} available")
    return FleetHealth(router_id, HEALTHY, "Management access is healthy")


def all_states() -> dict[int, FleetHealth]:
    ensure_schema()
    with core.db() as conn:
        ids = [int(r[0]) for r in conn.execute("SELECT id FROM routers WHERE enabled=1 AND COALESCE(lifecycle_state,'production')<>'retired' ORDER BY id")]
    return {router_id: get(router_id) for router_id in ids}


def counts() -> dict[str, int]:
    result: dict[str, int] = {}
    for item in all_states().values():
        result[item.state] = result.get(item.state, 0) + 1
    return result
