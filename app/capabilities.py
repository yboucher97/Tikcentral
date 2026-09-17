"""Typed router capability profiles.

Tikcentral-only routers must never be judged or modified as if they were built
from the Opticable fresh-router baseline. Capability profiles provide one source
of truth for which controls/checks apply to each router.
"""

from dataclasses import dataclass

from app import main as core
from app import migrations

TIKCENTRAL_ONLY = "tikcentral_only"
OPTICABLE_DEFAULT = "opticable_default"
VALID_MODES = {TIKCENTRAL_ONLY, OPTICABLE_DEFAULT}


@dataclass(frozen=True)
class RouterCapabilities:
    router_id: int
    mode: str
    supports_performance_profiles: bool
    supports_rescue: bool
    managed_baseline: bool
    source: str = "detected"

    @property
    def management_only(self) -> bool:
        return self.mode == TIKCENTRAL_ONLY

    @property
    def opticable_default(self) -> bool:
        return self.mode == OPTICABLE_DEFAULT


def ensure_schema():
    migrations.migrate()


def _from_row(router_id: int, row) -> RouterCapabilities:
    if not row:
        return RouterCapabilities(router_id, TIKCENTRAL_ONLY, False, True, False, "default")
    mode = row["mode"] if row["mode"] in VALID_MODES else TIKCENTRAL_ONLY
    return RouterCapabilities(
        router_id=router_id,
        mode=mode,
        supports_performance_profiles=bool(row["supports_performance_profiles"]),
        supports_rescue=bool(row["supports_rescue"]),
        managed_baseline=(mode == OPTICABLE_DEFAULT),
        source=row["source"] or "detected",
    )


def get(router_id: int) -> RouterCapabilities:
    ensure_schema()
    with core.db() as conn:
        row = conn.execute("SELECT * FROM router_capabilities WHERE router_id=?", (router_id,)).fetchone()
    return _from_row(router_id, row)


def set_mode(router_id: int, mode: str, detected_at: str, source: str = "detected") -> RouterCapabilities:
    if mode not in VALID_MODES:
        raise ValueError("invalid router capability mode")
    supports_profiles = int(mode == OPTICABLE_DEFAULT)
    with core.db() as conn:
        conn.execute(
            """INSERT INTO router_capabilities(router_id,mode,supports_performance_profiles,supports_rescue,detected_at,source)
               VALUES(?,?,?,1,?,?)
               ON CONFLICT(router_id) DO UPDATE SET mode=excluded.mode,
                 supports_performance_profiles=excluded.supports_performance_profiles,
                 supports_rescue=excluded.supports_rescue,
                 detected_at=excluded.detected_at,source=excluded.source""",
            (router_id, mode, supports_profiles, detected_at, source),
        )
    return get(router_id)


def mode(router_id: int) -> str:
    return get(router_id).mode


def supports_profiles(router_id: int) -> bool:
    return get(router_id).supports_performance_profiles


def supports_rescue(router_id: int) -> bool:
    return get(router_id).supports_rescue


def requires_opticable_baseline(router_id: int) -> bool:
    return get(router_id).managed_baseline
