"""Typed router capability profiles.

Tikcentral-only routers must not be judged or modified as if they were generated
from the Opticable fresh-router baseline.
"""

from app import main as core
from app import migrations

TIKCENTRAL_ONLY = "tikcentral_only"
OPTICABLE_DEFAULT = "opticable_default"


def ensure_schema():
    migrations.migrate()


def get(router_id: int):
    ensure_schema()
    with core.db() as conn:
        return conn.execute("SELECT * FROM router_capabilities WHERE router_id=?", (router_id,)).fetchone()


def set_mode(router_id: int, mode: str, detected_at: str, source: str = "detected"):
    if mode not in {TIKCENTRAL_ONLY, OPTICABLE_DEFAULT}:
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


def mode(router_id: int) -> str:
    row = get(router_id)
    return row["mode"] if row else TIKCENTRAL_ONLY


def supports_profiles(router_id: int) -> bool:
    row = get(router_id)
    return bool(row and row["supports_performance_profiles"])
