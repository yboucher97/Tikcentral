"""Record Access Guardian state transitions in the shared event timeline."""

from app import events
from app import guardian
from app import main as core

_original_tick = guardian.guardian_tick
_installed = False


def _tick_with_events():
    events.ensure_schema()
    with core.db() as conn:
        previous = {
            row["router_id"]: (bool(row["management_ok"]), row["last_error"] or "")
            for row in conn.execute("SELECT router_id,management_ok,last_error FROM router_access_state").fetchall()
        }
    results = _original_tick()
    with core.db() as conn:
        current = conn.execute(
            "SELECT router_id,management_ok,last_error FROM router_access_state"
        ).fetchall()
    for row in current:
        rid = row["router_id"]
        before = previous.get(rid)
        now_ok = bool(row["management_ok"])
        error = row["last_error"] or ""
        if before is None:
            events.record(rid, "access", "Guardian baseline: healthy" if now_ok else "Guardian baseline: degraded", error, "info" if now_ok else "warning")
        elif before[0] != now_ok:
            events.record(rid, "access", "Management access restored" if now_ok else "Management access degraded", error, "info" if now_ok else "critical")
        elif not now_ok and before[1] != error:
            events.record(rid, "access", "Management access issue changed", error, "warning")
    return results


def install():
    global _installed
    if _installed:
        return
    guardian.guardian_tick = _tick_with_events
    _installed = True


install()
