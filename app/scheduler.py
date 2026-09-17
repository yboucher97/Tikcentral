"""Tikcentral scheduler orchestration.

Change jobs and read-only probes deliberately use separate lanes. A router with
an active mutation is skipped by telemetry/drift for that scheduler tick so
background reads cannot contend with change verification or reboot recovery.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from app import errors, events, jobs, main as core, operations, settings


def _eligible_healthy_router_ids() -> list[int]:
    busy = jobs.active_change_router_ids()
    with core.db() as conn:
        rows = conn.execute(
            """SELECT r.id FROM routers r
               JOIN router_access_state a ON a.router_id=r.id
               WHERE r.enabled=1 AND a.management_ok=1
               ORDER BY r.id"""
        ).fetchall()
    return [int(r["id"]) for r in rows if int(r["id"]) not in busy]


def _run_parallel(ids: list[int], fn, *, workers: int, category: str, failure_summary: str):
    if not ids:
        return
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ids)))) as pool:
        futures = {pool.submit(fn, rid): rid for rid in ids}
        for fut in as_completed(futures):
            router_id = futures[fut]
            try:
                fut.result()
            except Exception as exc:
                err = errors.from_exception(exc)
                events.record(router_id, category, failure_summary, errors.short(err), err.severity)


def scheduled_tick():
    operations.ensure_schema()
    operations._process_upgrade_job()

    with core.db() as conn:
        state = conn.execute("SELECT * FROM operations_settings WHERE id=1").fetchone()

    now = operations.now_iso()
    eligible = _eligible_healthy_router_ids()

    if operations._seconds_since(state["last_telemetry_at"]) >= int(state["telemetry_interval_seconds"]):
        _run_parallel(
            eligible,
            lambda rid: operations.collect_telemetry(rid, False),
            workers=settings.TELEMETRY_WORKERS,
            category="telemetry",
            failure_summary="Telemetry collection failed",
        )
        with core.db() as conn:
            conn.execute("UPDATE operations_settings SET last_telemetry_at=? WHERE id=1", (now,))

    if operations._seconds_since(state["last_drift_at"]) >= int(state["drift_interval_seconds"]):
        busy = jobs.active_change_router_ids()
        with core.db() as conn:
            rows = conn.execute(
                """SELECT e.router_id FROM router_expected_state e
                   JOIN router_access_state a ON a.router_id=e.router_id
                   JOIN routers r ON r.id=e.router_id
                   WHERE e.baseline_sha256<>'' AND a.management_ok=1 AND r.enabled=1
                   ORDER BY e.router_id"""
            ).fetchall()
        drift_ids = [int(r["router_id"]) for r in rows if int(r["router_id"]) not in busy]
        _run_parallel(
            drift_ids,
            operations.check_drift,
            workers=settings.DRIFT_WORKERS,
            category="drift",
            failure_summary="Drift check failed",
        )
        with core.db() as conn:
            conn.execute("UPDATE operations_settings SET last_drift_at=? WHERE id=1", (now,))
