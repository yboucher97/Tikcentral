"""Tikcentral scheduler orchestration.

Change jobs and read-only probes deliberately use separate lanes. Optional
subsystems are fault-isolated: none can stop Guardian/access from running on the
next timer tick.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from app import alert_queue, automation_inventory, capacity_forecast, certificate_monitor, commissioning_checklist, compliance, database_health, desired_state, errors, events, fleet_health, interface_monitor, ip_enrichment, jobs, lte_monitor, main as core, maintenance_automation, mtu_diagnostics, operations, outage_classifier, retention_policy, security_audit, settings, state_capture, system_health, time_health, topology, traffic_monitor, upgrade_campaigns, wan_probe


def _eligible_healthy_router_ids() -> list[int]:
    busy = jobs.active_change_router_ids()
    with core.db() as conn:
        rows = conn.execute(
            """SELECT r.id FROM routers r
               JOIN router_access_state a ON a.router_id=r.id
               WHERE r.enabled=1 AND a.management_ok=1 AND COALESCE(r.lifecycle_state,'production')<>'retired'
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
                try:
                    events.record(router_id, category, failure_summary, errors.short(err), err.severity)
                except Exception:
                    pass


def _optional(name: str, fn):
    try:
        return fn()
    except Exception as exc:
        err = errors.from_exception(exc, "OPTIONAL_SUBSYSTEM_FAILED", f"Optional subsystem {name} failed")
        try:
            events.record(None, "system", f"Optional subsystem failed: {name}", errors.short(err), "warning")
        except Exception:
            pass
        return None


def _change_lane():
    # Process at most the currently active serialized upgrade job. Other router
    # mutations are initiated explicitly through the web/API job engine.
    return operations._process_upgrade_job()


def _collect_router_observability(router_id: int):
    """Collect optional router state without allowing one probe family to hide another."""
    result = {"telemetry": None, "wan": None, "known_good": None, "compliance": None, "lte": None, "interfaces": None, "certificates": None, "security": None, "automation": None, "traffic": None, "topology": None, "wan_probe": None, "desired_state": None, "time_health": None, "mtu": None, "errors": []}
    for key, fn in (
        ("telemetry", lambda: operations.collect_telemetry(router_id, False)),
        ("wan", lambda: state_capture.collect_wan_state(router_id)),
        ("known_good", lambda: state_capture.refresh_known_good_if_due(router_id)),
        ("compliance", lambda: compliance.evaluate(router_id)),
        ("lte", lambda: lte_monitor.collect(router_id)),
        ("interfaces", lambda: interface_monitor.collect(router_id)),
        ("certificates", lambda: certificate_monitor.collect(router_id)),
        ("security", lambda: security_audit.collect(router_id)),
        ("automation", lambda: automation_inventory.collect(router_id)),
        ("traffic", lambda: traffic_monitor.collect(router_id)),
        ("topology", lambda: topology.collect(router_id)),
        ("wan_probe", lambda: wan_probe.collect(router_id)),
        ("desired_state", lambda: desired_state.check(router_id)),
        ("time_health", lambda: time_health.collect(router_id)),
        ("mtu", lambda: mtu_diagnostics.collect(router_id)),
    ):
        try:
            result[key] = fn()
        except Exception as exc:
            result["errors"].append(f"{key}: {errors.short(exc)}")
    try:
        result["capacity"] = capacity_forecast.assess(router_id)
    except Exception as exc:
        result["errors"].append(f"capacity: {errors.short(exc)}")
    if result["errors"]:
        events.record(
            router_id,
            "observability",
            "Optional router observability partially failed",
            "; ".join(result["errors"]),
            "warning",
        )
    return result


def _telemetry_lane(state, now):
    if operations._seconds_since(state["last_telemetry_at"]) < int(state["telemetry_interval_seconds"]):
        return
    eligible = _eligible_healthy_router_ids()
    _run_parallel(
        eligible,
        _collect_router_observability,
        workers=settings.TELEMETRY_WORKERS,
        category="telemetry",
        failure_summary="Telemetry collection failed",
    )
    with core.db() as conn:
        conn.execute("UPDATE operations_settings SET last_telemetry_at=? WHERE id=1", (now,))


def _drift_lane(state, now):
    if operations._seconds_since(state["last_drift_at"]) < int(state["drift_interval_seconds"]):
        return
    busy = jobs.active_change_router_ids()
    with core.db() as conn:
        rows = conn.execute(
            """SELECT e.router_id FROM router_expected_state e
               JOIN router_access_state a ON a.router_id=e.router_id
               JOIN routers r ON r.id=e.router_id
               WHERE e.baseline_sha256<>'' AND a.management_ok=1 AND r.enabled=1
                 AND COALESCE(r.lifecycle_state,'production')<>'retired'
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


def scheduled_tick():
    operations.ensure_schema()
    with core.db() as conn:
        state = conn.execute("SELECT * FROM operations_settings WHERE id=1").fetchone()
    now = operations.now_iso()

    _optional("change_jobs", _change_lane)
    _optional("upgrade_campaign_status", upgrade_campaigns.sync_all)
    _optional("maintenance_automation", maintenance_automation.process)
    _optional("alert_queue_sync", alert_queue.sync)
    _optional("telemetry", lambda: _telemetry_lane(state, now))
    _optional("drift", lambda: _drift_lane(state, now))
    _optional("public_ip_enrichment", ip_enrichment.refresh_all)
    _optional("outage_classification", outage_classifier.assess_all)
    _optional("fleet_health", fleet_health.counts)
    _optional("database_health", database_health.collect)
    _optional("retention_cleanup", retention_policy.cleanup)
    _optional("commissioning_checklist", commissioning_checklist.evaluate_candidates)
    _optional("system_health", system_health.scheduled_tick)
    _optional("event_maintenance", events.maintenance)
