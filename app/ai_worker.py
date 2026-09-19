"""Persistent worker for read-only Codex router analysis.

This process is intentionally separate from the web server and Guardian timer.
It claims one queued analysis, gathers a sanitized snapshot through Tikcentral,
invokes the isolated Codex helper, stores the report, and exits.
"""

from datetime import datetime, timedelta, timezone

from app import ai_analysis, errors, events, jobs, main as core, migrations, settings


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _recover_stale():
    # A VPS/app restart must not leave a report permanently stuck as "running".
    seconds = max(1800, settings.AI_TIMEOUT + settings.AI_ROUTER_READ_TIMEOUT * 8 + 300)
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    with core.db() as conn:
        conn.execute(
            """UPDATE router_ai_analyses
               SET status='queued', started_at=NULL, error_code='', error_detail=''
               WHERE status='running' AND started_at IS NOT NULL AND started_at<?""",
            (cutoff,),
        )


def _claim_one():
    """Atomically claim one queued analysis whose router has no active change."""
    with core.db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT a.* FROM router_ai_analyses a
               JOIN routers r ON r.id=a.router_id
               WHERE a.status='queued' AND r.enabled=1
                 AND a.trigger_source='human_web'
                 AND NOT EXISTS (
                   SELECT 1 FROM router_jobs j
                   WHERE j.router_id=a.router_id
                     AND j.status IN ('queued','running','verifying')
                 )
               ORDER BY a.id
               LIMIT 1"""
        ).fetchone()
        if not row:
            return None
        started = _now()
        changed = conn.execute(
            "UPDATE router_ai_analyses SET status='running',started_at=? WHERE id=? AND status='queued'",
            (started, row["id"]),
        ).rowcount
        if changed != 1:
            return None
        return dict(row) | {"status": "running", "started_at": started}


def run_once() -> int:
    migrations.migrate()
    _recover_stale()
    job = _claim_one()
    if not job:
        return 0

    job_id = int(job["id"])
    router_id = int(job["router_id"])
    if job.get("trigger_source") != "human_web":
        return 0
    try:
        snapshot = ai_analysis.collect_snapshot(
            router_id,
            job.get("focus_start", ""),
            job.get("focus_end", ""),
            job.get("focus_note", ""),
        )
        report = ai_analysis.run_codex(snapshot)
        finished = _now()
        with core.db() as conn:
            conn.execute(
                """UPDATE router_ai_analyses
                   SET status='succeeded',finished_at=?,report=?,error_code='',error_detail=''
                   WHERE id=?""",
                (finished, report, job_id),
            )
        events.record(router_id, "ai", "AI router analysis completed", f"Analysis #{job_id} completed", "info")
        return 0
    except Exception as exc:
        err = errors.from_exception(exc, "AI_ANALYSIS_FAILED", "AI router analysis failed")
        detail = errors.short(err)[:4000]
        with core.db() as conn:
            conn.execute(
                """UPDATE router_ai_analyses
                   SET status='failed',finished_at=?,error_code=?,error_detail=?
                   WHERE id=?""",
                (_now(), err.code, detail, job_id),
            )
        try:
            events.record(router_id, "ai", "AI router analysis failed", f"{err.code}: {detail}", "warning")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(run_once())
