"""Unified job state for Tikcentral router-changing operations.

Read-only telemetry, Guardian and drift probes are intentionally not inserted into
router_jobs. The table represents serialized changes that may alter router state.
"""

import json
from contextlib import contextmanager
from datetime import datetime, timezone

from app import errors
from app import main as core
from app import migrations

ACTIVE = {"queued", "running", "verifying"}
FINAL = {"succeeded", "failed"}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_schema():
    migrations.migrate()


def create(router_id: int | None, kind: str, actor: str = "system", target: str = "", payload=None, *, serialize_router: bool = False, serialize_global_kind: str = "") -> int:
    """Reserve a mutation job atomically.

    BEGIN IMMEDIATE makes the active-job check and INSERT one short SQLite write
    transaction. Without it, two simultaneous web requests could both observe
    "no active job" before either INSERT committed.
    """
    ensure_schema()
    with core.db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if serialize_router and router_id is not None:
            active = conn.execute(
                "SELECT id,kind FROM router_jobs WHERE router_id=? AND status IN ('queued','running','verifying') ORDER BY id LIMIT 1",
                (router_id,),
            ).fetchone()
            if active:
                raise errors.OperationError("ROUTER_BUSY", "Another change is already active on this router", f"job {active['id']} · {active['kind']}")
        if serialize_global_kind:
            active = conn.execute(
                "SELECT id,router_id FROM router_jobs WHERE kind LIKE ? AND status IN ('queued','running','verifying') ORDER BY id LIMIT 1",
                (serialize_global_kind + "%",),
            ).fetchone()
            if active:
                raise errors.OperationError("JOB_BUSY", "Another serialized job is already active", f"job {active['id']}")
        now = now_iso()
        cur = conn.execute(
            """INSERT INTO router_jobs(router_id,kind,status,actor,target,payload,created_at,updated_at)
               VALUES(?,?, 'queued',?,?,?,?,?)""",
            (router_id, kind, actor, target, json.dumps(payload or {}), now, now),
        )
        return cur.lastrowid


def transition(job_id: int, status: str, *, error: errors.OperationError | None = None):
    if status not in ACTIVE | FINAL:
        raise ValueError("invalid job status")
    now = now_iso()
    with core.db() as conn:
        row = conn.execute("SELECT status FROM router_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise KeyError("job not found")
        current = row["status"]
        allowed = {
            "queued": {"running", "failed"},
            "running": {"verifying", "succeeded", "failed"},
            "verifying": {"succeeded", "failed"},
            "succeeded": set(),
            "failed": set(),
        }
        if status != current and status not in allowed.get(current, set()):
            raise errors.OperationError("INVALID_JOB_TRANSITION", "Invalid job state transition", f"{current} -> {status}")
        if status == current:
            return
        started = now if status == "running" and current == "queued" else None
        finished = now if status in FINAL else None
        conn.execute(
            """UPDATE router_jobs SET status=?,updated_at=?,
               started_at=CASE WHEN ?<>'' THEN ? ELSE started_at END,
               finished_at=CASE WHEN ?<>'' THEN ? ELSE finished_at END,
               error_code=?,error_message=? WHERE id=?""",
            (status, now, started or "", started or "", finished or "", finished or "",
             error.code if error else "", (error.message + (" — " + error.detail if error and error.detail else "")) if error else "", job_id),
        )


def running(job_id: int):
    transition(job_id, "running")


def verifying(job_id: int):
    transition(job_id, "verifying")


def succeeded(job_id: int):
    transition(job_id, "succeeded")


def failed(job_id: int, exc: Exception, *, code: str = "OPERATION_FAILED", message: str = "Operation failed"):
    transition(job_id, "failed", error=errors.from_exception(exc, code, message))


@contextmanager
def operation(router_id: int | None, kind: str, actor: str = "system", target: str = "", payload=None, *, serialize_router: bool = True, serialize_global_kind: str = "", fail_code: str = "OPERATION_FAILED", fail_message: str = "Operation failed"):
    """Create/run/fail a serialized mutation with one consistent lifecycle."""
    job_id = create(
        router_id,
        kind,
        actor,
        target,
        payload,
        serialize_router=serialize_router,
        serialize_global_kind=serialize_global_kind,
    )
    running(job_id)
    try:
        yield job_id
    except Exception as exc:
        try:
            failed(job_id, exc, code=fail_code, message=fail_message)
        finally:
            raise
    else:
        row = get(job_id)
        if row and row["status"] in {"running", "verifying"}:
            succeeded(job_id)


def get(job_id: int):
    ensure_schema()
    with core.db() as conn:
        return conn.execute("SELECT * FROM router_jobs WHERE id=?", (job_id,)).fetchone()


def latest(router_id: int, limit: int = 20):
    ensure_schema()
    with core.db() as conn:
        return conn.execute(
            "SELECT * FROM router_jobs WHERE router_id=? ORDER BY id DESC LIMIT ?",
            (router_id, max(1, min(limit, 100))),
        ).fetchall()


def active_for_router(router_id: int):
    ensure_schema()
    with core.db() as conn:
        return conn.execute(
            "SELECT * FROM router_jobs WHERE router_id=? AND status IN ('queued','running','verifying') ORDER BY id LIMIT 1",
            (router_id,),
        ).fetchone()


def active_change_router_ids() -> set[int]:
    """Routers that read-only fleet work should leave alone for this tick."""
    ensure_schema()
    with core.db() as conn:
        rows = conn.execute(
            "SELECT DISTINCT router_id FROM router_jobs WHERE router_id IS NOT NULL AND status IN ('queued','running','verifying')"
        ).fetchall()
    return {int(r[0]) for r in rows}


def router_has_active_change(router_id: int) -> bool:
    return active_for_router(router_id) is not None


def next_queued(kind_prefix: str = ""):
    ensure_schema()
    with core.db() as conn:
        if kind_prefix:
            return conn.execute(
                "SELECT * FROM router_jobs WHERE status='queued' AND kind LIKE ? ORDER BY id LIMIT 1",
                (kind_prefix + "%",),
            ).fetchone()
        return conn.execute("SELECT * FROM router_jobs WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
