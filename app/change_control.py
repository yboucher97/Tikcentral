"""Shared safety framework for router-changing operations.

Every access-sensitive mutation can record a transaction transcript, enforce a
healthy Guardian preflight and verify management access after the change.
Recovery operations may explicitly opt out of the healthy preflight.
"""

import json
from datetime import datetime, timezone

from app import errors, main as core, migrations


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def active_maintenance(router_id: int):
    migrations.migrate()
    now = now_iso()
    with core.db() as conn:
        return conn.execute(
            """SELECT * FROM router_maintenance
               WHERE router_id=? AND start_at<=? AND end_at>?""",
            (router_id, now, now),
        ).fetchone()


def begin(router_id: int, kind: str, actor: str, *, job_id: int | None = None, pre_access: dict | None = None) -> int:
    migrations.migrate()
    now = now_iso()
    with core.db() as conn:
        cur = conn.execute(
            """INSERT INTO change_transactions
               (router_id,job_id,kind,actor,status,created_at,pre_access)
               VALUES(?,?,?,?, 'running', ?, ?)""",
            (router_id, job_id, kind, actor, now, json.dumps(pre_access or {}, sort_keys=True)),
        )
        tx = int(cur.lastrowid)
    step(tx, "preflight", "ok", "Transaction started")
    return tx


def attach_job(transaction_id: int, job_id: int):
    with core.db() as conn:
        conn.execute(
            "UPDATE change_transactions SET job_id=? WHERE id=? AND status='running'",
            (job_id, transaction_id),
        )


def step(transaction_id: int, phase: str, status: str, message: str, details: str = ""):
    migrations.migrate()
    status = status if status in {"ok", "warning", "failed", "info"} else "info"
    with core.db() as conn:
        conn.execute(
            """INSERT INTO change_transaction_steps
               (transaction_id,step_at,phase,status,message,details)
               VALUES(?,?,?,?,?,?)""",
            (transaction_id, now_iso(), phase[:80], status, message[:500], (details or "")[-4000:]),
        )


def finish(transaction_id: int, *, post_access: dict | None = None):
    with core.db() as conn:
        conn.execute(
            """UPDATE change_transactions
               SET status='succeeded',finished_at=?,post_access=?
               WHERE id=? AND status='running'""",
            (now_iso(), json.dumps(post_access or {}, sort_keys=True), transaction_id),
        )
    step(transaction_id, "complete", "ok", "Transaction committed")


def fail(transaction_id: int, exc: Exception, *, post_access: dict | None = None):
    err = errors.from_exception(exc)
    with core.db() as conn:
        conn.execute(
            """UPDATE change_transactions
               SET status='failed',finished_at=?,post_access=?,error_code=?,error_detail=?
               WHERE id=? AND status='running'""",
            (now_iso(), json.dumps(post_access or {}, sort_keys=True), err.code, err.detail or err.message, transaction_id),
        )
    step(transaction_id, "complete", "failed", err.message, err.detail)


def require_management(router, operation: str, *, allow_degraded: bool = False):
    """Require full Guardian access before an ordinary router mutation."""
    from app import guardian

    result = guardian.probe_router(router)
    if not result["management_ok"] and not allow_degraded:
        raise errors.OperationError(
            "GUARDIAN_UNHEALTHY",
            f"{operation} blocked because management access is degraded",
            guardian.access_issue(result),
            severity="critical",
        )
    return result


def verify_management(router, operation: str, *, transaction_id: int | None = None, auto_repair: bool = True):
    """Verify access after a mutation and, when safe, repair Tikcentral-owned access.

    Recovery is attempted only when WireGuard and SSH are still reachable. This
    never restores a full customer configuration; it only reconciles the
    canonical Tikcentral management objects so a normal change cannot silently
    strand remote access.
    """
    from app import guardian, management_script, router_exec, settings

    result = guardian.probe_router(router)
    if result["management_ok"]:
        if transaction_id is not None:
            step(transaction_id, "verify", "ok", "Management access verified",
                 json.dumps(result, sort_keys=True))
        return result

    issue = guardian.access_issue(result)
    if transaction_id is not None:
        step(transaction_id, "verify", "failed", "Management verification failed", issue)

    if auto_repair and result["wg_online"] and result["ssh_open"]:
        if transaction_id is not None:
            step(transaction_id, "recovery", "warning",
                 "Attempting canonical Tikcentral access recovery", issue)
        try:
            output = router_exec.mutate(
                router["vpn_ip"],
                management_script.access_repair_command(),
                timeout=settings.MUTATION_TIMEOUT,
                label=f"{operation} access recovery",
            )
            recovered = guardian.probe_router(router)
            if transaction_id is not None:
                step(
                    transaction_id,
                    "recovery",
                    "ok" if recovered["management_ok"] else "failed",
                    "Canonical access recovery applied",
                    router_exec.sanitize(output, 2000) or guardian.access_issue(recovered),
                )
            if recovered["management_ok"]:
                return recovered
            result = recovered
            issue = guardian.access_issue(recovered)
        except Exception as exc:
            if transaction_id is not None:
                step(transaction_id, "recovery", "failed",
                     "Canonical access recovery failed", errors.short(exc))

    raise errors.OperationError(
        "ACCESS_VERIFY_FAILED",
        f"{operation} completed but management verification failed",
        issue,
        severity="critical",
    )


def latest(router_id: int, limit: int = 20):
    migrations.migrate()
    with core.db() as conn:
        return conn.execute(
            """SELECT * FROM change_transactions
               WHERE router_id=? ORDER BY id DESC LIMIT ?""",
            (router_id, max(1, min(limit, 100))),
        ).fetchall()


def steps(transaction_id: int):
    migrations.migrate()
    with core.db() as conn:
        return conn.execute(
            "SELECT * FROM change_transaction_steps WHERE transaction_id=? ORDER BY id",
            (transaction_id,),
        ).fetchall()
