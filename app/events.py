"""Shared event timeline for Tikcentral router operations."""

from datetime import datetime, timezone

from app import main as core
from app import migrations
from app import settings


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_schema():
    migrations.migrate()


def record(router_id, category: str, summary: str, details: str = "", severity: str = "info"):
    ensure_schema()
    summary = (summary or "")[:500]
    details = (details or "")[-4000:]
    severity = severity if severity in {"info", "warning", "critical"} else "info"

    # Routine successful telemetry belongs in router_telemetry, not the operator
    # timeline. Warnings/errors still surface here.
    if category == "telemetry" and severity == "info":
        return

    now = now_iso()
    with core.db() as conn:
        previous = conn.execute(
            "SELECT event_at,severity,summary,details FROM router_events WHERE router_id IS ? AND category=? ORDER BY id DESC LIMIT 1",
            (router_id, category),
        ).fetchone()
        if previous and previous["severity"] == severity and previous["summary"] == summary and previous["details"] == details:
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(previous["event_at"])).total_seconds()
            except Exception:
                age = 999999
            if age < settings.EVENT_DEDUP_SECONDS:
                return
        conn.execute(
            "INSERT INTO router_events(router_id,event_at,severity,category,summary,details) VALUES(?,?,?,?,?,?)",
            (router_id, now, severity, category, summary, details),
        )
        if router_id is not None:
            # Keep important events in the larger retention window.
            conn.execute(
                """DELETE FROM router_events WHERE router_id=? AND severity='info' AND id NOT IN
                   (SELECT id FROM router_events WHERE router_id=? AND severity='info' ORDER BY id DESC LIMIT ?)""",
                (router_id, router_id, settings.EVENT_INFO_RETENTION_ROWS),
            )
            conn.execute(
                """DELETE FROM router_events WHERE router_id=? AND id NOT IN
                   (SELECT id FROM router_events WHERE router_id=? ORDER BY id DESC LIMIT ?)""",
                (router_id, router_id, settings.EVENT_RETENTION_ROWS),
            )
        else:
            # Fleet/global events have no router_id but still need bounded
            # retention or cross-site/system events will grow forever.
            conn.execute(
                """DELETE FROM router_events WHERE router_id IS NULL AND severity='info' AND id NOT IN
                   (SELECT id FROM router_events WHERE router_id IS NULL AND severity='info' ORDER BY id DESC LIMIT ?)""",
                (settings.EVENT_INFO_RETENTION_ROWS,),
            )
            conn.execute(
                """DELETE FROM router_events WHERE router_id IS NULL AND id NOT IN
                   (SELECT id FROM router_events WHERE router_id IS NULL ORDER BY id DESC LIMIT ?)""",
                (settings.EVENT_RETENTION_ROWS,),
            )


def maintenance():
    """Best-effort timeline cleanup; safe to call from optional scheduler lane."""
    ensure_schema()
    with core.db() as conn:
        router_ids = [r[0] for r in conn.execute("SELECT DISTINCT router_id FROM router_events WHERE router_id IS NOT NULL")]
        for router_id in router_ids:
            conn.execute(
                """DELETE FROM router_events WHERE router_id=? AND severity='info' AND id NOT IN
                   (SELECT id FROM router_events WHERE router_id=? AND severity='info' ORDER BY id DESC LIMIT ?)""",
                (router_id, router_id, settings.EVENT_INFO_RETENTION_ROWS),
            )
            conn.execute(
                """DELETE FROM router_events WHERE router_id=? AND id NOT IN
                   (SELECT id FROM router_events WHERE router_id=? ORDER BY id DESC LIMIT ?)""",
                (router_id, router_id, settings.EVENT_RETENTION_ROWS),
            )
        conn.execute(
            """DELETE FROM router_events WHERE router_id IS NULL AND severity='info' AND id NOT IN
               (SELECT id FROM router_events WHERE router_id IS NULL AND severity='info' ORDER BY id DESC LIMIT ?)""",
            (settings.EVENT_INFO_RETENTION_ROWS,),
        )
        conn.execute(
            """DELETE FROM router_events WHERE router_id IS NULL AND id NOT IN
               (SELECT id FROM router_events WHERE router_id IS NULL ORDER BY id DESC LIMIT ?)""",
            (settings.EVENT_RETENTION_ROWS,),
        )


def recent(router_id: int, limit: int = 100):
    ensure_schema()
    with core.db() as conn:
        return conn.execute(
            "SELECT * FROM router_events WHERE router_id=? ORDER BY id DESC LIMIT ?",
            (router_id, max(1, min(limit, 500))),
        ).fetchall()
