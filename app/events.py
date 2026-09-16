"""Shared event timeline for Tikcentral router operations."""

from datetime import datetime, timezone

from app import main as core

SCHEMA = """
CREATE TABLE IF NOT EXISTS router_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    router_id INTEGER,
    event_at TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    category TEXT NOT NULL DEFAULT 'system',
    summary TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_router_events_router_time
    ON router_events(router_id, event_at DESC);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_schema():
    with core.db() as conn:
        conn.executescript(SCHEMA)


def record(router_id, category: str, summary: str, details: str = "", severity: str = "info"):
    ensure_schema()
    with core.db() as conn:
        conn.execute(
            "INSERT INTO router_events(router_id,event_at,severity,category,summary,details) VALUES(?,?,?,?,?,?)",
            (router_id, now_iso(), severity, category, summary[:500], details[-10000:]),
        )


def recent(router_id: int, limit: int = 100):
    ensure_schema()
    with core.db() as conn:
        return conn.execute(
            "SELECT * FROM router_events WHERE router_id=? ORDER BY id DESC LIMIT ?",
            (router_id, max(1, min(limit, 500))),
        ).fetchall()
