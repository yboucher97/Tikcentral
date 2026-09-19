"""Tikcentral SQLite/database growth and filesystem runway monitoring."""

import html
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import events, main as core, migrations, settings


SAMPLE_MINUTES=60
FORECAST_WINDOW_DAYS=14


def _now(): return datetime.now(timezone.utc)


def _size(path):
    try:return os.path.getsize(path)
    except OSError:return 0


def _human(value):
    value=float(value or 0)
    for unit in ("B","KB","MB","GB","TB"):
        if value<1024 or unit=="TB": return f"{value:.1f} {unit}"
        value/=1024
    return f"{value:.1f} TB"


def collect(force=False, persist=True):
    migrations.migrate()
    now=_now()
    db_path=Path(settings.DB_PATH)
    db_bytes=_size(str(db_path))
    wal_bytes=_size(str(db_path)+"-wal")
    shm_bytes=_size(str(db_path)+"-shm")
    total_sqlite=db_bytes+wal_bytes+shm_bytes
    try:
        st=os.statvfs(str(db_path.parent))
        fs_total=int(st.f_frsize*st.f_blocks)
        fs_free=int(st.f_frsize*st.f_bavail)
    except Exception:
        fs_total=fs_free=0

    cutoff=(now-timedelta(days=FORECAST_WINDOW_DAYS)).isoformat()
    with core.db() as conn:
        last=conn.execute("SELECT * FROM database_health_history ORDER BY id DESC LIMIT 1").fetchone()
        if last and not force:
            try:
                age=(now-datetime.fromisoformat(last["checked_at"])).total_seconds()
                if age<SAMPLE_MINUTES*60:return dict(last)
            except Exception: pass
        old=conn.execute(
            "SELECT * FROM database_health_history WHERE checked_at>=? ORDER BY id ASC LIMIT 1",(cutoff,)
        ).fetchone()

    growth=None
    if old:
        try:
            days=(now-datetime.fromisoformat(old["checked_at"])).total_seconds()/86400
            if days>=0.25:
                growth=max(0.0,(total_sqlite-float(old["total_sqlite_bytes"]))/days)
        except Exception: growth=None

    used=max(0,fs_total-fs_free) if fs_total else 0
    days_to_80=None
    if fs_total and growth and growth>0:
        target=fs_total*0.80
        remaining=max(0,target-used)
        days_to_80=remaining/growth

    free_pct=(fs_free*100/fs_total) if fs_total else None
    if free_pct is not None and (free_pct<=10 or (days_to_80 is not None and days_to_80<=7)):
        status="critical"
    elif free_pct is not None and (free_pct<=20 or (days_to_80 is not None and days_to_80<=30)):
        status="warning"
    else:
        status="ok" if fs_total else "unknown"

    summary=f"SQLite {_human(total_sqlite)}"
    if fs_total:
        summary+=f" · filesystem free {free_pct:.1f}%"
    if growth is not None:
        summary+=f" · growth {_human(growth)}/day"
    if days_to_80 is not None:
        summary+=f" · ~{days_to_80:.0f} days to 80% filesystem use"

    previous=None
    if persist:
        with core.db() as conn:
            previous=conn.execute("SELECT status FROM database_health_history ORDER BY id DESC LIMIT 1").fetchone()
            conn.execute(
                """INSERT INTO database_health_history
                   (checked_at,db_bytes,wal_bytes,shm_bytes,total_sqlite_bytes,filesystem_total_bytes,filesystem_free_bytes,
                    growth_bytes_per_day,estimated_days_to_80_percent,status,summary)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (now.isoformat(),db_bytes,wal_bytes,shm_bytes,total_sqlite,fs_total,fs_free,growth,days_to_80,status,summary),
            )
            conn.execute(
                """DELETE FROM database_health_history WHERE id NOT IN
                   (SELECT id FROM database_health_history ORDER BY id DESC LIMIT 2160)"""
            )
        if previous and previous["status"]!=status:
            events.record(None,"database-health",f"Database/storage health: {previous['status']} → {status}",summary,
                          "critical" if status=="critical" else ("warning" if status=="warning" else "info"))
    return {
        "checked_at":now.isoformat(),"db_bytes":db_bytes,"wal_bytes":wal_bytes,"shm_bytes":shm_bytes,
        "total_sqlite_bytes":total_sqlite,"filesystem_total_bytes":fs_total,"filesystem_free_bytes":fs_free,
        "growth_bytes_per_day":growth,"estimated_days_to_80_percent":days_to_80,"status":status,"summary":summary,
    }


def register(app,page_func):
    migrations.migrate()

    @app.get("/database-health",response_class=HTMLResponse)
    def page(request:Request):
        user=core.require_web_admin(request)
        if not user:return RedirectResponse("/login",303)
        current=collect(force=True,persist=False)
        with core.db() as conn:
            rows=conn.execute("SELECT * FROM database_health_history ORDER BY id DESC LIMIT 168").fetchall()
            page_count=conn.execute("PRAGMA page_count").fetchone()[0]
            page_size=conn.execute("PRAGMA page_size").fetchone()[0]
            freelist=conn.execute("PRAGMA freelist_count").fetchone()[0]
        history_parts=[]
        for x in rows:
            runway=f'{x["estimated_days_to_80_percent"]:.0f}' if x["estimated_days_to_80_percent"] is not None else "—"
            growth=_human(x["growth_bytes_per_day"]) if x["growth_bytes_per_day"] is not None else "—"
            history_parts.append(
                f'<tr><td>{html.escape(x["checked_at"])}</td><td>{html.escape(x["status"])}</td><td>{_human(x["total_sqlite_bytes"])}</td>'
                f'<td>{growth}</td><td>{runway}</td><td>{_human(x["filesystem_free_bytes"])}</td></tr>'
            )
        history="".join(history_parts) or '<tr><td colspan="6">No history.</td></tr>'
        current_runway=f'{current["estimated_days_to_80_percent"]:.0f}' if current["estimated_days_to_80_percent"] is not None else "—"
        current_growth=_human(current["growth_bytes_per_day"]) if current["growth_bytes_per_day"] is not None else "—"
        body=f'''<div class="panel pad"><h2>Database / storage health</h2>
<div><strong>{html.escape(current["status"])}</strong> · {html.escape(current["summary"])}</div>
<div class="muted">Standard thresholds: warning at ≤20% filesystem free or ≤30 forecast days to 80% use; critical at ≤10% free or ≤7 days.</div></div>
<div class="cards">
<div class="card"><h3>SQLite DB</h3><div class="value">{_human(current["db_bytes"])}</div></div>
<div class="card"><h3>WAL</h3><div class="value">{_human(current["wal_bytes"])}</div></div>
<div class="card"><h3>Total SQLite files</h3><div class="value">{_human(current["total_sqlite_bytes"])}</div></div>
<div class="card"><h3>Growth/day</h3><div class="value">{current_growth}</div></div>
<div class="card"><h3>Days to 80%</h3><div class="value">{current_runway}</div></div>
<div class="card"><h3>Filesystem free</h3><div class="value">{_human(current["filesystem_free_bytes"])}</div></div>
</div>
<div class="panel pad"><h3>SQLite internals</h3><div>Pages: {page_count} · page size: {_human(page_size)} · freelist pages: {freelist} · approximate freelist space: {_human(freelist*page_size)}</div></div>
<div class="panel"><div class="pad"><h3>Recent samples</h3></div><table><thead><tr><th>Time</th><th>Status</th><th>SQLite</th><th>Growth/day</th><th>Days to 80%</th><th>FS free</th></tr></thead><tbody>{history}</tbody></table></div>'''
        return page_func("Database Health",body,user,"database-health")
