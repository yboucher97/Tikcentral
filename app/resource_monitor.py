"""Router resource anomaly and reboot monitoring from retained telemetry."""

import re
from datetime import datetime, timedelta, timezone

from app import events, main as core, migrations, settings


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def _memory_bytes(value: str):
    value = (value or "").strip().lower().replace(" ", "")
    m = re.fullmatch(r"([0-9.]+)([kmgt]?i?b?)?", value)
    if not m:
        return None
    number = float(m.group(1))
    unit = m.group(2) or ""
    factors = {
        "": 1, "b": 1,
        "k": 1000, "kb": 1000, "kib": 1024,
        "m": 1000**2, "mb": 1000**2, "mib": 1024**2,
        "g": 1000**3, "gb": 1000**3, "gib": 1024**3,
        "t": 1000**4, "tb": 1000**4, "tib": 1024**4,
    }
    return int(number * factors.get(unit, 1))


def _uptime_seconds(value: str):
    text = (value or "").strip().lower()
    if not text:
        return None
    total = 0
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    for number, unit in re.findall(r"(\d+)(w|d|h|m|s)", text):
        total += int(number) * units[unit]
    return total if total or text in {"0s","0"} else None


def _set_alert(router_id: int, metric: str, active: bool, value: str, severity: str, summary: str):
    migrations.migrate()
    now = now_iso()
    with core.db() as conn:
        row = conn.execute(
            "SELECT active FROM router_resource_alerts WHERE router_id=? AND metric=?",
            (router_id, metric),
        ).fetchone()
        was_active = bool(row["active"]) if row else False
        conn.execute(
            """INSERT INTO router_resource_alerts
               (router_id,metric,active,first_seen_at,last_seen_at,last_value)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(router_id,metric) DO UPDATE SET
                 active=excluded.active,
                 first_seen_at=CASE WHEN router_resource_alerts.active=0 AND excluded.active=1 THEN excluded.first_seen_at ELSE router_resource_alerts.first_seen_at END,
                 last_seen_at=excluded.last_seen_at,last_value=excluded.last_value""",
            (router_id, metric, int(active), now if active else "", now, value),
        )
    if active and not was_active:
        events.record(router_id, "resource", summary, value, severity)
    elif not active and was_active:
        events.record(router_id, "resource", f"{metric.replace('_',' ').title()} returned to normal", value, "info")


def evaluate(router_id: int, current, previous=None):
    if current is None:
        return
    cpu = int(current["cpu_load"] or 0)
    if cpu >= settings.RESOURCE_CPU_CRITICAL:
        _set_alert(router_id, "cpu", True, f"{cpu}%", "critical", f"CPU load critical at {cpu}%")
    elif cpu >= settings.RESOURCE_CPU_WARN:
        _set_alert(router_id, "cpu", True, f"{cpu}%", "warning", f"CPU load high at {cpu}%")
    else:
        _set_alert(router_id, "cpu", False, f"{cpu}%", "info", "")

    free_b = _memory_bytes(current["free_memory"])
    total_b = _memory_bytes(current["total_memory"])
    if free_b is not None and total_b and total_b > 0:
        pct = free_b * 100 / total_b
        if pct <= settings.RESOURCE_MEMORY_CRITICAL_PERCENT:
            _set_alert(router_id, "memory", True, f"{pct:.1f}% free", "critical", f"Free memory critical at {pct:.1f}%")
        elif pct <= settings.RESOURCE_MEMORY_WARN_PERCENT:
            _set_alert(router_id, "memory", True, f"{pct:.1f}% free", "warning", f"Free memory low at {pct:.1f}%")
        else:
            _set_alert(router_id, "memory", False, f"{pct:.1f}% free", "info", "")

    if previous is not None:
        old_up = _uptime_seconds(previous["uptime"])
        new_up = _uptime_seconds(current["uptime"])
        if old_up is not None and new_up is not None and new_up + 60 < old_up:
            _record_reboot(router_id, previous, current, new_up)


def _record_reboot(router_id: int, previous, current, new_uptime_seconds: int):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=settings.RESOURCE_REBOOT_CORRELATION_MINUTES)).isoformat()
    with core.db() as conn:
        job = conn.execute(
            """SELECT id,kind,actor,status,created_at,finished_at FROM router_jobs
               WHERE router_id=? AND created_at>=?
                 AND (kind LIKE 'upgrade%' OR kind LIKE 'routerboot%' OR kind='web_ssh')
               ORDER BY id DESC LIMIT 1""",
            (router_id, cutoff),
        ).fetchone()
    if job and (job["kind"].startswith("upgrade") or job["kind"].startswith("routerboot")):
        attribution = f"Tikcentral job #{job['id']} · {job['kind']} · actor {job['actor'] or '-'}"
        severity = "info"
        summary = "Router reboot detected and attributed to Tikcentral"
    elif job and job["kind"] == "web_ssh":
        attribution = f"Recent manual Web SSH job #{job['id']} by {job['actor'] or '-'} may be related"
        severity = "warning"
        summary = "Router reboot detected near a manual Tikcentral SSH action"
    else:
        attribution = "No matching Tikcentral reboot/upgrade transaction found in the correlation window"
        severity = "warning"
        summary = "Unexpected router reboot detected"
    details = (
        f"uptime_before={previous['uptime']}; uptime_after={current['uptime']}; "
        f"estimated_seconds_since_reboot={new_uptime_seconds}; attribution={attribution}"
    )
    events.record(router_id, "reboot", summary, details, severity)
