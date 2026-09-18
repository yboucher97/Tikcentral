"""Meaningful fleet attention summary for the main dashboard."""

import html
import json
from datetime import datetime, timedelta, timezone

from app import main as core, migrations, settings


def render() -> str:
    migrations.migrate()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with core.db() as conn:
        stale = conn.execute(
            """SELECT r.id,r.site_name,
              (SELECT created_at FROM router_backup_records b WHERE b.router_id=r.id ORDER BY b.id DESC LIMIT 1) last_backup
              FROM routers r WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired'"""
        ).fetchall()
        degraded = conn.execute(
            """SELECT r.id,r.site_name,a.last_error FROM routers r
               LEFT JOIN router_access_state a ON a.router_id=r.id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance') AND (a.management_ok IS NULL OR a.management_ok=0)"""
        ).fetchall()
        drift = conn.execute(
            """SELECT r.id,r.site_name FROM routers r JOIN router_expected_state e ON e.router_id=r.id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired' AND e.drifted=1"""
        ).fetchall()
        alerts = conn.execute(
            """SELECT r.id,r.site_name,x.metric,x.last_value FROM router_resource_alerts x
               JOIN routers r ON r.id=x.router_id WHERE x.active=1 ORDER BY x.last_seen_at DESC LIMIT 25"""
        ).fetchall()
        reboots = conn.execute(
            """SELECT r.id,r.site_name,e.event_at,e.summary FROM router_events e
               JOIN routers r ON r.id=e.router_id WHERE e.category='reboot' AND e.event_at>=?
               ORDER BY e.id DESC LIMIT 20""", (cutoff,)
        ).fetchall()
        failed = conn.execute(
            """SELECT r.id,r.site_name,t.id tx_id,t.kind,t.finished_at,t.error_code
               FROM change_transactions t JOIN routers r ON r.id=t.router_id
               WHERE t.status='failed' AND (t.finished_at='' OR t.finished_at>=?)
               ORDER BY t.id DESC LIMIT 20""", (cutoff,)
        ).fetchall()
        flaps = conn.execute(
            """SELECT r.id,r.site_name,s.last_flap_count FROM router_access_alert_state s
               JOIN routers r ON r.id=s.router_id WHERE s.last_flap_count>=?
               ORDER BY s.last_flap_count DESC LIMIT 20""", (settings.GUARDIAN_FLAP_THRESHOLD,)
        ).fetchall()
        compliance = conn.execute(
            """SELECT r.id,r.site_name,c.status,c.passed,c.warnings,c.failed
               FROM router_policy_compliance c JOIN routers r ON r.id=c.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired' AND c.status<>'pass'
               ORDER BY c.failed DESC,c.warnings DESC LIMIT 30"""
        ).fetchall()
        outages = conn.execute(
            """SELECT r.id,r.site_name,o.classification,o.confidence,o.summary
               FROM router_outage_assessment o JOIN routers r ON r.id=o.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance') AND o.classification<>'healthy'
               ORDER BY o.assessed_at DESC LIMIT 30"""
        ).fetchall()
        sys = conn.execute("SELECT checked_at,overall_status,checks_json FROM system_health_history ORDER BY id DESC LIMIT 1").fetchone()

    items = []
    now = datetime.now(timezone.utc)
    for r in stale:
        old = True
        if r["last_backup"]:
            try:
                old = (now - datetime.fromisoformat(r["last_backup"])).total_seconds() > 2 * 86400
            except Exception:
                old = True
        if old:
            items.append(("warning", r["site_name"], "Backup stale or never taken", f'/operations/{r["id"]}'))
    for r in degraded:
        items.append(("critical", r["site_name"], "Management access degraded" + (f' · {r["last_error"]}' if r["last_error"] else ""), "/guardian"))
    for r in drift:
        items.append(("warning", r["site_name"], "Configuration drift detected", f'/changes/{r["id"]}'))
    for r in alerts:
        items.append(("warning", r["site_name"], f'Resource alert: {r["metric"]} {r["last_value"]}', f'/fleet-search?attention=alerts'))
    for r in reboots:
        items.append(("warning", r["site_name"], r["summary"], f'/operations/{r["id"]}'))
    for r in failed:
        items.append(("critical", r["site_name"], f'Failed change: {r["kind"]} {r["error_code"]}', f'/reliability#tx-{r["tx_id"]}'))
    for r in flaps:
        items.append(("warning", r["site_name"], f'{r["last_flap_count"]} management flaps in the detection window', "/guardian"))
    for r in compliance:
        level = "critical" if r["failed"] else "warning"
        items.append((level, r["site_name"],
                      f'Golden policy: {r["failed"]} failed / {r["warnings"]} warnings',
                      f'/compliance/{r["id"]}'))
    for r in outages:
        level = "critical" if r["classification"] in {"likely_isp","possible_control_plane","site_wan"} else "warning"
        items.append((level,r["site_name"],f'{r["summary"]} · confidence {r["confidence"]}',f'/operations/{r["id"]}'))
    if sys and sys["overall_status"] != "ok":
        items.append(("critical", "Tikcentral", f'System self-health: {sys["overall_status"]}', "/system-health"))

    if not items:
        return '<div class="panel pad"><h2>Attention</h2><div class="muted">No current fleet items require attention.</div></div>'
    rows = "".join(
        f'<tr><td><span class="tc-status {"bad" if sev=="critical" else "warn"}"><span class="tc-status-dot"></span>{html.escape(sev.title())}</span></td>'
        f'<td><strong>{html.escape(site)}</strong></td><td>{html.escape(msg)}</td><td><a href="{html.escape(link)}">Open</a></td></tr>'
        for sev,site,msg,link in items[:50]
    )
    return f'<div class="panel"><div class="pad"><h2>Attention</h2><div class="muted">Only actionable reliability, backup, drift, reboot, resource and Tikcentral self-health items.</div></div><table><thead><tr><th>Level</th><th>Site</th><th>Issue</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>'
