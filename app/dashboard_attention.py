"""Meaningful fleet attention summary for the main dashboard."""

import html
import json
from datetime import datetime, timedelta, timezone

from app import alert_queue, main as core, migrations, settings


def render() -> str:
    migrations.migrate()
    try:
        alert_queue.sync()
    except Exception:
        pass
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=24)).isoformat()
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
               JOIN routers r ON r.id=x.router_id WHERE x.active=1 AND COALESCE(r.lifecycle_state,'production')<>'retired' ORDER BY x.last_seen_at DESC LIMIT 25"""
        ).fetchall()
        reboots = conn.execute(
            """SELECT r.id,r.site_name,e.event_at,e.summary FROM router_events e
               JOIN routers r ON r.id=e.router_id WHERE COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance') AND e.category='reboot' AND e.event_at>=?
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
               JOIN routers r ON r.id=s.router_id WHERE COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance') AND s.last_flap_count>=?
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
        certs = conn.execute(
            """SELECT r.id,r.site_name,c.name,c.days_remaining,c.status
               FROM router_certificates c JOIN routers r ON r.id=c.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired'
                 AND c.captured_at=(SELECT MAX(c2.captured_at) FROM router_certificates c2 WHERE c2.router_id=c.router_id)
                 AND c.status IN ('warning','critical','expired')
               ORDER BY c.days_remaining ASC LIMIT 30"""
        ).fetchall()
        upcoming = conn.execute(
            """SELECT p.id,p.title,p.start_at,p.change_type,COALESCE(r.site_name,'Fleet') site_name
               FROM planned_changes p LEFT JOIN routers r ON r.id=p.router_id
               WHERE p.status='planned' AND p.start_at>=? AND p.start_at<=?
               ORDER BY p.start_at LIMIT 20""",
            (now.isoformat(), (now + timedelta(days=7)).isoformat()),
        ).fetchall()
        security = conn.execute(
            """SELECT r.id,r.site_name,s.status,s.critical_count,s.warning_count
               FROM router_security_audit s JOIN routers r ON r.id=s.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired'
                 AND s.status IN ('critical','warning')
               ORDER BY s.critical_count DESC,s.warning_count DESC LIMIT 30"""
        ).fetchall()
        unmanaged = conn.execute(
            """SELECT r.id,r.site_name,COUNT(*) unmanaged_count
               FROM router_automation_inventory a JOIN routers r ON r.id=a.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired'
                 AND a.enabled=1 AND a.managed=0
                 AND a.captured_at=(SELECT MAX(a2.captured_at) FROM router_automation_inventory a2 WHERE a2.router_id=a.router_id)
               GROUP BY r.id,r.site_name HAVING COUNT(*)>0
               ORDER BY unmanaged_count DESC LIMIT 30"""
        ).fetchall()
        capacity = conn.execute(
            """SELECT r.id,r.site_name,c.summary,c.assessed_at
               FROM router_capacity_forecast c JOIN routers r ON r.id=c.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired'
                 AND c.status='warning'
               ORDER BY c.assessed_at DESC LIMIT 30"""
        ).fetchall()
        wan_probes = conn.execute(
            """SELECT r.id,r.site_name,w.classification,w.summary,w.captured_at
               FROM router_wan_probe_history w JOIN routers r ON r.id=w.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance')
                 AND w.id=(SELECT MAX(w2.id) FROM router_wan_probe_history w2 WHERE w2.router_id=w.router_id)
                 AND w.classification NOT IN ('healthy','unknown')
               ORDER BY w.id DESC LIMIT 30"""
        ).fetchall()
        desired_state = conn.execute(
            """SELECT r.id,r.site_name,d.status,d.failed,d.warnings
               FROM router_desired_state_status d JOIN routers r ON r.id=d.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production')<>'retired'
                 AND d.status IN ('fail','warning')
               ORDER BY d.failed DESC,d.warnings DESC LIMIT 30"""
        ).fetchall()
        time_health = conn.execute(
            """SELECT r.id,r.site_name,t.status,t.summary
               FROM router_time_health t JOIN routers r ON r.id=t.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance')
                 AND t.status IN ('warning','critical')
               ORDER BY CASE t.status WHEN 'critical' THEN 0 ELSE 1 END,t.checked_at DESC LIMIT 30"""
        ).fetchall()
        mtu_health = conn.execute(
            """SELECT r.id,r.site_name,m.status,m.summary
               FROM router_mtu_history m JOIN routers r ON r.id=m.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance')
                 AND m.id=(SELECT MAX(m2.id) FROM router_mtu_history m2 WHERE m2.router_id=m.router_id)
                 AND m.status='warning'
               ORDER BY m.id DESC LIMIT 30"""
        ).fetchall()
        public_ip_churn = conn.execute(
            """SELECT r.id,r.site_name,p.status,p.summary
               FROM router_public_ip_analysis p JOIN routers r ON r.id=p.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance')
                 AND p.status='high_churn'
               ORDER BY p.changes_30d DESC LIMIT 30"""
        ).fetchall()
        identity_collisions = conn.execute(
            "SELECT * FROM router_identity_collisions ORDER BY router_count DESC,identity LIMIT 30"
        ).fetchall()
        network_quality = conn.execute(
            """SELECT r.id,r.site_name,q.status,q.bufferbloat_status,q.summary
               FROM router_wan_quality q JOIN routers r ON r.id=q.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance')
                 AND q.id=(SELECT MAX(q2.id) FROM router_wan_quality q2 WHERE q2.router_id=q.router_id)
                 AND q.status IN ('warning','saturated')
               ORDER BY q.id DESC LIMIT 30"""
        ).fetchall()
        negotiation = conn.execute(
            """SELECT r.id,r.site_name,n.interface,n.summary
               FROM router_interface_negotiation n JOIN routers r ON r.id=n.router_id
               WHERE r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance')
                 AND n.status='warning' ORDER BY n.checked_at DESC LIMIT 30"""
        ).fetchall()
        dns_failures = conn.execute(
            """SELECT r.id,r.site_name,COUNT(*) failures
               FROM router_dns_health d JOIN routers r ON r.id=d.router_id
               WHERE d.ok=0 AND d.captured_at=(SELECT MAX(d2.captured_at) FROM router_dns_health d2 WHERE d2.router_id=d.router_id)
                 AND r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance')
               GROUP BY r.id,r.site_name HAVING COUNT(*)>0 ORDER BY failures DESC LIMIT 30"""
        ).fetchall()
        gateway_failures = conn.execute(
            """SELECT r.id,r.site_name,g.summary
               FROM router_isp_gateway_history g JOIN routers r ON r.id=g.router_id
               WHERE g.id=(SELECT MAX(g2.id) FROM router_isp_gateway_history g2 WHERE g2.router_id=g.router_id)
                 AND g.reachable=0 AND r.enabled=1 AND COALESCE(r.lifecycle_state,'production') NOT IN ('retired','maintenance')
               ORDER BY g.id DESC LIMIT 30"""
        ).fetchall()
        cross_site = conn.execute(
            "SELECT * FROM fleet_cross_site_anomalies WHERE status='active' ORDER BY id DESC LIMIT 20"
        ).fetchall()
        sys = conn.execute("SELECT checked_at,overall_status,checks_json FROM system_health_history ORDER BY id DESC LIMIT 1").fetchone()
        db_health = conn.execute(
            "SELECT * FROM database_health_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        queue_counts = conn.execute(
            """SELECT
                 SUM(CASE WHEN status='new' THEN 1 ELSE 0 END) new_count,
                 SUM(CASE WHEN status='acknowledged' THEN 1 ELSE 0 END) acknowledged_count,
                 SUM(CASE WHEN status='assigned' THEN 1 ELSE 0 END) assigned_count,
                 SUM(CASE WHEN status='investigating' THEN 1 ELSE 0 END) investigating_count
               FROM alert_queue WHERE status<>'resolved'"""
        ).fetchone()

    items = []
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
    for r in certs:
        level = "critical" if r["status"] in {"critical","expired"} else "warning"
        items.append((level,r["site_name"],f'Certificate {r["name"] or "-"}: {r["status"]} · {r["days_remaining"]} days',f'/certificates/{r["id"]}'))
    for p in upcoming:
        items.append(("warning",p["site_name"],f'Planned {p["change_type"]}: {p["title"]} · {p["start_at"]}',f'/change-calendar/{p["id"]}'))
    for r in security:
        level="critical" if r["critical_count"] else "warning"
        items.append((level,r["site_name"],
                      f'Security exposure audit: {r["critical_count"]} critical / {r["warning_count"]} warning',
                      f'/security-audit/{r["id"]}'))
    for r in unmanaged:
        items.append(("warning",r["site_name"],
                      f'{r["unmanaged_count"]} enabled unmanaged RouterOS automation object(s)',
                      f'/automation-inventory/{r["id"]}'))
    for r in capacity:
        items.append(("warning",r["site_name"],f'Capacity trend: {r["summary"]}',f'/capacity/{r["id"]}'))
    for r in wan_probes:
        level="critical" if r["classification"] in {"site_or_upstream","upstream"} else "warning"
        items.append((level,r["site_name"],f'WAN probe: {r["summary"]}',f'/wan-probe/{r["id"]}'))
    for r in desired_state:
        level="critical" if r["failed"] else "warning"
        items.append((level,r["site_name"],
                      f'Desired state: {r["failed"]} failed / {r["warnings"]} warnings',
                      f'/desired-state/{r["id"]}'))
    for r in time_health:
        items.append((r["status"],r["site_name"],f'Time/NTP: {r["summary"]}',f'/time-health/{r["id"]}'))
    for r in mtu_health:
        items.append(("warning",r["site_name"],f'MTU/MSS: {r["summary"]}',f'/mtu/{r["id"]}'))
    for r in public_ip_churn:
        items.append(("warning",r["site_name"],f'Public IP churn: {r["summary"]}',f'/public-ip-analysis/{r["id"]}'))
    for r in identity_collisions:
        items.append(("warning","Fleet",r["summary"],"/identity-collisions"))
    for r in network_quality:
        level="critical" if r["bufferbloat_status"]=="severe" else "warning"
        items.append((level,r["site_name"],f'WAN quality: {r["summary"]}',f'/network-quality/{r["id"]}'))
    for r in negotiation:
        items.append(("warning",r["site_name"],f'Interface negotiation {r["interface"]}: {r["summary"]}',f'/network-quality/{r["id"]}'))
    for r in dns_failures:
        items.append(("warning",r["site_name"],f'DNS health: {r["failures"]} resolver check(s) failed',f'/network-quality/{r["id"]}'))
    for r in gateway_failures:
        items.append(("critical",r["site_name"],f'ISP gateway: {r["summary"]}',f'/network-quality/{r["id"]}'))
    for r in cross_site:
        items.append(("critical" if r["kind"]=="multi-provider" else "warning","Fleet",r["summary"],"/cross-site-anomalies"))
    if sys and sys["overall_status"] != "ok":
        items.append(("critical", "Tikcentral", f'System self-health: {sys["overall_status"]}', "/system-health"))
    if db_health and db_health["status"] in {"warning","critical"}:
        items.append((db_health["status"],"Tikcentral",f'Database/storage: {db_health["summary"]}',"/database-health"))

    queue_total=sum(int(queue_counts[k] or 0) for k in ("new_count","acknowledged_count","assigned_count","investigating_count")) if queue_counts else 0
    queue_banner=f'<div class="panel pad"><h2>Alert workflow</h2><div><strong>{queue_total} open alert(s)</strong> · {int(queue_counts["new_count"] or 0) if queue_counts else 0} new · {int(queue_counts["assigned_count"] or 0) if queue_counts else 0} assigned · {int(queue_counts["investigating_count"] or 0) if queue_counts else 0} investigating</div><div style="margin-top:10px"><a href="/alerts"><button class="primary">Open alert queue</button></a></div></div>'
    if not items:
        return queue_banner+'<div class="panel pad"><h2>Attention</h2><div class="muted">No current fleet items require attention.</div></div>'
    rows = "".join(
        f'<tr><td><span class="tc-status {"bad" if sev=="critical" else "warn"}"><span class="tc-status-dot"></span>{html.escape(sev.title())}</span></td>'
        f'<td><strong>{html.escape(site)}</strong></td><td>{html.escape(msg)}</td><td><a href="{html.escape(link)}">Open</a></td></tr>'
        for sev,site,msg,link in items[:50]
    )
    return queue_banner+f'<div class="panel"><div class="pad"><h2>Attention</h2><div class="muted">Actionable fleet findings remain visible here; acknowledge, assign and resolve persistent events in the alert queue.</div></div><table><thead><tr><th>Level</th><th>Site</th><th>Issue</th><th></th></tr></thead><tbody>{rows}</tbody></table></div>'
