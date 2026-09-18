#!/usr/bin/env python3
"""Offline release gate for Tikcentral.

Uses a temporary SQLite database, never contacts routers, and must pass before an
atomic release can become current.
"""

import ast
import ipaddress
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_TMP = tempfile.TemporaryDirectory(prefix="tikcentral-release-test-")
os.environ["DB_PATH"] = str(Path(_TMP.name) / "tikcentral.db")

from app import ai_analysis, capabilities, errors, events, fleet, fleet_health, jobs
from app import management_script, migrations, performance_profile, router_exec
from app import scheduler, settings, ui
from app import main as core
from app.final import app

REQUIRED_ROUTES = {
    ("GET", "/"), ("GET", "/login"), ("POST", "/login"),
    ("GET", "/routers"), ("GET", "/settings"),
    ("GET", "/enroll"), ("POST", "/enroll/generate"),
    ("POST", "/enroll/admin-credentials"),
    ("GET", "/automation"), ("POST", "/automation/settings"),
    ("POST", "/automation/backup"), ("POST", "/automation/analyze"),
    ("GET", "/automation/jobs/{job_id}"),
    ("GET", "/ssh"), ("GET", "/ssh/{router_id}"), ("POST", "/ssh/{router_id}"),
    ("GET", "/guardian"), ("POST", "/guardian/{router_id}/repair"),
    ("GET", "/reliability"),
    ("POST", "/reliability/{router_id}/maintenance/start"),
    ("POST", "/reliability/{router_id}/maintenance/clear"),
    ("GET", "/reliability/{router_id}/quality"),
    ("GET", "/reliability/{router_id}/known-good"),
    ("POST", "/reliability/{router_id}/known-good/capture"),
    ("GET", "/reliability/{router_id}/wan"),
    ("GET", "/system-health"),
    ("POST", "/system-health/run"),
    ("POST", "/system-health/verify-backups"),
    ("GET", "/fleet-search"),
    ("GET", "/operator-audit"),
    ("GET", "/reliability/{router_id}/breakglass"),
    ("POST", "/reliability/{router_id}/breakglass"),
    ("GET", "/reliability/{router_id}/support"),
    ("GET", "/operations"), ("GET", "/operations/{router_id}"),
    ("POST", "/operations/{router_id}/commission"),
    ("POST", "/operations/{router_id}/telemetry"),
    ("POST", "/operations/{router_id}/profile/{profile}"),
    ("POST", "/operations/{router_id}/backup/{tier}"),
    ("POST", "/operations/{router_id}/drift/check"),
    ("POST", "/operations/{router_id}/baseline"),
    ("POST", "/operations/{router_id}/update/check"),
    ("POST", "/operations/{router_id}/upgrade/{mode}"),
    ("POST", "/operations/{router_id}/routerboot"),
    ("POST", "/operations/{router_id}/approve-version"),
    ("GET", "/rescue"), ("POST", "/rescue/{router_id}/enable"),
    ("POST", "/rescue/{router_id}/disable"),
    ("GET", "/changes"), ("GET", "/changes/{router_id}"),
    ("GET", "/audit"), ("GET", "/audit/{router_id}"),
    ("POST", "/audit/{router_id}/normalize"),
    ("GET", "/ai/{router_id}"), ("POST", "/ai/{router_id}/analyze"),
    ("GET", "/timeline/{router_id}"),
    ("GET", "/timeline/{router_id}/before"),
    ("GET", "/incidents/{router_id}"),
    ("POST", "/incidents/{router_id}/analyze"),
    ("GET", "/compliance"), ("GET", "/compliance/{router_id}"),
    ("GET", "/lte/{router_id}"),
    ("GET", "/interfaces/{router_id}"),
    ("GET", "/site/{router_id}"), ("POST", "/site/{router_id}"),
    ("GET", "/protection/{router_id}"), ("POST", "/protection/{router_id}"),
    ("POST", "/protection/{router_id}/{rule_id}/delete"),
    ("GET", "/diagnostics/{router_id}"), ("POST", "/diagnostics/{router_id}"),
    ("GET", "/recovery/{router_id}"),
    ("GET", "/recovery/{router_id}/snapshot/{snapshot_id}"),
    ("GET", "/lifecycle"), ("GET", "/lifecycle/{router_id}"), ("POST", "/lifecycle/{router_id}"),
    ("GET", "/maintenance-history/{router_id}"), ("POST", "/maintenance-history/{router_id}"),
    ("GET", "/upgrade-campaigns"), ("POST", "/upgrade-campaigns"),
    ("GET", "/upgrade-campaigns/{campaign_id}"), ("POST", "/upgrade-campaigns/{campaign_id}/approve"),
    ("GET", "/change-calendar"), ("POST", "/change-calendar"),
    ("GET", "/change-calendar/{change_id}"), ("POST", "/change-calendar/{change_id}/status"),
    ("GET", "/hardware/{router_id}"), ("POST", "/hardware/{router_id}"),
    ("GET", "/certificates/{router_id}"),
}

FORBIDDEN_FILES = {
    "app/entrypoint.py", "app/enroll_ui.py", "app/enrollment_v2.py", "app/enrollment_v3.py",
    "app/guardian_events.py", "app/branding.py", "app/ui_enhancements.py",
    "app/operations_stability.py", "app/operations_compat.py", "app/operations_safety.py",
    "app/operations_safe_routes.py", "app/operations_robust.py", "app/rescue_v2.py",
    "app/rescue_safe_routes.py", "app/backup_tiers.py",
    "deploy/tikcentral-enroll-ui.service", "scripts/smoke_test.py", "scripts/install-updater.sh",
    "app/static/opticable-logo-light.png", "app/static/opticable-logo-dark.png", "Caddyfile",
}


def fail(message):
    raise SystemExit(message)


def routes():
    counts, owners = {}, {}
    for route in app.routes:
        path = getattr(route, "path", None)
        if not path:
            continue
        for method in getattr(route, "methods", set()) or set():
            key = method, path
            counts[key] = counts.get(key, 0) + 1
            owners[key] = getattr(getattr(route, "endpoint", None), "__module__", "")
    return counts, owners


def validate_routes():
    counts, owners = routes()
    for key in REQUIRED_ROUTES:
        if counts.get(key) != 1:
            fail(f"Route {key} count={counts.get(key, 0)}, expected 1")
    dupes = [(k, n) for k, n in counts.items() if n > 1 and k[0] not in {"HEAD", "OPTIONS"}]
    if dupes:
        fail(f"Duplicate routes: {dupes}")

    owners_expected = {
        ("POST", "/enroll/generate"): "app.enrollment",
        ("POST", "/guardian/{router_id}/repair"): "app.guardian",
        ("POST", "/reliability/{router_id}/maintenance/start"): "app.reliability",
        ("POST", "/reliability/{router_id}/maintenance/clear"): "app.reliability",
        ("POST", "/rescue/{router_id}/enable"): "app.rescue",
        ("POST", "/rescue/{router_id}/disable"): "app.rescue",
        ("POST", "/ssh/{router_id}"): "app.production",
        ("POST", "/audit/{router_id}/normalize"): "app.final",
        ("POST", "/ai/{router_id}/analyze"): "app.ai_analysis",
        ("GET", "/fleet-search"): "app.fleet_explorer",
        ("GET", "/operator-audit"): "app.operator_audit",
        ("GET", "/timeline/{router_id}"): "app.troubleshooting",
        ("GET", "/timeline/{router_id}/before"): "app.troubleshooting",
        ("GET", "/incidents/{router_id}"): "app.troubleshooting",
        ("POST", "/incidents/{router_id}/analyze"): "app.troubleshooting",
        ("GET", "/compliance"): "app.compliance",
        ("GET", "/compliance/{router_id}"): "app.compliance",
        ("GET", "/lte/{router_id}"): "app.lte_monitor",
        ("GET", "/interfaces/{router_id}"): "app.interface_monitor",
        ("GET", "/site/{router_id}"): "app.site_metadata",
        ("POST", "/site/{router_id}"): "app.site_metadata",
        ("GET", "/protection/{router_id}"): "app.object_protection",
        ("POST", "/protection/{router_id}"): "app.object_protection",
        ("POST", "/protection/{router_id}/{rule_id}/delete"): "app.object_protection",
        ("GET", "/diagnostics/{router_id}"): "app.diagnostics",
        ("POST", "/diagnostics/{router_id}"): "app.diagnostics",
        ("GET", "/recovery/{router_id}"): "app.recovery_browser",
        ("GET", "/recovery/{router_id}/snapshot/{snapshot_id}"): "app.recovery_browser",
        ("GET", "/lifecycle"): "app.lifecycle",
        ("GET", "/lifecycle/{router_id}"): "app.lifecycle",
        ("POST", "/lifecycle/{router_id}"): "app.lifecycle",
        ("GET", "/maintenance-history/{router_id}"): "app.maintenance_history",
        ("POST", "/maintenance-history/{router_id}"): "app.maintenance_history",
        ("GET", "/upgrade-campaigns"): "app.upgrade_campaigns",
        ("POST", "/upgrade-campaigns"): "app.upgrade_campaigns",
        ("GET", "/upgrade-campaigns/{campaign_id}"): "app.upgrade_campaigns",
        ("POST", "/upgrade-campaigns/{campaign_id}/approve"): "app.upgrade_campaigns",
        ("GET", "/change-calendar"): "app.change_calendar",
        ("POST", "/change-calendar"): "app.change_calendar",
        ("GET", "/change-calendar/{change_id}"): "app.change_calendar",
        ("POST", "/change-calendar/{change_id}/status"): "app.change_calendar",
        ("GET", "/hardware/{router_id}"): "app.hardware_inventory",
        ("POST", "/hardware/{router_id}"): "app.hardware_inventory",
        ("GET", "/certificates/{router_id}"): "app.certificate_monitor",
    }
    for path in (
        "/operations/{router_id}/telemetry", "/operations/{router_id}/commission",
        "/operations/{router_id}/profile/{profile}", "/operations/{router_id}/backup/{tier}",
        "/operations/{router_id}/drift/check", "/operations/{router_id}/baseline",
        "/operations/{router_id}/update/check", "/operations/{router_id}/upgrade/{mode}",
        "/operations/{router_id}/routerboot", "/operations/{router_id}/approve-version",
    ):
        owners_expected[("POST", path)] = "app.operations"
    for key, expected in owners_expected.items():
        if owners.get(key) != expected:
            fail(f"Route owner {key}: {owners.get(key)!r}, expected {expected}")

    forbidden = {
        ("POST", "/automation/command"),
        ("POST", "/automation/update/check"),
        ("POST", "/automation/update/install"),
    }
    if forbidden.intersection(counts):
        fail("Legacy fleet mutation routes returned")


def validate_source_boundaries():
    for relative in FORBIDDEN_FILES:
        if (ROOT / relative).exists():
            fail(f"Legacy/redundant file returned: {relative}")

    for path in (ROOT / "app").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        lower, upper = text.lower(), text.upper()
        if path.name != "settings.py" and ("os.getenv(" in text or "os.environ[" in text):
            fail(f"Direct environment access outside settings.py: {path.name}")
        if path.name != "migrations.py" and ("CREATE TABLE" in upper or "ALTER TABLE" in upper):
            fail(f"Schema DDL outside migrations.py: {path.name}")
        if path.name not in {"jobs.py", "migrations.py"} and any(
            x in lower for x in ("insert into router_jobs", "update router_jobs", "delete from router_jobs")
        ):
            fail(f"Direct router_jobs mutation outside jobs.py: {path.name}")
        if path.name != "router_exec.py" and "subprocess." in text:
            tree = ast.parse(text, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.List, ast.Tuple)):
                    values = [x.value for x in node.elts if isinstance(x, ast.Constant) and isinstance(x.value, str)]
                    if "ssh" in values or "sftp" in values:
                        fail(f"Direct SSH/SFTP command outside router_exec.py: {path.name}")
        if path.name != "main.py" and any(x in text for x in (
            "app.router.routes[:]", "portal.portal_page =", "production.production_page =",
            "fleet_web.fleet_page =", "core.page =", "run_mass_command(",
        )):
            fail(f"Legacy patch/mass mutation pattern: {path.name}")

    guardian_text = (ROOT / "app/guardian.py").read_text(encoding="utf-8")
    final_text = (ROOT / "app/final.py").read_text(encoding="utf-8")
    if "REPAIR_COMMAND" in guardian_text or "NORMALIZE_COMMAND" in final_text:
        fail("Duplicate management firewall policy returned")
    if "management_script.access_repair_command()" not in guardian_text:
        fail("Guardian is not using canonical access repair policy")
    if "management_script.firewall_reconcile_command(include_print=True)" not in final_text:
        fail("Audit is not using canonical firewall policy")
    if "change_control.require_management" not in final_text:
        fail("Audit normalization bypasses shared access preflight")
    operations_text = (ROOT / "app/operations.py").read_text(encoding="utf-8")
    if "change_control.require_management" not in operations_text or "change_control.verify_management" not in operations_text:
        fail("Access-sensitive operations bypass shared change-control safety")
    production_text = (ROOT / "app/production.py").read_text(encoding="utf-8")
    for marker in ("change_control.authorize_mutation", "override_degraded", "override_reason", "change_control.begin", "operations.backup_router", "change_control.verify_management"):
        if marker not in production_text:
            fail(f"Web SSH bypasses degraded-access/transaction safety: {marker}")
    rescue_text = (ROOT / "app/rescue.py").read_text(encoding="utf-8")
    for marker in ("change_control.require_management", "change_control.begin", "operations.backup_router", "change_control.verify_management"):
        if marker not in rescue_text:
            fail(f"Rescue bypasses transactional safety: {marker}")
    change_text = (ROOT / "app/change_control.py").read_text(encoding="utf-8")
    for marker in ("Attempting canonical Tikcentral access recovery", "management_script.access_repair_command()", "transaction_id"):
        if marker not in change_text:
            fail(f"Shared change-control recovery missing: {marker}")
    for marker in ("change_control.begin", "change_control.attach_job", "change_control.step", "router_exec.sanitize"):
        if marker not in guardian_text:
            fail(f"Guardian repair transcript incomplete: {marker}")
    for marker in ("authorize_mutation", "OVERRIDE_REASON_REQUIRED", "OVERRIDE_UNSAFE", "access_override"):
        if marker not in change_text:
            fail(f"Degraded-access mutation protection missing: {marker}")
    reliability_text = (ROOT / "app/reliability.py").read_text(encoding="utf-8")
    for marker in ("_quality_summary", "_availability_svg", "_latency_svg", "/quality", "AESGCM", "_encrypt_breakglass", "passphrase is used only for this request"):
        if marker not in reliability_text:
            fail(f"Reliability feature missing: {marker}")
    decryptor = ROOT / "scripts/decrypt_breakglass.py"
    if not decryptor.is_file() or "AESGCM" not in decryptor.read_text(encoding="utf-8"):
        fail("Encrypted break-glass decryptor missing")
    system_health_text = (ROOT / "app/system_health.py").read_text(encoding="utf-8")
    for marker in ("collect_health", "record_health", "verify_backups", "_verify_database_backup", "_router_backup_status", "systemctl", "PRAGMA quick_check"):
        if marker not in system_health_text:
            fail(f"System self-health feature missing: {marker}")
    guardian_alert_text = (ROOT / "app/guardian.py").read_text(encoding="utf-8")
    for marker in ("_flap_count", "_update_alert_state", "GUARDIAN_WARN_FAILURES", "GUARDIAN_CRITICAL_MINUTES", "GUARDIAN_FLAP_THRESHOLD", "access_escalation", "access_flap"):
        if marker not in guardian_alert_text:
            fail(f"Guardian flap/escalation feature missing: {marker}")
    scheduler_text = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    if 'system_health.scheduled_tick' not in scheduler_text:
        fail("System health verification is not scheduled")
    state_capture_text = (ROOT / "app/state_capture.py").read_text(encoding="utf-8")
    for marker in ("MANAGEMENT_STATE_COMMAND", "WAN_STATE_COMMAND", "capture_management_known_good", "compare_management_known_good", "collect_wan_state", "store_config_snapshot_content"):
        if marker not in state_capture_text:
            fail(f"State capture feature missing: {marker}")
    role_text = (ROOT / "app/role_access.py").read_text(encoding="utf-8")
    for token in ("viewer", "technician", "admin", "Viewer accounts are read-only", "/admin/users"):
        if token not in role_text:
            fail(f"RBAC feature missing: {token}")
    preview_text = (ROOT / "app/change_preview.py").read_text(encoding="utf-8")
    for token in ("Pre-change preview", "Planned touch", "Guardian", "Backup state", "Recovery path", "preview_ack"):
        if token not in preview_text:
            fail(f"Change preview feature missing: {token}")
    attention_text = (ROOT / "app/dashboard_attention.py").read_text(encoding="utf-8")
    for token in ("Backup stale", "Management access degraded", "Configuration drift detected", "Failed change", "System self-health"):
        if token not in attention_text:
            fail(f"Dashboard attention feature missing: {token}")
    ai_focus_text = (ROOT / "app/ai_analysis.py").read_text(encoding="utf-8")
    for token in ("incident_focus", "focus_start", "focus_end", "focus_note", "Incident · last 24h"):
        if token not in ai_focus_text:
            fail(f"Incident-focused AI feature missing: {token}")
    support_text = (ROOT / "app/reliability.py").read_text(encoding="utf-8")
    for token in ("_support_summary_html", 'files["SUMMARY.html"]', "Start here"):
        if token not in support_text:
            fail(f"Support HTML summary missing: {token}")
    final_policy = (ROOT / "app/final.py").read_text(encoding="utf-8")
    for token in ("change_preview.install_middleware", "role_access.install_middleware"):
        if token not in final_policy:
            fail(f"Production policy middleware missing: {token}")
    ip_text = (ROOT / "app/ip_enrichment.py").read_text(encoding="utf-8")
    for marker in ("ipwho.is", "router_public_ip_history", "IP_LOOKUP_REFRESH_DAYS", "Public IP changed"):
        if marker not in ip_text and marker not in (ROOT / "app/settings.py").read_text(encoding="utf-8"):
            fail(f"Public-IP enrichment feature missing: {marker}")
    troubleshooting_text = (ROOT / "app/troubleshooting.py").read_text(encoding="utf-8")
    for marker in ("Router timeline", "What changed before failure?", "Incident builder", "router_public_ip_history", "queue_analysis"):
        if marker not in troubleshooting_text:
            fail(f"Troubleshooting timeline feature missing: {marker}")
    scheduler_ip = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    if 'ip_enrichment.refresh_all' not in scheduler_ip:
        fail("Public-IP enrichment is not scheduled")
    if "troubleshooting.register(app, ui.page)" not in final_text:
        fail("Troubleshooting routes are not registered")
    compliance_text = (ROOT / "app/compliance.py").read_text(encoding="utf-8")
    for marker in ("POLICY_COMMAND", "Tikcentral WireGuard interface exists", "Default admin account is not active", "router_policy_compliance"):
        if marker not in compliance_text:
            fail(f"Golden-policy compliance feature missing: {marker}")
    lte_text = (ROOT / "app/lte_monitor.py").read_text(encoding="utf-8")
    for marker in ("LTE_COMMAND", "router_lte_history", "rsrp", "ca_band", "LTE history"):
        if marker not in lte_text:
            fail(f"LTE observability feature missing: {marker}")
    scheduler_obs = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("compliance.evaluate", "lte_monitor.collect"):
        if marker not in scheduler_obs:
            fail(f"Scheduled observability missing: {marker}")
    cc_text = (ROOT / "app/change_control.py").read_text(encoding="utf-8")
    for marker in ("transaction_pre", "transaction_post", "Pre-change configuration snapshot captured", "Post-change configuration snapshot captured"):
        if marker not in cc_text:
            fail(f"Transaction snapshot pairing missing: {marker}")
    interface_text = (ROOT / "app/interface_monitor.py").read_text(encoding="utf-8")
    for marker in ("router_interface_history", "rx_errors", "tx_errors", "link_downs", "ETHERNET_MONITOR_COMMAND", "Interface health"):
        if marker not in interface_text:
            fail(f"Interface health feature missing: {marker}")
    outage_text = (ROOT / "app/outage_classifier.py").read_text(encoding="utf-8")
    for marker in ("likely_isp", "possible_control_plane", "site_wan", "management_path", "router_outage_assessment"):
        if marker not in outage_text:
            fail(f"Outage classifier feature missing: {marker}")
    site_text = (ROOT / "app/site_metadata.py").read_text(encoding="utf-8")
    for marker in ("router_site_metadata", "customer_name", "circuit_type", "ticket_reference", "support_notes"):
        if marker not in site_text:
            fail(f"Site metadata feature missing: {marker}")
    scheduler_new = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("interface_monitor.collect", "outage_classifier.assess_all"):
        if marker not in scheduler_new:
            fail(f"Scheduled monitoring missing: {marker}")
    protection_text = (ROOT / "app/object_protection.py").read_text(encoding="utf-8")
    for marker in ("router_object_protection", "protected_matches", "customer-owned", "never-modify", "Protected objects"):
        if marker not in protection_text:
            fail(f"Protected-object ownership feature missing: {marker}")
    diagnostics_text = (ROOT / "app/diagnostics.py").read_text(encoding="utf-8")
    for marker in ("TEMPLATES", "System resources", "Internet traceroute", "LTE monitor", 'require_web_role(request,"technician")'):
        if marker not in diagnostics_text:
            fail(f"Safe diagnostic templates missing: {marker}")
    recovery_text = (ROOT / "app/recovery_browser.py").read_text(encoding="utf-8")
    for marker in ("Guided recovery", "router_backup_records", "router_snapshots", "does not automatically apply", "Protected objects"):
        if marker not in recovery_text:
            fail(f"Recovery browser feature missing: {marker}")
    production_guard = (ROOT / "app/production.py").read_text(encoding="utf-8")
    if "object_protection.protected_matches" not in production_guard:
        fail("Manual Web SSH does not enforce protected objects")
    role_guard = (ROOT / "app/role_access.py").read_text(encoding="utf-8")
    if '"/ssh"' not in role_guard or "ADMIN_PREFIXES" not in role_guard:
        fail("Arbitrary Web SSH is not admin-only")
    preview_guard = (ROOT / "app/change_preview.py").read_text(encoding="utf-8")
    for marker in ("Protected objects", "protected_hits", "Blocked by protected object policy"):
        if marker not in preview_guard:
            fail(f"Protected-object preview integration missing: {marker}")
    final_guard = (ROOT / "app/final.py").read_text(encoding="utf-8")
    if "Normalization blocked by protected object rule" not in final_guard:
        fail("Normalization does not enforce protected-object policy")
    lifecycle_text = (ROOT / "app/lifecycle.py").read_text(encoding="utf-8")
    for marker in ("STATES", "commissioning", "production", "maintenance", "retired", "Lifecycle changed"):
        if marker not in lifecycle_text:
            fail(f"Router lifecycle feature missing: {marker}")
    maintenance_text = (ROOT / "app/maintenance_history.py").read_text(encoding="utf-8")
    for marker in ("router_maintenance_history", "ticket_reference", "work_performed", "follow_up", "Maintenance history"):
        if marker not in maintenance_text:
            fail(f"Maintenance history feature missing: {marker}")
    campaign_text = (ROOT / "app/upgrade_campaigns.py").read_text(encoding="utf-8")
    for marker in ("upgrade_campaigns", "upgrade_campaign_members", "canary", "Approve rollout", "sync_all", "campaign_stage"):
        if marker not in campaign_text:
            fail(f"Upgrade campaign feature missing: {marker}")
    scheduler_lifecycle = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("lifecycle_state", "upgrade_campaigns.sync_all"):
        if marker not in scheduler_lifecycle:
            fail(f"Lifecycle/campaign scheduler integration missing: {marker}")
    main_lifecycle = (ROOT / "app/main.py").read_text(encoding="utf-8")
    if '"new", iso(now), "enrollment"' not in main_lifecycle:
        fail("New enrollments do not start in New lifecycle state")
    calendar_text = (ROOT / "app/change_calendar.py").read_text(encoding="utf-8")
    for marker in ("planned_changes", "Plan a change", "Recorded changes this month", "change_transactions"):
        if marker not in calendar_text:
            fail(f"Change calendar feature missing: {marker}")
    hardware_text = (ROOT / "app/hardware_inventory.py").read_text(encoding="utf-8")
    for marker in ("hardware_inventory", "warranty_until", "asset_tag", "Hardware inventory"):
        if marker not in hardware_text:
            fail(f"Hardware inventory feature missing: {marker}")
    cert_text = (ROOT / "app/certificate_monitor.py").read_text(encoding="utf-8")
    for marker in ("router_certificates", "invalid-after", "days_remaining", "critical", "warning"):
        if marker not in cert_text:
            fail(f"Certificate inventory feature missing: {marker}")
    scheduler_cert = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    if "certificate_monitor.collect" not in scheduler_cert:
        fail("Certificate inventory is not scheduled")
    resource_text = (ROOT / "app/resource_monitor.py").read_text(encoding="utf-8")
    for marker in ("_uptime_seconds", "_memory_bytes", "_record_reboot", "RESOURCE_CPU_WARN", "Unexpected router reboot detected"):
        if marker not in resource_text:
            fail(f"Resource/reboot monitor missing: {marker}")
    explorer_text = (ROOT / "app/fleet_explorer.py").read_text(encoding="utf-8")
    for marker in ("Fleet Search", "Backup stale >2d", "CPU ≥85%", "Active resource alert", "No bulk mutation actions"):
        if marker not in explorer_text:
            fail(f"Fleet read-only search missing: {marker}")
    audit_text = (ROOT / "app/operator_audit.py").read_text(encoding="utf-8")
    for marker in ("operator_audit_log", "install_middleware", "source_ip", "Request bodies", "Guardian repair", "Manual Web SSH"):
        if marker not in audit_text:
            fail(f"Operator audit feature missing: {marker}")
    operations_resource = (ROOT / "app/operations.py").read_text(encoding="utf-8")
    if "resource_monitor.evaluate" not in operations_resource:
        fail("Telemetry does not feed resource/reboot monitor")
    changes_text = (ROOT / "app/changes.py").read_text(encoding="utf-8")
    for marker in ("_render_diff", "_diff_counts", "Directly attributed to Tikcentral", "source_kind", "source_actor"):
        if marker not in changes_text:
            fail(f"Configuration history feature missing: {marker}")
    for path in (ROOT / "app").glob("*.py"):
        if "show-sensitive=no" in path.read_text(encoding="utf-8"):
            fail(f"Invalid RouterOS show-sensitive=no syntax returned: {path.name}")


def validate_ui_and_assets():
    rendered = ui.page(
        "Operations",
        '<div class="panel"><table><thead><tr><th>Status</th></tr></thead><tbody><tr><td>Healthy</td></tr></tbody></table></div>',
        {"email": "validator@opticable.local"}, "operations",
    ).body.decode()
    for marker in ("tcGlobalSearch", "tcToggleTheme", "tc-local-search", "Columns ▾"):
        if marker not in rendered:
            fail(f"Shared UI missing {marker}")
    if set(settings.ASSET_FILES) != {"logo_light", "logo_dark", "icon"}:
        fail("Unexpected asset manifest keys")
    for key, filename in settings.ASSET_FILES.items():
        asset = ROOT / "app/static" / filename
        expected = f"/static/{filename}?v={settings.ASSET_VERSION}"
        if not asset.is_file() or not asset.stat().st_size:
            fail(f"Missing asset: {asset}")
        if settings.ASSETS.get(key) != expected or expected not in rendered:
            fail(f"Asset manifest/cache mismatch: {key}")


def validate_router_policy():
    normalized = router_exec.routeros_single_line("/system resource print\n/ip service print")
    if "/system resource print;" not in normalized or "/ip service print;" not in normalized:
        fail("RouterOS command normalization failed")
    redacted = router_exec.sanitize('password="supersecret" token=abc123')
    if "supersecret" in redacted or "abc123" in redacted:
        fail("RouterOS secret redaction failed")
    if errors.from_exception(PermissionError("x")).code != errors.Code.PERMISSION_DENIED:
        fail("Structured error mapping failed")

    canonical = management_script.firewall_reconcile_command()
    repair = management_script.access_repair_command()
    enroll = management_script.build_routeros_script("validator", "validator-token-123456789")
    for marker in ('name="tikcentral"', "10.250.0.1/32", "/api/enroll", "dst-port=22,8291,8728", "dst-port=22,8291"):
        if marker not in enroll:
            fail(f"Enrollment policy missing {marker}")
    for comment in ("Tikcentral management TCP", "Tikcentral admin TCP", "Tikcentral admin ICMP"):
        tag = f'comment="{comment}"'
        if canonical.count(tag) != 1 or enroll.count(tag) != 1 or tag not in repair:
            fail(f"Canonical firewall rule missing/duplicated: {comment}")
    if 'name="winbox"] disabled=no address=10.250.0.1/32' in enroll or 'name="ssh"] disabled=no address=10.250.0.1/32' in enroll:
        fail("Enrollment would overwrite local management address access")


def validate_rescue():
    network = ipaddress.ip_network(settings.RESCUE_NETWORK)
    address = ipaddress.ip_interface(settings.RESCUE_ADDRESS)
    start_text, end_text = settings.RESCUE_POOL.split("-", 1)
    start, end = ipaddress.ip_address(start_text), ipaddress.ip_address(end_text)
    if address.ip not in network or start not in network or end not in network or int(start) > int(end):
        fail("Invalid centralized Rescue addressing")
    if settings.RESCUE_GATEWAY != str(address.ip):
        fail("Rescue gateway not derived from Rescue address")
    text = (ROOT / "app/rescue.py").read_text(encoding="utf-8")
    for marker in ("settings.RESCUE_NETWORK", "settings.RESCUE_GATEWAY", "settings.RESCUE_DNS", "settings.RESCUE_POOL"):
        if marker not in text:
            fail(f"Rescue bypasses centralized setting: {marker}")


def validate_persistence_and_jobs():
    expected = len(migrations.MIGRATIONS)
    if migrations.migrate() != expected or migrations.migrate() != expected:
        fail("Migrations are not deterministic/idempotent")
    required = {
        "routers", "router_jobs", "router_capabilities", "router_telemetry", "router_events",
        "router_access_state", "router_access_history", "router_backup_records",
        "fleet_settings", "fleet_jobs", "fleet_job_results", "router_snapshots", "fleet_findings",
        "router_ai_analyses", "change_transactions", "change_transaction_steps",
        "router_maintenance", "fleet_incidents", "router_management_known_good", "router_wan_history",
        "router_access_alert_state", "system_health_history", "backup_verifications",
        "router_resource_alerts", "operator_audit_log", "router_public_ip_history",
        "router_policy_compliance", "router_lte_history",
        "router_interface_history", "router_outage_assessment", "router_site_metadata",
        "router_object_protection",
        "router_maintenance_history", "upgrade_campaigns", "upgrade_campaign_members",
        "planned_changes", "hardware_inventory", "router_certificates",
    }
    with sqlite3.connect(settings.DB_PATH) as conn:
        version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        snapshot_columns = {r[1] for r in conn.execute("PRAGMA table_info(router_snapshots)")}
        ai_columns = {r[1] for r in conn.execute("PRAGMA table_info(router_ai_analyses)")}
        router_columns = {r[1] for r in conn.execute("PRAGMA table_info(routers)")}
    if version != expected or not required.issubset(tables):
        fail("Fresh migration schema validation failed")
    if not {"source_kind", "source_id", "source_actor"}.issubset(snapshot_columns):
        fail("Attributed snapshot schema validation failed")
    if not {"focus_start", "focus_end", "focus_note"}.issubset(ai_columns):
        fail("Incident AI schema validation failed")
    if not {"lifecycle_state", "lifecycle_updated_at", "lifecycle_updated_by"}.issubset(router_columns):
        fail("Router lifecycle schema validation failed")

    capabilities.set_mode(9001, capabilities.OPTICABLE_DEFAULT, "2026-01-01T00:00:00+00:00", "smoke")
    cap = capabilities.get(9001)
    if not cap.supports_performance_profiles or not cap.managed_baseline:
        fail("Typed capability persistence failed")

    with core.db() as conn:
        for rid in (9001, 9002):
            conn.execute(
                "INSERT INTO routers(id,site_name,public_key,vpn_ip,created_at,enabled) VALUES(?,?,?,?,?,1)",
                (rid, f"Smoke {rid}", f"key-{rid}", f"10.250.250.{rid-9000}", "2026-01-01T00:00:00+00:00"),
            )
            conn.execute(
                """INSERT INTO router_access_state
                   (router_id,checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok,last_good_at,last_error)
                   VALUES(?, ?,1,1,1,1,1,?,'')""",
                (rid, "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
            )

    ai_id = ai_analysis.queue_analysis(9002, "validator")
    if ai_analysis.queue_analysis(9002, "validator") != ai_id:
        fail("AI analysis queue allowed duplicate pending work for one router")

    job_id = jobs.create(9001, "smoke_mutation", "validator", serialize_router=True)
    jobs.running(job_id)
    eligible = scheduler._eligible_healthy_router_ids()
    if 9001 in eligible or 9002 not in eligible:
        fail("Read/change scheduler isolation failed")
    if fleet_health.get(9001).state != fleet_health.CHANGE_IN_PROGRESS:
        fail("Fleet health does not surface active change")
    jobs.verifying(job_id)
    jobs.succeeded(job_id)
    if fleet_health.get(9001).state != fleet_health.HEALTHY:
        fail("Fleet health did not return to Healthy")
    try:
        jobs.running(job_id)
    except Exception:
        pass
    else:
        fail("Terminal job accepted invalid transition")

    if hasattr(fleet, "run_mass_command"):
        fail("Generic fleet mass mutation helper returned")
    fleet_text = (ROOT / "app/fleet.py").read_text(encoding="utf-8")
    if "with jobs.operation(" not in fleet_text or '"backup"' not in fleet_text:
        fail("Fleet backups are not serialized through router_jobs")


def validate_optional_boundaries():
    with core.db() as conn:
        before = conn.execute("SELECT COUNT(*) FROM router_events").fetchone()[0]
    events.record(9001, "telemetry", "Telemetry collected: CPU 5%", severity="info")
    with core.db() as conn:
        after = conn.execute("SELECT COUNT(*) FROM router_events").fetchone()[0]
    if after != before:
        fail("Routine telemetry polluted event timeline")

    runner = (ROOT / "app/fleet_runner.py").read_text(encoding="utf-8")
    guardian_pos = runner.find("guardian.guardian_tick")
    scheduler_pos = runner.find("scheduler.scheduled_tick")
    if guardian_pos < 0 or scheduler_pos < 0 or guardian_pos > scheduler_pos:
        fail("Guardian is no longer first in scheduled critical path")


def validate_provisioning_and_updater():
    script = performance_profile.performance_ready_default_config_script(
        "release-validation", 12, 4, 500, 500, 80, 40, "ether2"
    )
    script = performance_profile.apply_profile(script, "throughput")
    for marker in (
        "Default WAN DHCP", "Bell PPPoE - enter credentials onsite", "Opticable FastTrack",
        "Opticable RAW", "Opticable MSS clamp", "OPT-QOS-UPLOAD",
        "Performance profile active: Maximum throughput",
    ):
        if marker not in script:
            fail(f"Provisioning missing {marker}")

    launcher = ROOT / "helpers/tikcentral-update"
    if not launcher.is_file() or "repository.git" not in launcher.read_text(encoding="utf-8"):
        fail("Stable updater launcher missing/invalid")
    wg_helper = (ROOT / "helpers/tikcentral-wg-peer").read_text(encoding="utf-8")
    if "/etc/tikcentral/tikcentral.env" not in wg_helper or "WG_ROUTER_POOL" not in wg_helper:
        fail("WireGuard helper ignores centralized router pool")

    codex_helper_path = ROOT / "helpers/tikcentral-codex-analyze"
    if not codex_helper_path.is_file():
        fail("Codex analysis helper missing")
    codex_helper = codex_helper_path.read_text(encoding="utf-8")
    for marker in ("tikcentral-ai", "env -i", "--sandbox read-only", "--skip-git-repo-check"):
        if marker not in codex_helper:
            fail(f"Codex helper missing isolation control: {marker}")
    for unit in ("deploy/tikcentral-ai.service", "deploy/tikcentral-ai.timer"):
        if not (ROOT / unit).is_file():
            fail(f"AI worker unit missing: {unit}")
    backup_script = (ROOT / "scripts/backup.sh").read_text(encoding="utf-8")
    for marker in ("chown root:tikcentral", "chmod 0640"):
        if marker not in backup_script:
            fail(f"Database backup verification permission missing: {marker}")
    worker_text = (ROOT / "app/ai_worker.py").read_text(encoding="utf-8")
    if "router_ai_analyses" not in worker_text or "ai_analysis.run_codex" not in worker_text:
        fail("Persistent AI worker is not wired to the AI queue")


def main():
    validate_routes()
    validate_source_boundaries()
    validate_ui_and_assets()
    validate_router_policy()
    validate_rescue()
    validate_persistence_and_jobs()
    validate_optional_boundaries()
    validate_provisioning_and_updater()
    print(f"Tikcentral release validation: OK · schema v{len(migrations.MIGRATIONS)} · {len(app.routes)} routes")


if __name__ == "__main__":
    try:
        main()
    finally:
        _TMP.cleanup()
