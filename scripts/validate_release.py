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

from app import ai_analysis, capabilities, errors, events, fleet, fleet_health, jobs, semantic_config
from app import management_script, migrations, performance_profile, router_exec
from app import scheduler, settings, system_health, ui, ui_time
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
    ("POST", "/hardware/{router_id}/{item_id}/status"),
    ("GET", "/certificates/{router_id}"),
    ("GET", "/security-audit/{router_id}"),
    ("GET", "/automation-inventory/{router_id}"),
    ("GET", "/traffic/{router_id}"),
    ("GET", "/capacity/{router_id}"),
    ("GET", "/notes/{router_id}"), ("POST", "/notes/{router_id}"),
    ("GET", "/customer-report/{router_id}"),
    ("POST", "/customer-report/{router_id}/record"),
    ("GET", "/topology/{router_id}"),
    ("GET", "/wan-probe/{router_id}"), ("POST", "/wan-probe/{router_id}"),
    ("GET", "/desired-state/{router_id}"), ("POST", "/desired-state/{router_id}"),
    ("GET", "/replacements"), ("POST", "/replacements"),
    ("GET", "/replacements/{replacement_id}"), ("POST", "/replacements/{replacement_id}/execute"),
    ("GET", "/maintenance-automation"), ("POST", "/maintenance-automation"),
    ("GET", "/alerts"), ("POST", "/alerts/{alert_id}"),
    ("GET", "/customers"), ("GET", "/customer"),
    ("GET", "/database-health"),
    ("GET", "/config-search"),
    ("GET", "/retention"), ("POST", "/retention"),
    ("GET", "/commissioning-checklist/{router_id}"),
    ("POST", "/commissioning-checklist/settings"),
    ("GET", "/time-health/{router_id}"),
    ("GET", "/mtu/{router_id}"), ("POST", "/mtu/{router_id}/run"),
    ("GET", "/public-ip-analysis/{router_id}"),
    ("GET", "/identity-collisions"),
    ("GET", "/local-utilization/{router_id}"),
    ("GET", "/model-capabilities"),
    ("GET", "/log-patterns/{router_id}"),
    ("GET", "/hardware-lifecycle"),
    ("GET", "/hardware-lifecycle/{router_id}"),
    ("POST", "/hardware-lifecycle/{router_id}/notes"),
    ("GET", "/network-quality/{router_id}"),
    ("POST", "/network-quality/{router_id}/run"),
    ("GET", "/cross-site-anomalies"),
    ("GET", "/change-impact/{transaction_id}"),
    ("GET", "/training"),
    ("GET", "/training/intelligence-guide"),
    ("GET", "/training/{lesson_id}"),
    ("POST", "/training/{lesson_id}/status"),
    ("POST", "/training/track/{track_slug}/skip"),
    ("POST", "/training/reset"),
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
        ("POST", "/hardware/{router_id}/{item_id}/status"): "app.hardware_inventory",
        ("GET", "/certificates/{router_id}"): "app.certificate_monitor",
        ("GET", "/security-audit/{router_id}"): "app.security_audit",
        ("GET", "/automation-inventory/{router_id}"): "app.automation_inventory",
        ("GET", "/traffic/{router_id}"): "app.traffic_monitor",
        ("GET", "/capacity/{router_id}"): "app.capacity_forecast",
        ("GET", "/notes/{router_id}"): "app.operator_notes",
        ("POST", "/notes/{router_id}"): "app.operator_notes",
        ("GET", "/customer-report/{router_id}"): "app.customer_reports",
        ("POST", "/customer-report/{router_id}/record"): "app.customer_reports",
        ("GET", "/topology/{router_id}"): "app.topology",
        ("GET", "/wan-probe/{router_id}"): "app.wan_probe",
        ("POST", "/wan-probe/{router_id}"): "app.wan_probe",
        ("GET", "/desired-state/{router_id}"): "app.desired_state",
        ("POST", "/desired-state/{router_id}"): "app.desired_state",
        ("GET", "/replacements"): "app.router_replacement",
        ("POST", "/replacements"): "app.router_replacement",
        ("GET", "/replacements/{replacement_id}"): "app.router_replacement",
        ("POST", "/replacements/{replacement_id}/execute"): "app.router_replacement",
        ("GET", "/maintenance-automation"): "app.maintenance_automation",
        ("POST", "/maintenance-automation"): "app.maintenance_automation",
        ("GET", "/alerts"): "app.alert_queue",
        ("POST", "/alerts/{alert_id}"): "app.alert_queue",
        ("GET", "/customers"): "app.customer_overview",
        ("GET", "/customer"): "app.customer_overview",
        ("GET", "/database-health"): "app.database_health",
        ("GET", "/config-search"): "app.config_search",
        ("GET", "/retention"): "app.retention_policy",
        ("POST", "/retention"): "app.retention_policy",
        ("GET", "/commissioning-checklist/{router_id}"): "app.commissioning_checklist",
        ("POST", "/commissioning-checklist/settings"): "app.commissioning_checklist",
        ("GET", "/time-health/{router_id}"): "app.time_health",
        ("GET", "/mtu/{router_id}"): "app.mtu_diagnostics",
        ("POST", "/mtu/{router_id}/run"): "app.mtu_diagnostics",
        ("GET", "/public-ip-analysis/{router_id}"): "app.public_ip_analysis",
        ("GET", "/identity-collisions"): "app.identity_collision",
        ("GET", "/local-utilization/{router_id}"): "app.local_utilization",
        ("GET", "/model-capabilities"): "app.model_capabilities",
        ("GET", "/log-patterns/{router_id}"): "app.log_patterns",
        ("GET", "/hardware-lifecycle"): "app.hardware_lifecycle",
        ("GET", "/hardware-lifecycle/{router_id}"): "app.hardware_lifecycle",
        ("POST", "/hardware-lifecycle/{router_id}/notes"): "app.hardware_lifecycle",
        ("GET", "/network-quality/{router_id}"): "app.network_quality",
        ("POST", "/network-quality/{router_id}/run"): "app.network_quality",
        ("GET", "/cross-site-anomalies"): "app.cross_site_anomaly",
        ("GET", "/change-impact/{transaction_id}"): "app.change_impact",
        ("GET", "/training"): "app.training",
        ("GET", "/training/intelligence-guide"): "app.training",
        ("GET", "/training/{lesson_id}"): "app.training",
        ("POST", "/training/{lesson_id}/status"): "app.training",
        ("POST", "/training/track/{track_slug}/skip"): "app.training",
        ("POST", "/training/reset"): "app.training",
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
    main_source = (ROOT / "app/main.py").read_text(encoding="utf-8")
    ui_source = (ROOT / "app/ui.py").read_text(encoding="utf-8")
    winbox_source = (ROOT / "app/winbox_proxy.py").read_text(encoding="utf-8")
    update_source = (ROOT / "update.sh").read_text(encoding="utf-8")
    for marker in ('id="tcLogoutForm"', "input.name='csrf'", "logoutForm.querySelector('button').disabled=false"):
        if marker not in ui_source:
            fail(f"Logout CSRF UI regression: {marker}")
    if 'async def logout(request: Request):' not in main_source or 'require_csrf(request, data.get("csrf", ""))' not in main_source:
        fail("Logout route is not CSRF protected")
    for legacy in ("localStorage.getItem('tikcentral:density')", "localStorage.getItem('tikcentral:hide-guidance')", "localStorage.getItem('tikcentral:router-tab')"):
        if legacy in ui_source:
            fail(f"Cross-user UI fallback storage reintroduced: {legacy}")
    for marker in ("authorization_watch", "target_active(vpn_ip)", "mode=ro", "PRAGMA query_only=ON"):
        if marker not in winbox_source:
            fail(f"WinBox relay authorization/read-only regression: {marker}")
    for marker in ('CADDY_TMP="$(mktemp', 'caddy validate --adapter caddyfile --config "$CADDY_TMP"', 'install -o root -g root -m 0644 "$CADDY_TMP" /etc/caddy/Caddyfile'):
        if marker not in update_source:
            fail(f"Safe Caddy staging regression: {marker}")

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
    for marker in ("Protected objects", "protected_hits", "blocked_reasons", "router is disabled or retired"):
        if marker not in preview_guard:
            fail(f"Protected-object/lifecycle preview integration missing: {marker}")
    final_guard = (ROOT / "app/final.py").read_text(encoding="utf-8")
    if "Normalization blocked by protected object rule" not in final_guard:
        fail("Normalization does not enforce protected-object policy")
    guardian_guard = (ROOT / "app/guardian.py").read_text(encoding="utf-8")
    rescue_guard = (ROOT / "app/rescue.py").read_text(encoding="utf-8")
    ssh_guard = (ROOT / "app/production.py").read_text(encoding="utf-8")
    for source, label, markers in (
        (guardian_guard, "Guardian repair", ("ROUTER_RETIRED", "lifecycle_state")),
        (rescue_guard, "Rescue", ("ROUTER_RETIRED", "lifecycle_state")),
        (ssh_guard, "Web SSH", ("lifecycle_state", "active router not found")),
        (final_guard, "Audit normalization", ("lifecycle_state", '"retired"')),
    ):
        for marker in markers:
            if marker not in source:
                fail(f"{label} retired-router guard missing: {marker}")
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
    for marker in ("planned_changes", "Plan a change", "Recorded changes this month", "change_transactions", "_normalize_datetime", "datetime-local"):
        if marker not in calendar_text:
            fail(f"Change calendar feature missing: {marker}")
    hardware_text = (ROOT / "app/hardware_inventory.py").read_text(encoding="utf-8")
    for marker in ("hardware_inventory", "warranty_until", "asset_tag", "Hardware inventory", "hardware_status"):
        if marker not in hardware_text:
            fail(f"Hardware inventory feature missing: {marker}")
    cert_text = (ROOT / "app/certificate_monitor.py").read_text(encoding="utf-8")
    for marker in ("router_certificates", "invalid-after", "days_remaining", "critical", "warning", "transitions", "events.record"):
        if marker not in cert_text:
            fail(f"Certificate inventory feature missing: {marker}")
    scheduler_cert = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    if "certificate_monitor.collect" not in scheduler_cert:
        fail("Certificate inventory is not scheduled")
    security_text = (ROOT / "app/security_audit.py").read_text(encoding="utf-8")
    for marker in ("router_security_audit", "IP service", "MAC WinBox", "Bandwidth server", "SOCKS proxy", "SNMP"):
        if marker not in security_text:
            fail(f"Security exposure audit missing: {marker}")
    automation_inv_text = (ROOT / "app/automation_inventory.py").read_text(encoding="utf-8")
    for marker in ("router_automation_inventory", "system script", "system scheduler", "tool netwatch", "Script bodies", "managed"):
        if marker not in automation_inv_text:
            fail(f"RouterOS automation inventory missing: {marker}")
    traffic_text = (ROOT / "app/traffic_monitor.py").read_text(encoding="utf-8")
    for marker in ("router_traffic_history", "95th", "rx_bps", "tx_bps", "Traffic surge", "counter resets"):
        if marker not in traffic_text:
            fail(f"Traffic history feature missing: {marker}")
    scheduler_security = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("security_audit.collect", "automation_inventory.collect", "traffic_monitor.collect"):
        if marker not in scheduler_security:
            fail(f"Scheduled security/traffic observability missing: {marker}")
    capacity_text = (ROOT / "app/capacity_forecast.py").read_text(encoding="utf-8")
    for marker in ("router_capacity_forecast", "HORIZON_DAYS", "insufficient_data", "Trend projection only", "projected_30d"):
        if marker not in capacity_text:
            fail(f"Capacity forecasting feature missing: {marker}")
    notes_text = (ROOT / "app/operator_notes.py").read_text(encoding="utf-8")
    for marker in ("operator_notes", "ticket_reference", "visibility", "customer", "Operator notes"):
        if marker not in notes_text:
            fail(f"Operator notes feature missing: {marker}")
    report_text = (ROOT / "app/customer_reports.py").read_text(encoding="utf-8")
    for marker in ("customer_report_history", "Print / Save PDF", "visibility='customer'", "excludes management IPs", "AI analysis"):
        if marker not in report_text:
            fail(f"Customer report feature missing: {marker}")
    scheduler_capacity = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    if "capacity_forecast.assess" not in scheduler_capacity:
        fail("Capacity forecasting is not scheduled after observability")
    topology_text = (ROOT / "app/topology.py").read_text(encoding="utf-8")
    for marker in ("router_topology_devices", "Ubiquiti / UniFi", "TP-Link / Omada", "MikroTik router", "hardware_inventory"):
        if marker not in topology_text:
            fail(f"Topology feature missing: {marker}")
    wan_probe_text = (ROOT / "app/wan_probe.py").read_text(encoding="utf-8")
    for marker in ("STANDARD", "1.1.1.1", "8.8.8.8", "cloudflare.com", "degraded_quality", "packet_loss_warn_percent", "latency_warn_ms"):
        if marker not in wan_probe_text:
            fail(f"WAN probe standard profile missing: {marker}")
    for marker in ("external_states", "probe unavailable or incomplete", "dns_ok=None"):
        haystack = wan_probe_text.replace(" ", "") if marker == "dns_ok=None" else wan_probe_text
        if marker not in haystack:
            fail(f"WAN probe transport-failure handling missing: {marker}")
    desired_text = (ROOT / "app/desired_state.py").read_text(encoding="utf-8")
    for marker in ("STANDARD_INTENT", "management_services_restricted", "default_route_required", "wireguard_required", "audit only"):
        if marker not in desired_text:
            fail(f"Desired-state intent feature missing: {marker}")
    scheduler_next = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("topology.collect", "wan_probe.collect", "desired_state.check"):
        if marker not in scheduler_next:
            fail(f"Topology/WAN/desired-state scheduling missing: {marker}")
    outage_next = (ROOT / "app/outage_classifier.py").read_text(encoding="utf-8")
    if "router_wan_probe_history" not in outage_next or "Multi-target WAN probe" not in outage_next:
        fail("Outage classifier does not use multi-target WAN evidence")
    replacement_text = (ROOT / "app/router_replacement.py").read_text(encoding="utf-8")
    for marker in ("router_replacements", "copy_site_metadata", "copy_protection", "copy_desired_state", "copy_wan_profile", "move_hardware", "move_future_changes", "does not clone a RouterOS export", "WireGuard/public-key identity"):
        if marker not in replacement_text:
            fail(f"Router replacement workflow missing: {marker}")
    maintenance_auto_text = (ROOT / "app/maintenance_automation.py").read_text(encoding="utf-8")
    for marker in ("maintenance_automation_runs", "run_on_upgrades", "run_on_routerboot", "post-change", "capture_config_snapshot", "compliance.evaluate", "security_audit.collect", "wan_probe.collect", "interface_monitor.collect", "desired_state.check"):
        if marker not in maintenance_auto_text:
            fail(f"Post-change maintenance automation missing: {marker}")
    alert_queue_text = (ROOT / "app/alert_queue.py").read_text(encoding="utf-8")
    for marker in ("alert_queue", "acknowledged", "assigned", "investigating", "resolved", "ticket_reference", "resolution_note"):
        if marker not in alert_queue_text:
            fail(f"Persistent alert workflow missing: {marker}")
    dashboard_queue_text = (ROOT / "app/dashboard_attention.py").read_text(encoding="utf-8")
    if "alert_queue.sync" not in dashboard_queue_text or "Open alert queue" not in dashboard_queue_text:
        fail("Dashboard Attention is not connected to alert workflow")
    scheduler_ops_text = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("maintenance_automation.process", "alert_queue.sync"):
        if marker not in scheduler_ops_text:
            fail(f"Scheduler workflow integration missing: {marker}")
    operations_backup_text = (ROOT / "app/operations.py").read_text(encoding="utf-8")
    if '"post-change"' not in operations_backup_text:
        fail("Post-change backup tier is not supported")
    customer_overview_text = (ROOT / "app/customer_overview.py").read_text(encoding="utf-8")
    for marker in ("Customers / sites", "Unassigned", "Sites / circuits", "Maintenance history", "Hardware", "Generated reports", "alert_queue"):
        if marker not in customer_overview_text:
            fail(f"Customer/site overview missing: {marker}")
    database_health_text = (ROOT / "app/database_health.py").read_text(encoding="utf-8")
    for marker in ("database_health_history", "statvfs", "growth_bytes_per_day", "estimated_days_to_80_percent", "SAMPLE_MINUTES", "FORECAST_WINDOW_DAYS", "Standard thresholds"):
        if marker not in database_health_text:
            fail(f"Database/storage health feature missing: {marker}")
    scheduler_storage_text = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    if "database_health.collect" not in scheduler_storage_text:
        fail("Database/storage health is not scheduled")
    dashboard_storage_text = (ROOT / "app/dashboard_attention.py").read_text(encoding="utf-8")
    if "database_health_history" not in dashboard_storage_text or "/database-health" not in dashboard_storage_text:
        fail("Database/storage warnings are not surfaced in Attention")
    config_search_text = (ROOT / "app/config_search.py").read_text(encoding="utf-8")
    for marker in ("Fleet configuration search", "router_snapshots", "router_exec.sanitize", "Latest snapshot per router", "All retained history"):
        if marker not in config_search_text:
            fail(f"Fleet config search missing: {marker}")
    retention_text = (ROOT / "app/retention_policy.py").read_text(encoding="utf-8")
    for marker in ("retention_settings", "retention_cleanup_history", "snapshot_days", "mtu_days", "router_mtu_history", "public_ip_sighting_days", "router_public_ip_sightings", "local_utilization_days", "router_local_utilization", "log_pattern_days", "router_log_patterns", "dns_health_days", "router_dns_health", "wan_quality_days", "router_wan_quality", "pppoe_days", "router_pppoe_history", "isp_gateway_days", "router_isp_gateway_history", "0 days means keep forever", "router_access_history", "router_wan_probe_history", "router_public_ip_history"):
        if marker not in retention_text:
            fail(f"Retention policy missing: {marker}")
    commissioning_text = (ROOT / "app/commissioning_checklist.py").read_text(encoding="utf-8")
    for marker in ("commissioning_checklist_status", "auto_promote", "promoted to Production", "require_hardware", "require_backup", "classification\"]==\"healthy"):
        if marker not in commissioning_text:
            fail(f"Commissioning checklist missing: {marker}")
    scheduler_policy_text = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("retention_policy.cleanup", "commissioning_checklist.evaluate_candidates"):
        if marker not in scheduler_policy_text:
            fail(f"Retention/commissioning scheduler integration missing: {marker}")
    ui_copy_text = (ROOT / "app/ui.py").read_text(encoding="utf-8")
    for marker in ("window.tcCopy", "tcWriteClipboard", "document.execCommand('copy')", "installCopyButtons", "MutationObserver", "input,textarea,select"):
        if marker not in ui_copy_text:
            fail(f"Shared clipboard support missing: {marker}")
    for path_name in ("app/enrollment.py", "app/changes.py"):
        page_text=(ROOT / path_name).read_text(encoding="utf-8")
        if "tcCopy(" not in page_text:
            fail(f"Page does not use shared clipboard helper: {path_name}")
    time_health_text = (ROOT / "app/time_health.py").read_text(encoding="utf-8")
    for marker in ("router_time_health", "DRIFT_WARN_SECONDS", "DRIFT_CRITICAL_SECONDS", "/system clock print", "/system ntp client print", "Time / NTP health", "Read-only"):
        if marker not in time_health_text:
            fail(f"Time/NTP health feature missing: {marker}")
    mtu_text = (ROOT / "app/mtu_diagnostics.py").read_text(encoding="utf-8")
    for marker in ("router_mtu_history", "do-not-fragment=yes", "PAYLOADS", "estimated_path_mtu", "recommended_tcp_mss", "AUTO_INTERVAL_HOURS", "Read-only DF ping"):
        if marker not in mtu_text:
            fail(f"MTU/MSS diagnostics missing: {marker}")
    scheduler_network_diag = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("time_health.collect", "mtu_diagnostics.collect"):
        if marker not in scheduler_network_diag:
            fail(f"Time/MTU scheduler integration missing: {marker}")
    attention_network_diag = (ROOT / "app/dashboard_attention.py").read_text(encoding="utf-8")
    for marker in ("router_time_health", "router_mtu_history", "/time-health/", "/mtu/"):
        if marker not in attention_network_diag:
            fail(f"Time/MTU attention integration missing: {marker}")
    public_ip_analysis_text = (ROOT / "app/public_ip_analysis.py").read_text(encoding="utf-8")
    for marker in ("router_public_ip_sightings", "changes_7d", "changes_30d", "changes_90d", "high_churn", "avg_days_between_changes"):
        if marker not in public_ip_analysis_text:
            fail(f"Public-IP frequency analysis missing: {marker}")
    ip_enrichment_text = (ROOT / "app/ip_enrichment.py").read_text(encoding="utf-8")
    if "router_public_ip_sightings" not in ip_enrichment_text or "transition" not in ip_enrichment_text:
        fail("Public-IP enrichment does not record actual transitions")
    identity_text = (ROOT / "app/identity_collision.py").read_text(encoding="utf-8")
    for marker in ("router_identity_collisions", "Duplicate RouterOS identity detected", "LOWER(TRIM(identity))", "HAVING COUNT(*)>1"):
        if marker not in identity_text:
            fail(f"Identity collision detector missing: {marker}")
    local_util_text = (ROOT / "app/local_utilization.py").read_text(encoding="utf-8")
    for marker in ("router_local_utilization", "confidence", "topo_if", "bridges", "_wan_interfaces", "estimate", "utilization_percent", "estimated_capacity_bps"):
        if marker not in local_util_text:
            fail(f"Local utilization estimation missing: {marker}")
    model_cap_text = (ROOT / "app/model_capabilities.py").read_text(encoding="utf-8")
    for marker in ("router_model_capability_observations", "router_model_capability_catalog", "architecture-name", "ethernet_ports", "lte_interfaces", "wifi_interfaces"):
        if marker not in model_cap_text:
            fail(f"Model capability database missing: {marker}")
    log_patterns_text = (ROOT / "app/log_patterns.py").read_text(encoding="utf-8")
    for marker in ("router_log_patterns", "normalized_pattern", "IP_RE", "MAC_RE", "pattern_hash", "Router log pattern detected"):
        if marker not in log_patterns_text:
            fail(f"Router log pattern detector missing: {marker}")
    scheduler_intel_text = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("public_ip_analysis.assess_all", "identity_collision.scan", "local_utilization.collect", "model_capabilities.collect", "log_patterns.collect"):
        if marker not in scheduler_intel_text:
            fail(f"Fleet intelligence scheduler integration missing: {marker}")
    semantic_text = (ROOT / "app/semantic_config.py").read_text(encoding="utf-8")
    for marker in ("AREA_RULES", "DNS", "Routing", "NAT", "changed", "_props", "compare"):
        if marker not in semantic_text:
            fail(f"Semantic config diff missing: {marker}")
    semantic_sample = semantic_config.compare(
        "/ip dns\nset servers=1.1.1.1 allow-remote-requests=yes",
        "/ip dns\nset servers=9.9.9.9 allow-remote-requests=yes",
    )
    if not semantic_sample or semantic_sample[0]["area"] != "DNS" or semantic_sample[0]["action"] != "changed" or "servers:" not in semantic_sample[0]["detail"]:
        fail("Semantic config diff smoke test failed")
    hardware_lifecycle_text = (ROOT / "app/hardware_lifecycle.py").read_text(encoding="utf-8")
    for marker in ("router_hardware_lifecycle", "observed_days", "model_observed_days", "reboot_count", "replacement_notes", "not vendor EOL"):
        if marker not in hardware_lifecycle_text:
            fail(f"Hardware lifecycle intelligence missing: {marker}")
    if "hardware_lifecycle.assess_all" not in (ROOT / "app/scheduler.py").read_text(encoding="utf-8"):
        fail("Hardware lifecycle assessment is not scheduled")
    login_text = (ROOT / "app/main.py").read_text(encoding="utf-8")
    for marker in ("loginPassword", "loginPasswordToggle", "Show password", "Hide password"):
        if marker not in login_text:
            fail(f"Login password visibility control missing: {marker}")
    shared_ui = (ROOT / "app/ui.py").read_text(encoding="utf-8")
    for marker in (
        "NAV_GROUPS", "PAGE_GUIDANCE", "Overview", "Fleet", "Operations", "Changes", "Intelligence", "Administration",
        "openPalette", "organizeRouterWorkspace", "defaultHidden", "tc-filter-toggle", "installRouterContext",
        "installRecentRouters", "protectDirtyForms", "decorateEmptyStates", "classifyActions", "tcGotoPrefix",
        "CATEGORY_SLUG", "CATEGORY_HOME", "tc-cat-fleet", "tc-cat-operations", "tc-cat-changes",
        "tc-cat-intelligence", "tc-cat-administration", "installDisclosureState", "emphasizeNestedSections",
        "ui:disclosure:", "tc-tab-description", "tabHelp", "Connectivity", "Configuration", "Assets", "Activity",
    ):
        if marker not in shared_ui:
            fail(f"Professional UI shell missing: {marker}")
    site_ui_text = (ROOT / "app/site_metadata.py").read_text(encoding="utf-8")
    for marker in ("Site identity", "Primary contact", "Circuit & technical details", "Support notes", "position:sticky"):
        if marker not in site_ui_text:
            fail(f"Progressive site-metadata UI missing: {marker}")
    main_ui_text = (ROOT / "app/main.py").read_text(encoding="utf-8")
    portal_ui_text = (ROOT / "app/portal.py").read_text(encoding="utf-8")
    if "data-default-hidden" not in main_ui_text or "data-default-hidden" not in portal_ui_text:
        fail("Focused default table-column presets are missing from dashboard/router inventory")
    for marker in ("tc-filter-column", "tc-filter-op", "tc-filter-value", "matchOperator", "contains", "!contains", ">=", "<=", "!="):
        if marker not in shared_ui:
            fail(f"Advanced shared table filter missing: {marker}")
    network_quality_text = (ROOT / "app/network_quality.py").read_text(encoding="utf-8")
    for marker in (
        "router_dns_health", "resolver reachability", "router_interface_negotiation", "downgrade",
        "SATURATION_PERCENT", "bufferbloat", "router_pppoe_history", "reconnect/reset",
        "router_isp_gateway_history", "ISP gateway state changed", "circuit_down_mbps", "circuit_up_mbps",
    ):
        if marker not in network_quality_text:
            fail(f"Network quality intelligence missing: {marker}")
    cross_site_text = (ROOT / "app/cross_site_anomaly.py").read_text(encoding="utf-8")
    for marker in ("fleet_cross_site_anomalies", "MIN_PROVIDER_ROUTERS", "MIN_FLEET_ROUTERS", "provider-network", "multi-provider"):
        if marker not in cross_site_text:
            fail(f"Cross-site anomaly detection missing: {marker}")
    change_impact_text = (ROOT / "app/change_impact.py").read_text(encoding="utf-8")
    for marker in ("change_impact_analysis", "BEFORE_MINUTES", "AFTER_MINUTES", "Temporal correlation", "semantic_config.compare", "Measured degradation"):
        if marker not in change_impact_text:
            fail(f"Change impact analysis missing: {marker}")
    scheduler_quality_text = (ROOT / "app/scheduler.py").read_text(encoding="utf-8")
    for marker in ("network_quality.collect", "cross_site_anomaly.scan", "change_impact.assess_recent"):
        if marker not in scheduler_quality_text:
            fail(f"Network quality/correlation scheduling missing: {marker}")
    site_metadata_quality = (ROOT / "app/site_metadata.py").read_text(encoding="utf-8")
    for marker in ("circuit_down_mbps", "circuit_up_mbps", "Circuit download Mbps", "Circuit upload Mbps"):
        if marker not in site_metadata_quality:
            fail(f"Circuit capacity metadata missing: {marker}")
    attention_quality = (ROOT / "app/dashboard_attention.py").read_text(encoding="utf-8")
    for marker in ("router_wan_quality", "router_interface_negotiation", "router_dns_health", "router_isp_gateway_history", "fleet_cross_site_anomalies"):
        if marker not in attention_quality:
            fail(f"Network quality attention integration missing: {marker}")
    ui_time_text = (ROOT / "app/ui_time.py").read_text(encoding="utf-8")
    for marker in ("Montréal", 'ZoneInfo("America/Toronto")', "_LEGACY_UTC_RE", "format_montreal", "localize_html_iso_timestamps"):
        if marker not in ui_time_text:
            fail(f"Montreal UI time formatter missing: {marker}")
    training_text = (ROOT / "app/training.py").read_text(encoding="utf-8")
    for marker in ("LESSONS", "RANKS", "INTELLIGENCE_GUIDE", "Smart Features Map", "Measure", "Compare", "Correlate", "Estimate", "AI", "Unknown is not Healthy", "Fast mode", "Complete mission", "I already know this", "user_training_progress", "XP earned", "Reset my training", "Skip unfinished", "Tikcentral Expert"):
        if marker not in training_text:
            fail(f"Interactive training feature missing: {marker}")
    if "training.register(app, ui.page)" not in (ROOT / "app/final.py").read_text(encoding="utf-8"):
        fail("Training routes are not registered")
    shared_ui_training = (ROOT / "app/ui.py").read_text(encoding="utf-8")
    for marker in ('("training", "/training", "Training")', "tc-training-grid", "tc-mission-list", "tc-smart-kind", "Smart help", "/training/intelligence-guide", "smartKind", "localPrefKey('ui:density')", "localPrefKey('ui:hide-guidance')", "tcRestoreGuidance", "CATEGORY_HOME"):
        if marker not in shared_ui_training:
            fail(f"Training/refined UI integration missing: {marker}")
    system_health_text = (ROOT / "app/system_health.py").read_text(encoding="utf-8")
    for marker in (
        "primary writable", "fallback writable", "scheduled backup not found; verified latest pre-update backup instead",
        "var(--ok)", 'verified["status"] == "warning"', "os.access(key, os.R_OK)",
        "os.access(helper, os.X_OK)", "DB_BACKUP_WARN_HOURS", "DB_BACKUP_CRITICAL_HOURS",
        "ROUTER_BACKUP_WARN_HOURS", "router_backup_verification", "backup age",
        "results.append((status, str(path)",
    ):
        if marker not in system_health_text:
            fail(f"System-health backup verification fix missing: {marker}")
    ui_copy_text = (ROOT / "app/ui.py").read_text(encoding="utf-8")
    if "hasAttribute('data-no-copy')" not in ui_copy_text:
        fail("No-copy fields can still receive automatic Copy buttons")
    for marker in (
        "localWallTime", "isDateHeader", "tc-date-range", 'type="datetime-local"',
        "installCellCopy", "cellTextForCopy", "tc-copy-priority", "Montréal local time",
        "does not contain", "op==='>='", "op==='<='",
    ):
        if marker not in ui_copy_text:
            fail(f"Shared table filter/copy capability missing: {marker}")
    alert_text = (ROOT / "app/alert_queue.py").read_text(encoding="utf-8")
    for marker in ('<th>Time</th>', 'last_seen_at', 'first_seen_at'):
        if marker not in alert_text:
            fail(f"Alert timestamp/filter support missing: {marker}")
    log_text = (ROOT / "app/log_patterns.py").read_text(encoding="utf-8")
    for marker in ('<th>Captured</th>', 'captured_at', 'LIMIT 1000'):
        if marker not in log_text:
            fail(f"Log-pattern history timestamp support missing: {marker}")
    main_text = (ROOT / "app/main.py").read_text(encoding="utf-8")
    if "Last handshake UTC" in main_text or "strftime(\"%Y-%m-%d %H:%M:%S\") if latest" in main_text:
        fail("Dashboard still exposes unlocalized handshake timestamps")
    reliability_text = (ROOT / "app/reliability.py").read_text(encoding="utf-8")
    if "format_montreal" not in reliability_text:
        fail("Support summary timestamps are not localized to Montreal")
    for path in (ROOT / "app").glob("*.py"):
        if "var(--green)" in path.read_text(encoding="utf-8"):
            fail(f"Stale pre-redesign healthy color token remains: {path.name}")
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
    for marker in ("Recovered interrupted upgrade job", "transaction_id=tx_id or None", 'if job["status"] == "running"'):
        if marker not in operations_resource:
            fail(f"Upgrade restart/verification recovery missing: {marker}")
    guardian_source = (ROOT / "app/guardian.py").read_text(encoding="utf-8")
    for marker in ("inactive_ids", "lifecycle_state", "Guardian no longer probes or escalates it"):
        if marker not in guardian_source:
            fail(f"Guardian retired/disabled suppression missing: {marker}")
    changes_text = (ROOT / "app/changes.py").read_text(encoding="utf-8")
    for marker in ("_render_diff", "_diff_counts", "Directly attributed to Tikcentral", "source_kind", "source_actor", "Semantic configuration diff", "semantic_config.compare", "Measured change impact", "Events in interval", "<th>Started</th>", "<th>Time</th>"):
        if marker not in changes_text:
            fail(f"Configuration history feature missing: {marker}")
    for path in (ROOT / "app").glob("*.py"):
        if "show-sensitive=no" in path.read_text(encoding="utf-8"):
            fail(f"Invalid RouterOS show-sensitive=no syntax returned: {path.name}")


def validate_ui_and_assets():
    rendered = ui.page(
        "Operations",
        '<div class="panel"><table data-default-hidden="0"><thead><tr><th>Status</th></tr></thead><tbody><tr><td>Healthy</td></tr></tbody></table></div>',
        {"email": "validator@opticable.local", "role": "admin"}, "operations",
    ).body.decode()
    for marker in (
        "tc-shell", "tc-sidebar", "tc-topbar", "tcCommandBtn", "tcPalette", "tcGlobalSearch",
        "tcToggleTheme", "tc-local-search", "tc-filter-column", "tc-filter-op", "tc-filter-value",
        "tc-filter-toggle", "Columns", "tcCopy", "Copy field value", "organizeRouterWorkspace",
        "tc-router-toolbox", "tc-workspace-tabs", "data-default-hidden", "tc-page-intro",
        "tcObjectContext", "installRouterContext", "installRecentRouters", "protectDirtyForms",
        "tcDensityToggle", "tcRestoreGuidance", "tcDisclosureToggle", "installDisclosureState",
        "tc-section-index", "data-workflow", "tc-date-range", "tc-date-from", "tc-date-to",
        "tc-date-column", "Montréal local time", "tc-cell-copy", "tc-copy-priority",
    ):
        if marker not in rendered:
            fail(f"Shared UI missing {marker}")
    login_rendered = ui.page("Sign in", '<div class="login">Login</div>', None).body.decode()
    if '<aside class="tc-sidebar"' in login_rendered or '<div class="tc-shell">' in login_rendered or 'id="tcCommandBtn"' in login_rendered:
        fail("Anonymous/login UI incorrectly renders authenticated application shell")
    if '<div class="login">Login</div>' not in login_rendered:
        fail("Anonymous/login UI content is missing")
    if not getattr(ui, "NAV_GROUPS", None) or len(ui.NAV) < 20:
        fail("Grouped navigation registry is missing or incomplete")
    converted = ui_time.format_montreal("2026-09-19T11:40:00+00:00", seconds=True)
    if converted != "2026-09-19 07:40:00 EDT":
        fail(f"Montreal timezone conversion failed: {converted}")
    legacy = ui_time.localize_html_iso_timestamps("<td>2026-09-19 11:40:00 UTC</td>")
    if "2026-09-19 07:40:00 EDT" not in legacy:
        fail("Legacy UTC timestamp was not converted to Montreal local time")
    protected_attr = '<input value="2026-09-19T11:40:00+00:00">'
    if ui_time.localize_html_iso_timestamps(protected_attr) != protected_attr:
        fail("Timestamp localization modified an HTML attribute value")
    raw_pre = '<pre>2026-09-19T11:40:00+00:00</pre>'
    if ui_time.localize_html_iso_timestamps(raw_pre) != raw_pre:
        fail("Timestamp localization modified raw preformatted technical output")
    form_values = core.FormValues({"router_ids": ["1", "2"], "name": ["campaign"]})
    if form_values.get("router_ids") != "2" or form_values.getlist("router_ids") != ["1", "2"]:
        fail("Multi-value form parser lost repeated values")
    route_counts, _ = routes()
    for group, items in ui.NAV_GROUPS:
        for key, href, label in items:
            if route_counts.get(("GET", href), 0) != 1:
                fail(f"Navigation destination missing: {group} / {label} -> {href}")
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
        "router_security_audit", "router_automation_inventory", "router_traffic_history",
        "router_capacity_forecast", "operator_notes", "customer_report_history",
        "router_topology_devices", "router_wan_probe_config", "router_wan_probe_history",
        "router_desired_state", "router_desired_state_status",
        "router_replacements", "maintenance_automation_settings", "maintenance_automation_runs", "alert_queue",
        "database_health_history",
        "retention_settings", "retention_cleanup_history",
        "commissioning_checklist_settings", "commissioning_checklist_status",
        "router_time_health", "router_mtu_history",
        "router_public_ip_analysis", "router_public_ip_sightings", "router_identity_collisions",
        "router_local_utilization", "router_model_capability_observations", "router_model_capability_catalog",
        "router_log_patterns", "router_hardware_lifecycle",
        "router_dns_health", "router_interface_negotiation", "router_wan_quality",
        "router_pppoe_history", "router_isp_gateway_history", "fleet_cross_site_anomalies",
        "change_impact_analysis", "user_training_progress",
    }
    with sqlite3.connect(settings.DB_PATH) as conn:
        version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        snapshot_columns = {r[1] for r in conn.execute("PRAGMA table_info(router_snapshots)")}
        ai_columns = {r[1] for r in conn.execute("PRAGMA table_info(router_ai_analyses)")}
        router_columns = {r[1] for r in conn.execute("PRAGMA table_info(routers)")}
        router_indexes = {r[1] for r in conn.execute("PRAGMA index_list(routers)")}
        site_columns = {r[1] for r in conn.execute("PRAGMA table_info(router_site_metadata)")}
        retention_columns = {r[1] for r in conn.execute("PRAGMA table_info(retention_settings)")}
    if version != expected or not required.issubset(tables):
        fail("Fresh migration schema validation failed")
    if not {"source_kind", "source_id", "source_actor"}.issubset(snapshot_columns):
        fail("Attributed snapshot schema validation failed")
    if not {"focus_start", "focus_end", "focus_note"}.issubset(ai_columns):
        fail("Incident AI schema validation failed")
    if not {"lifecycle_state", "lifecycle_updated_at", "lifecycle_updated_by"}.issubset(router_columns):
        fail("Router lifecycle schema validation failed")
    if "idx_routers_public_winbox_port_unique" not in router_indexes:
        fail("Public WinBox relay ports are not protected by a unique index")
    if not {"circuit_down_mbps", "circuit_up_mbps"}.issubset(site_columns):
        fail("Circuit capacity metadata schema validation failed")
    if not {"dns_health_days", "wan_quality_days", "pppoe_days", "isp_gateway_days"}.issubset(retention_columns):
        fail("Network quality retention schema validation failed")

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

    ai_id = ai_analysis.queue_analysis(9002, "validator", human_requested=True)
    if ai_analysis.queue_analysis(9002, "validator", human_requested=True) != ai_id:
        fail("AI analysis queue allowed duplicate pending work for one router")
    try:
        ai_analysis.queue_analysis(9001, "scheduler")
    except Exception:
        pass
    else:
        fail("AI analysis queue accepted a non-human backend trigger")

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
    for marker in ("install -d -o root -g tikcentral -m 0750", "chown root:tikcentral", "chmod 0640"):
        if marker not in backup_script:
            fail(f"Database backup verification permission missing: {marker}")
    update_text = (ROOT / "update.sh").read_text(encoding="utf-8")
    for marker in (
        "install -d -o root -g tikcentral -m 0750 /var/backups/tikcentral",
        "chown root:tikcentral \"$DB_BACKUP\"",
        "systemctl start tikcentral-backup.service",
        "system_health.verify_backups()",
        "system_health.record_health()",
        "find \"$ROUTER_BACKUP_DIR\" -type d -exec chmod 0750",
    ):
        if marker not in update_text:
            fail(f"Atomic updater backup-permission repair missing: {marker}")
    migrations_text = (ROOT / "app/migrations.py").read_text(encoding="utf-8")
    for marker in ("fcntl.flock", ".migrate.lock", "LOCK_EX"):
        if marker not in migrations_text:
            fail(f"Cross-process migration serialization missing: {marker}")
    updater_markers = (
        'DB_FILE="${DB_PATH:-/var/lib/tikcentral/tikcentral.db}"',
        "ACTIVATION_DB_BACKUP",
        "Quiesce every Tikcentral process",
        "pre-migration activation snapshot",
        'install -o tikcentral -g tikcentral -m 0640 "$ACTIVATION_DB_BACKUP" "$DB_FILE"',
    )
    for marker in updater_markers:
        if marker not in update_text:
            fail(f"Migration-safe updater rollback missing: {marker}")
    bootstrap_text = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
    if 'install -d -o root -g tikcentral -m 0750 "$BACKUP_DIR"' not in bootstrap_text:
        fail("Bootstrap backup-directory group permissions are unsafe for self-health verification")
    worker_text = (ROOT / "app/ai_worker.py").read_text(encoding="utf-8")
    if "router_ai_analyses" not in worker_text or "ai_analysis.run_codex" not in worker_text:
        fail("Persistent AI worker is not wired to the AI queue")
    for marker in ("_fail_ineligible_queued", "ROUTER_INACTIVE", "lifecycle_state"):
        if marker not in worker_text:
            fail(f"Inactive-router AI queue cleanup missing: {marker}")
    main_request_text = (ROOT / "app/main.py").read_text(encoding="utf-8")
    for marker in ("_read_limited_body", "request.stream()", "request body too large"):
        if marker not in main_request_text:
            fail(f"Request body size protection missing: {marker}")
    for marker in ("trigger_source='human_web'", 'human_requested: bool = False', "AI_HUMAN_TRIGGER_REQUIRED"):
        source = worker_text + (ROOT / "app/ai_analysis.py").read_text(encoding="utf-8")
        if marker not in source:
            fail(f"AI human-trigger control missing: {marker}")


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
