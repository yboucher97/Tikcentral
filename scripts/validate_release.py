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
    for marker in ("change_control.require_management", "change_control.begin", "operations.backup_router", "change_control.verify_management"):
        if marker not in production_text:
            fail(f"Web SSH bypasses transactional safety: {marker}")
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
        "router_maintenance", "fleet_incidents",
    }
    with sqlite3.connect(settings.DB_PATH) as conn:
        version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if version != expected or not required.issubset(tables):
        fail("Fresh migration schema validation failed")

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
