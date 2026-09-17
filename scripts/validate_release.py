#!/usr/bin/env python3
"""Offline release validation for Tikcentral.

The production DB is never opened and no router is contacted. A candidate must
pass this gate before the atomic current symlink moves.
"""

import ast
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

_VALIDATION_TMP = tempfile.TemporaryDirectory(prefix="tikcentral-release-test-")
os.environ["DB_PATH"] = str(Path(_VALIDATION_TMP.name) / "tikcentral.db")

from app import capabilities
from app import errors
from app import events
from app import fleet
from app import fleet_health
from app import jobs
from app import management_script
from app import migrations
from app import performance_profile
from app import router_exec
from app import scheduler
from app import settings
from app import ui
from app import main as core
from app.final import app

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_ROUTES = {
    ("GET", "/"), ("GET", "/login"), ("POST", "/login"),
    ("GET", "/routers"), ("GET", "/settings"),
    ("GET", "/enroll"), ("POST", "/enroll/generate"), ("POST", "/enroll/admin-credentials"),
    ("GET", "/automation"), ("POST", "/automation/settings"),
    ("POST", "/automation/backup"), ("POST", "/automation/analyze"),
    ("GET", "/automation/jobs/{job_id}"),
    ("GET", "/ssh"), ("GET", "/ssh/{router_id}"), ("POST", "/ssh/{router_id}"),
    ("GET", "/guardian"), ("POST", "/guardian/{router_id}/repair"),
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


def route_counts():
    counts = {}
    owners = {}
    for route in app.routes:
        path = getattr(route, "path", None)
        if not path:
            continue
        for method in (getattr(route, "methods", set()) or set()):
            key = (method, path)
            counts[key] = counts.get(key, 0) + 1
            owners[key] = getattr(getattr(route, "endpoint", None), "__module__", "")
    return counts, owners


def validate_routes():
    counts, owners = route_counts()
    for route in REQUIRED_ROUTES:
        if counts.get(route) != 1:
            raise SystemExit(f"Route {route} count={counts.get(route, 0)}, expected exactly 1")
    duplicates = sorted((key, count) for key, count in counts.items() if count > 1 and key[0] not in {"HEAD", "OPTIONS"})
    if duplicates:
        raise SystemExit(f"Duplicate method/path routes detected: {duplicates}")

    expected_owners = {
        ("POST", "/enroll/generate"): "app.enrollment",
        ("POST", "/enroll/admin-credentials"): "app.enrollment",
        ("POST", "/rescue/{router_id}/enable"): "app.rescue",
        ("POST", "/rescue/{router_id}/disable"): "app.rescue",
        ("POST", "/ssh/{router_id}"): "app.production",
    }
    for path in (
        "/operations/{router_id}/telemetry", "/operations/{router_id}/commission",
        "/operations/{router_id}/profile/{profile}", "/operations/{router_id}/backup/{tier}",
        "/operations/{router_id}/drift/check", "/operations/{router_id}/baseline",
        "/operations/{router_id}/update/check", "/operations/{router_id}/upgrade/{mode}",
        "/operations/{router_id}/routerboot", "/operations/{router_id}/approve-version",
    ):
        expected_owners[("POST", path)] = "app.operations"
    for key, expected in expected_owners.items():
        if owners.get(key) != expected:
            raise SystemExit(f"{key}: owner={owners.get(key)!r}, expected {expected}")

    forbidden_routes = {
        ("POST", "/automation/command"),
        ("POST", "/automation/update/check"),
        ("POST", "/automation/update/install"),
    }
    present = forbidden_routes.intersection(counts)
    if present:
        raise SystemExit(f"Legacy fleet mutation route(s) returned: {sorted(present)}")


def validate_source_boundaries():
    for relative in FORBIDDEN_FILES:
        if (ROOT / relative).exists():
            raise SystemExit(f"Legacy/redundant file returned: {relative}")

    app_files = list((ROOT / "app").glob("*.py"))
    for path in app_files:
        text = path.read_text(encoding="utf-8")

        # Only settings.py parses environment variables.
        if path.name != "settings.py" and ("os.getenv(" in text or "os.environ[" in text):
            raise SystemExit(f"Direct environment access outside settings.py: {path.name}")

        # Only migrations.py owns persistent schema DDL.
        if path.name != "migrations.py":
            upper = text.upper()
            if "CREATE TABLE" in upper or "ALTER TABLE" in upper:
                raise SystemExit(f"Schema DDL outside migrations.py: {path.name}")

        # Only jobs.py/migrations.py mutate the serialized router job table.
        if path.name not in {"jobs.py", "migrations.py"}:
            lower = text.lower()
            for verb in ("insert into router_jobs", "update router_jobs", "delete from router_jobs"):
                if verb in lower:
                    raise SystemExit(f"Direct router_jobs mutation outside jobs.py: {path.name}")

        # Router SSH/SFTP subprocesses belong only in router_exec.py.
        if path.name != "router_exec.py" and any(token in text for token in ('"ssh"', "'ssh'", '"sftp"', "'sftp'")):
            tree = ast.parse(text, filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.List, ast.Tuple)):
                    continue
                values = [elt.value for elt in node.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
                if "ssh" in values or "sftp" in values:
                    raise SystemExit(f"Direct SSH/SFTP command outside router_exec.py: {path.name}")

        # The old route/render monkey-patch model must not return.
        forbidden_fragments = (
            "app.router.routes[:]", "portal.portal_page =", "production.production_page =",
            "fleet_web.fleet_page =", "core.page =", "run_mass_command(",
        )
        if path.name != "main.py" and any(fragment in text for fragment in forbidden_fragments):
            raise SystemExit(f"Legacy runtime patch/mass mutation pattern in {path.name}")


def validate_ui_assets():
    rendered = ui.page(
        "Operations",
        '<div class="panel"><table><thead><tr><th>Status</th></tr></thead><tbody><tr><td>Healthy</td></tr></tbody></table></div>',
        {"email": "validator@opticable.local"},
        "operations",
    ).body.decode()
    for marker in ("tcGlobalSearch", "tcToggleTheme", "tc-local-search", "Columns ▾"):
        if marker not in rendered:
            raise SystemExit(f"Shared UI validation failed: missing {marker}")
    if set(settings.ASSET_FILES) != {"logo_light", "logo_dark", "icon"}:
        raise SystemExit("Asset manifest keys changed unexpectedly")
    for key, filename in settings.ASSET_FILES.items():
        asset = ROOT / "app" / "static" / filename
        if not asset.is_file() or asset.stat().st_size == 0:
            raise SystemExit(f"Asset missing/empty: {asset}")
        expected_url = f"/static/{filename}?v={settings.ASSET_VERSION}"
        if settings.ASSETS.get(key) != expected_url or expected_url not in rendered:
            raise SystemExit(f"Asset manifest/cache mismatch for {key}")


def validate_router_execution_and_management_script():
    normalized = router_exec.routeros_single_line("/system resource print\n/ip service print")
    if "/system resource print;" not in normalized or "/ip service print;" not in normalized:
        raise SystemExit("RouterOS command normalization failed")
    redacted = router_exec.sanitize('user=x password="supersecret" token=abc123')
    if "supersecret" in redacted or "abc123" in redacted or redacted.count("<redacted>") < 2:
        raise SystemExit("RouterOS secret redaction failed")
    if errors.from_exception(PermissionError("nope")).code != errors.Code.PERMISSION_DENIED:
        raise SystemExit("Structured permission error mapping failed")

    script = management_script.build_routeros_script("validator", "validator-token-123456789")
    required = (
        'name="tikcentral"', "10.250.0.1/32", "Tikcentral management TCP",
        "Tikcentral admin TCP", "Tikcentral admin ICMP", "/api/enroll",
        "dst-port=22,8291,8728", "dst-port=22,8291",
    )
    for marker in required:
        if marker not in script:
            raise SystemExit(f"Management enrollment script missing: {marker}")
    if 'name="winbox"] disabled=no address=10.250.0.1/32' in script or 'name="ssh"] disabled=no address=10.250.0.1/32' in script:
        raise SystemExit("Management script would overwrite local WinBox/SSH address access")


def validate_persistence_and_jobs():
    expected = len(migrations.MIGRATIONS)
    if migrations.migrate() != expected or migrations.migrate() != expected:
        raise SystemExit("Migrations are not deterministic/idempotent")
    required_tables = {
        "routers", "router_jobs", "router_capabilities", "router_telemetry", "router_events",
        "fleet_settings", "fleet_jobs", "fleet_job_results", "router_snapshots", "fleet_findings",
    }
    with sqlite3.connect(settings.DB_PATH) as conn:
        version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if version != expected or not required_tables.issubset(tables):
        raise SystemExit("Fresh migration schema validation failed")

    cap = capabilities.set_mode(9001, capabilities.OPTICABLE_DEFAULT, "2026-01-01T00:00:00+00:00", "smoke-test")
    if not cap.supports_performance_profiles or not cap.managed_baseline:
        raise SystemExit("Typed capability persistence failed")

    with core.db() as conn:
        for rid in (9001, 9002):
            conn.execute(
                "INSERT OR REPLACE INTO routers(id,site_name,public_key,vpn_ip,created_at,enabled) VALUES(?,?,?,?,?,1)",
                (rid, f"Smoke {rid}", f"key-{rid}", f"10.250.250.{rid-9000}", "2026-01-01T00:00:00+00:00"),
            )
            conn.execute(
                """INSERT OR REPLACE INTO router_access_state
                   (router_id,checked_at,wg_online,ssh_open,winbox_open,api_open,management_ok,last_good_at,last_error)
                   VALUES(?, ?,1,1,1,1,1,?,'')""",
                (rid, "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
            )

    job_id = jobs.create(9001, "smoke_mutation", "validator", serialize_router=True)
    jobs.running(job_id)
    if 9001 in scheduler._eligible_healthy_router_ids() or 9002 not in scheduler._eligible_healthy_router_ids():
        raise SystemExit("Read/change scheduler isolation failed")
    if fleet_health.get(9001).state != fleet_health.CHANGE_IN_PROGRESS:
        raise SystemExit("Fleet health does not surface active router change")
    jobs.verifying(job_id)
    jobs.succeeded(job_id)
    if fleet_health.get(9001).state != fleet_health.HEALTHY:
        raise SystemExit("Fleet health did not return to Healthy")
    try:
        jobs.running(job_id)
    except Exception:
        pass
    else:
        raise SystemExit("Terminal job accepted an invalid transition")

    if hasattr(fleet, "run_mass_command"):
        raise SystemExit("Generic fleet mass mutation helper returned")


def validate_events_and_optional_boundaries():
    before = 0
    with core.db() as conn:
        before = conn.execute("SELECT COUNT(*) FROM router_events").fetchone()[0]
    events.record(9001, "telemetry", "Telemetry collected: CPU 5%", severity="info")
    with core.db() as conn:
        after = conn.execute("SELECT COUNT(*) FROM router_events").fetchone()[0]
    if after != before:
        raise SystemExit("Routine telemetry success polluted event timeline")

    runner = (ROOT / "app" / "fleet_runner.py").read_text(encoding="utf-8")
    guardian_pos = runner.find("guardian.guardian_tick()")
    scheduler_pos = runner.find("scheduler.scheduled_tick()")
    if guardian_pos < 0 or scheduler_pos < 0 or guardian_pos > scheduler_pos:
        raise SystemExit("Guardian is no longer first in the scheduled critical path")


def validate_provisioning():
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
            raise SystemExit(f"Provisioning validation failed: missing {marker}")


def validate_updater():
    launcher = ROOT / "helpers" / "tikcentral-update"
    if not launcher.is_file() or "repository.git" not in launcher.read_text(encoding="utf-8"):
        raise SystemExit("Stable updater launcher missing/invalid")


def main():
    validate_routes()
    validate_source_boundaries()
    validate_ui_assets()
    validate_router_execution_and_management_script()
    validate_persistence_and_jobs()
    validate_events_and_optional_boundaries()
    validate_provisioning()
    validate_updater()
    print(f"Tikcentral release validation: OK · schema v{len(migrations.MIGRATIONS)} · {len(app.routes)} routes")


if __name__ == "__main__":
    try:
        main()
    finally:
        _VALIDATION_TMP.cleanup()
