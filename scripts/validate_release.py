#!/usr/bin/env python3
"""Pre-deployment validation for one Tikcentral release.

The validator is fully sandboxed: DB_PATH is redirected to a temporary SQLite
file before any Tikcentral application module is imported. No router is contacted
and the production database is never opened.
"""

import ast
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

_VALIDATION_TMP = tempfile.TemporaryDirectory(prefix="tikcentral-release-test-")
os.environ["DB_PATH"] = str(Path(_VALIDATION_TMP.name) / "tikcentral.db")

from app import capabilities, enrollment_v2, jobs, migrations, performance_profile, router_exec, settings, ui
from app import main as core
from app.final import app

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_ROUTES = {
    "/enroll", "/enroll/generate", "/enroll/admin-credentials", "/routers", "/settings",
    "/automation", "/automation/command", "/automation/backup", "/automation/update/check",
    "/automation/update/install", "/ssh", "/ssh/{router_id}", "/guardian",
    "/guardian/{router_id}/repair", "/operations", "/operations/{router_id}",
    "/operations/{router_id}/commission", "/operations/{router_id}/telemetry",
    "/operations/{router_id}/profile/{profile}", "/operations/{router_id}/backup/{tier}",
    "/operations/{router_id}/drift/check", "/operations/{router_id}/baseline",
    "/operations/{router_id}/update/check", "/operations/{router_id}/upgrade/{mode}",
    "/operations/{router_id}/routerboot", "/operations/{router_id}/approve-version",
    "/rescue", "/rescue/{router_id}/enable", "/rescue/{router_id}/disable",
    "/changes", "/changes/{router_id}", "/audit", "/audit/{router_id}",
    "/audit/{router_id}/normalize",
}
OPERATIONS_POSTS = {
    "/operations/{router_id}/telemetry", "/operations/{router_id}/commission",
    "/operations/{router_id}/profile/{profile}", "/operations/{router_id}/backup/{tier}",
    "/operations/{router_id}/drift/check", "/operations/{router_id}/baseline",
    "/operations/{router_id}/update/check", "/operations/{router_id}/upgrade/{mode}",
    "/operations/{router_id}/routerboot", "/operations/{router_id}/approve-version",
}
RESCUE_POSTS = {"/rescue/{router_id}/enable", "/rescue/{router_id}/disable"}
FORBIDDEN_RUNTIME_MODULES = {
    "app.operations_safety", "app.operations_stability", "app.operations_compat",
    "app.operations_safe_routes", "app.operations_robust", "app.rescue_v2",
    "app.rescue_safe_routes", "app.ui_enhancements", "app.branding",
}


def route_matches(path: str, method: str | None = None):
    out = []
    for route in app.routes:
        if getattr(route, "path", None) != path:
            continue
        methods = getattr(route, "methods", set()) or set()
        if method is None or method in methods:
            out.append(route)
    return out


def validate_routes():
    existing = {getattr(r, "path", None) for r in app.routes}
    missing = sorted(REQUIRED_ROUTES - existing)
    if missing:
        raise SystemExit("Missing required route(s): " + ", ".join(missing))
    for path in OPERATIONS_POSTS:
        matches = route_matches(path, "POST")
        if len(matches) != 1 or matches[0].endpoint.__module__ != "app.operations":
            raise SystemExit(f"{path}: POST must be owned exactly once by app.operations")
    for path in RESCUE_POSTS:
        matches = route_matches(path, "POST")
        if len(matches) != 1 or matches[0].endpoint.__module__ != "app.rescue":
            raise SystemExit(f"{path}: POST must be owned exactly once by app.rescue")


def validate_runtime_composition():
    loaded = FORBIDDEN_RUNTIME_MODULES.intersection(sys.modules)
    if loaded:
        raise SystemExit("Legacy runtime patch module(s) imported: " + ", ".join(sorted(loaded)))
    from app import operations
    if operations.collect_telemetry.__module__ != "app.operations":
        raise SystemExit("Telemetry is not owned directly by app.operations")

    # Router SSH/SFTP subprocesses belong only in router_exec.py.
    for path in (ROOT / "app").glob("*.py"):
        if path.name == "router_exec.py":
            continue
        text = path.read_text(encoding="utf-8")
        if '"ssh"' not in text and "'ssh'" not in text and '"sftp"' not in text and "'sftp'" not in text:
            continue
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.List, ast.Tuple)):
                continue
            values = [elt.value for elt in node.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
            if "ssh" in values or "sftp" in values:
                raise SystemExit(f"Direct SSH/SFTP command outside router_exec.py: {path.name}")


def validate_ui():
    rendered = ui.page(
        "Operations",
        '<div class="panel"><table><thead><tr><th>Status</th></tr></thead><tbody><tr><td>Healthy</td></tr></tbody></table></div>',
        {"email": "validator@opticable.local"}, "operations",
    ).body.decode()
    for marker in (
        "tcGlobalSearch", "tcToggleTheme", "tc-local-search", "Columns ▾",
        settings.ASSETS["logo_light"], settings.ASSETS["logo_dark"], settings.ASSETS["icon"],
    ):
        if marker not in rendered:
            raise SystemExit(f"Shared UI validation failed: missing {marker}")
    for value in settings.ASSETS.values():
        relative = value.split("?", 1)[0].removeprefix("/static/")
        asset = ROOT / "app" / "static" / relative
        if not asset.is_file() or asset.stat().st_size == 0:
            raise SystemExit(f"Branding asset missing or empty: {asset}")


def validate_router_exec():
    normalized = router_exec.routeros_single_line("/system resource print\n/ip service print")
    if "/system resource print;" not in normalized or "/ip service print;" not in normalized:
        raise SystemExit("RouterOS command normalization failed")
    redacted = router_exec.sanitize('user=x password="supersecret" token=abc123')
    if "supersecret" in redacted or "abc123" in redacted or redacted.count("<redacted>") < 2:
        raise SystemExit("RouterOS secret redaction failed")


def validate_persistence_smoke():
    expected = len(migrations.MIGRATIONS)
    if migrations.migrate() != expected:
        raise SystemExit("Unexpected migration target version")
    if migrations.migrate() != expected:
        raise SystemExit("Migrations are not idempotent")
    with sqlite3.connect(settings.DB_PATH) as conn:
        version = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        required_tables = {"routers", "router_jobs", "router_capabilities", "router_telemetry", "router_events"}
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if version != expected or not required_tables.issubset(tables):
        raise SystemExit("Fresh migration schema validation failed")

    cap = capabilities.set_mode(9001, capabilities.OPTICABLE_DEFAULT, "2026-01-01T00:00:00+00:00", "smoke-test")
    if not cap.supports_performance_profiles or not cap.managed_baseline:
        raise SystemExit("Typed capability persistence failed")
    cap2 = capabilities.set_mode(9002, capabilities.TIKCENTRAL_ONLY, "2026-01-01T00:00:00+00:00", "smoke-test")
    if cap2.supports_performance_profiles or cap2.managed_baseline:
        raise SystemExit("Tikcentral-only capability policy failed")

    job_id = jobs.create(9001, "smoke_mutation", "validator", serialize_router=True)
    jobs.running(job_id)
    jobs.verifying(job_id)
    jobs.succeeded(job_id)
    if jobs.get(job_id)["status"] != "succeeded":
        raise SystemExit("Unified job lifecycle smoke test failed")
    try:
        jobs.running(job_id)
    except Exception:
        pass
    else:
        raise SystemExit("Terminal job accepted an invalid state transition")

    with jobs.operation(9002, "smoke_context", "validator") as context_job:
        jobs.verifying(context_job)
    if jobs.get(context_job)["status"] != "succeeded":
        raise SystemExit("Unified job context manager smoke test failed")


def validate_updater_launcher():
    launcher = ROOT / "helpers" / "tikcentral-update"
    if not launcher.is_file() or "repository.git" not in launcher.read_text(encoding="utf-8"):
        raise SystemExit("Stable updater launcher is missing or invalid")


def validate_provisioning():
    script = performance_profile.performance_ready_default_config_script(
        "release-validation", 12, 4, 500, 500, 80, 40, "ether2"
    )
    script = enrollment_v2._apply_profile(script, "throughput")
    for marker in (
        "Default WAN DHCP", "Bell PPPoE - enter credentials onsite", "Opticable FastTrack",
        "Opticable RAW", "Opticable MSS clamp", "OPT-QOS-UPLOAD",
        "Performance profile active: Maximum throughput",
    ):
        if marker not in script:
            raise SystemExit(f"Provisioning validation failed: missing {marker}")


def main():
    validate_routes()
    validate_runtime_composition()
    validate_ui()
    validate_router_exec()
    validate_persistence_smoke()
    validate_updater_launcher()
    validate_provisioning()
    print("Tikcentral release validation: OK")


if __name__ == "__main__":
    try:
        main()
    finally:
        _VALIDATION_TMP.cleanup()
