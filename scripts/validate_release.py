#!/usr/bin/env python3
"""Pre-deployment validation for one Tikcentral release.

This deliberately validates only the consolidated runtime. Old compatibility
modules may remain in git history, but a production release must not import them.
"""

from pathlib import Path
import sys

from fastapi.routing import APIRoute

from app import enrollment_v2, performance_profile, settings, ui
from app.final import app


REQUIRED_ROUTES = {
    "/enroll",
    "/enroll/generate",
    "/enroll/admin-credentials",
    "/routers",
    "/settings",
    "/automation",
    "/automation/command",
    "/automation/backup",
    "/automation/update/check",
    "/automation/update/install",
    "/ssh",
    "/ssh/{router_id}",
    "/guardian",
    "/guardian/{router_id}/repair",
    "/operations",
    "/operations/{router_id}",
    "/operations/{router_id}/commission",
    "/operations/{router_id}/telemetry",
    "/operations/{router_id}/profile/{profile}",
    "/operations/{router_id}/backup/{tier}",
    "/operations/{router_id}/drift/check",
    "/operations/{router_id}/baseline",
    "/operations/{router_id}/update/check",
    "/operations/{router_id}/upgrade/{mode}",
    "/operations/{router_id}/routerboot",
    "/operations/{router_id}/approve-version",
    "/rescue",
    "/rescue/{router_id}/enable",
    "/rescue/{router_id}/disable",
    "/changes",
    "/changes/{router_id}",
    "/audit",
    "/audit/{router_id}",
    "/audit/{router_id}/normalize",
}

OPERATIONS_POSTS = {
    "/operations/{router_id}/telemetry",
    "/operations/{router_id}/commission",
    "/operations/{router_id}/profile/{profile}",
    "/operations/{router_id}/backup/{tier}",
    "/operations/{router_id}/drift/check",
    "/operations/{router_id}/baseline",
    "/operations/{router_id}/update/check",
    "/operations/{router_id}/upgrade/{mode}",
    "/operations/{router_id}/routerboot",
    "/operations/{router_id}/approve-version",
}

RESCUE_POSTS = {
    "/rescue/{router_id}/enable",
    "/rescue/{router_id}/disable",
}

FORBIDDEN_RUNTIME_MODULES = {
    "app.operations_safety",
    "app.operations_stability",
    "app.operations_compat",
    "app.operations_safe_routes",
    "app.operations_robust",
    "app.rescue_v2",
    "app.rescue_safe_routes",
    "app.ui_enhancements",
    "app.branding",
}


def route_matches(path: str, method: str | None = None):
    found = []
    for route in app.routes:
        if getattr(route, "path", None) != path:
            continue
        methods = getattr(route, "methods", set()) or set()
        if method is None or method in methods:
            found.append(route)
    return found


def validate_routes():
    existing = {getattr(r, "path", None) for r in app.routes}
    missing = sorted(REQUIRED_ROUTES - existing)
    if missing:
        raise SystemExit("Missing required route(s): " + ", ".join(missing))

    for path in OPERATIONS_POSTS:
        matches = route_matches(path, "POST")
        if len(matches) != 1:
            raise SystemExit(f"{path}: expected exactly one POST handler, found {len(matches)}")
        if matches[0].endpoint.__module__ != "app.operations":
            raise SystemExit(f"{path}: handler is {matches[0].endpoint.__module__}, expected app.operations")

    for path in RESCUE_POSTS:
        matches = route_matches(path, "POST")
        if len(matches) != 1:
            raise SystemExit(f"{path}: expected exactly one POST handler, found {len(matches)}")
        if matches[0].endpoint.__module__ != "app.rescue":
            raise SystemExit(f"{path}: handler is {matches[0].endpoint.__module__}, expected app.rescue")


def validate_runtime_composition():
    loaded = FORBIDDEN_RUNTIME_MODULES.intersection(sys.modules)
    if loaded:
        raise SystemExit("Legacy runtime patch module(s) imported: " + ", ".join(sorted(loaded)))

    from app import operations
    if operations.collect_telemetry.__module__ != "app.operations":
        raise SystemExit("Telemetry is not owned directly by app.operations")


def validate_ui():
    rendered = ui.page(
        "Operations",
        '<div class="panel"><table><thead><tr><th>Status</th></tr></thead><tbody><tr><td>Healthy</td></tr></tbody></table></div>',
        {"email": "validator@opticable.local"},
        "operations",
    ).body.decode()
    for marker in (
        "tcGlobalSearch",
        "tcToggleTheme",
        "tc-local-search",
        "Columns ▾",
        settings.ASSETS["logo_light"],
        settings.ASSETS["logo_dark"],
        settings.ASSETS["icon"],
    ):
        if marker not in rendered:
            raise SystemExit(f"Shared UI validation failed: missing {marker}")

    root = Path(__file__).resolve().parents[1]
    for value in settings.ASSETS.values():
        relative = value.split("?", 1)[0].removeprefix("/static/")
        asset = root / "app" / "static" / relative
        if not asset.is_file() or asset.stat().st_size == 0:
            raise SystemExit(f"Branding asset missing or empty: {asset}")


def validate_provisioning():
    script = performance_profile.performance_ready_default_config_script(
        "release-validation", 12, 4, 500, 500, 80, 40, "ether2"
    )
    script = enrollment_v2._apply_profile(script, "throughput")
    required = (
        "Default WAN DHCP",
        "Bell PPPoE - enter credentials onsite",
        "Opticable FastTrack",
        "Opticable RAW",
        "Opticable MSS clamp",
        "OPT-QOS-UPLOAD",
        "Performance profile active: Maximum throughput",
    )
    for marker in required:
        if marker not in script:
            raise SystemExit(f"Provisioning validation failed: missing {marker}")


def main():
    validate_routes()
    validate_runtime_composition()
    validate_ui()
    validate_provisioning()
    print("Tikcentral release validation: OK")


if __name__ == "__main__":
    main()
