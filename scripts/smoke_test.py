#!/usr/bin/env python3
"""Offline/pre-restart smoke tests for a staged Tikcentral release."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import migrations, operations, rescue, router_exec, settings, ui
from app.final import app
from app.performance_profile import performance_ready_default_config_script
from app.enrollment_v2 import _apply_profile


def fail(msg):
    raise SystemExit("SMOKE TEST FAILED: " + msg)


version = migrations.current_version()
if version < 4:
    fail(f"schema version {version} < 4")

required = {
    ("GET", "/operations"), ("GET", "/operations/{router_id}"),
    ("POST", "/operations/{router_id}/telemetry"),
    ("POST", "/operations/{router_id}/commission"),
    ("POST", "/operations/{router_id}/profile/{profile}"),
    ("POST", "/operations/{router_id}/backup/{tier}"),
    ("POST", "/operations/{router_id}/drift/check"),
    ("POST", "/operations/{router_id}/baseline"),
    ("POST", "/operations/{router_id}/update/check"),
    ("POST", "/operations/{router_id}/upgrade/{mode}"),
    ("POST", "/operations/{router_id}/routerboot"),
    ("POST", "/operations/{router_id}/approve-version"),
    ("GET", "/rescue"), ("POST", "/rescue/{router_id}/enable"), ("POST", "/rescue/{router_id}/disable"),
    ("GET", "/guardian"), ("POST", "/guardian/{router_id}/repair"),
    ("GET", "/enroll"), ("POST", "/enroll/generate"),
    ("GET", "/changes"), ("GET", "/audit"), ("GET", "/ssh"), ("GET", "/automation"),
}
route_counts = {}
for route in app.routes:
    path = getattr(route, "path", None)
    for method in (getattr(route, "methods", set()) or set()):
        route_counts[(method, path)] = route_counts.get((method, path), 0) + 1
for item in required:
    if route_counts.get(item) != 1:
        fail(f"route {item} count={route_counts.get(item,0)}, expected 1")

if operations.collect_telemetry.__module__ != "app.operations":
    fail("Operations telemetry is patched by another module")
if rescue.enable_rescue.__module__ != "app.rescue":
    fail("Rescue implementation is patched by another module")
if router_exec.execute.__module__ != "app.router_exec":
    fail("Router execution layer is not centralized")

legacy_runtime = {
    "app.operations_stability", "app.operations_compat", "app.operations_safety",
    "app.operations_safe_routes", "app.operations_robust", "app.rescue_v2",
    "app.rescue_safe_routes", "app.backup_tiers", "app.guardian_events",
    "app.branding", "app.ui_enhancements",
}
loaded = legacy_runtime.intersection(sys.modules)
if loaded:
    fail("legacy runtime patches loaded: " + ", ".join(sorted(loaded)))

page = ui.page("Smoke", '<div class="panel"><table><thead><tr><th>A</th></tr></thead><tbody><tr><td>Healthy</td></tr></tbody></table></div>', {"email":"smoke@example.invalid"}, "operations").body.decode()
for marker in ("tcGlobalSearch", "tcToggleTheme", settings.ASSETS["logo_light"], settings.ASSETS["logo_dark"], "Columns"):
    if marker not in page:
        fail("UI marker missing: " + marker)

for name in ("opticable-logo-light.svg", "opticable-logo-dark.svg", "opticable-icon.png"):
    if not (ROOT / "app" / "static" / name).is_file():
        fail("branding asset missing: " + name)

script = _apply_profile(performance_ready_default_config_script("smoke", 12, 4, 500, 500, 80, 40, "ether2"), "throughput")
for marker in ("Default WAN DHCP", "Bell PPPoE - enter credentials onsite", "Opticable FastTrack", "Opticable MSS clamp", "OPT-QOS-UPLOAD"):
    if marker not in script:
        fail("provisioning marker missing: " + marker)

print(f"Tikcentral smoke tests passed · schema v{version} · {len(app.routes)} routes")
