"""Single source of truth for Tikcentral runtime configuration.

All application modules consume environment-derived values from this module so
safe defaults, validation and deployment behavior cannot silently diverge.
"""

import ipaddress
import os
from pathlib import Path


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _int(name: str, default: int, *, minimum: int = 0, maximum: int | None = None) -> int:
    value = int(os.getenv(name, str(default)))
    if value < minimum or (maximum is not None and value > maximum):
        high = maximum if maximum is not None else "unbounded"
        raise RuntimeError(f"{name} must be between {minimum} and {high}")
    return value


# Core application / identity.
DB_PATH = os.getenv("DB_PATH", "/var/lib/tikcentral/tikcentral.db")
TIMEZONE = os.getenv("TIKCENTRAL_TIMEZONE", "America/Toronto")
ADMIN_API_KEY = _required("ADMIN_API_KEY")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
BOOTSTRAP_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
SESSION_DAYS = _int("SESSION_DAYS", 7, minimum=1, maximum=90)
TOKEN_TTL_HOURS = _int("TOKEN_TTL_HOURS", 24, minimum=1, maximum=168)
TEMP_ACCESS_DAYS = _int("TEMP_ACCESS_DAYS", 5, minimum=1, maximum=90)

# WireGuard management overlay.
WG_HELPER = os.getenv("WG_HELPER", "/usr/local/sbin/tikcentral-wg-peer")
WG_SERVER_PUBLIC_KEY = _required("WG_SERVER_PUBLIC_KEY")
WG_ENDPOINT = _required("WG_ENDPOINT")
WG_ROUTER_POOL = ipaddress.ip_network(os.getenv("WG_ROUTER_POOL", "10.250.1.0/24"))
WG_ALLOWED_NETWORK = os.getenv("WG_ALLOWED_NETWORK", "10.250.0.0/16")
ONLINE_SECONDS = _int("ONLINE_SECONDS", 180, minimum=30, maximum=3600)
WG_HELPER_TIMEOUT = _int("TIKCENTRAL_WG_HELPER_TIMEOUT", 10, minimum=2, maximum=120)
PUBLIC_HOSTNAME = os.getenv("PUBLIC_HOSTNAME", WG_ENDPOINT.rsplit(":", 1)[0])

# Public WinBox relay.
WINBOX_PUBLIC_PORT_MIN = _int("WINBOX_PUBLIC_PORT_MIN", 20000, minimum=1024, maximum=65535)
WINBOX_PUBLIC_PORT_MAX = _int("WINBOX_PUBLIC_PORT_MAX", 49999, minimum=1024, maximum=65535)
if WINBOX_PUBLIC_PORT_MAX < WINBOX_PUBLIC_PORT_MIN:
    raise RuntimeError("WINBOX_PUBLIC_PORT_MAX must be >= WINBOX_PUBLIC_PORT_MIN")
WINBOX_BIND_HOST = os.getenv("WINBOX_BIND_HOST", "0.0.0.0")
WINBOX_TARGET_PORT = _int("WINBOX_TARGET_PORT", 8291, minimum=1, maximum=65535)
WINBOX_RESCAN_SECONDS = _int("WINBOX_RESCAN_SECONDS", 10, minimum=2, maximum=300)
WINBOX_CONNECT_TIMEOUT = _int("TIKCENTRAL_WINBOX_CONNECT_TIMEOUT", 8, minimum=1, maximum=60)

# Managed router identity / RouterOS execution.
SSH_USER = os.getenv("TIKCENTRAL_ROUTER_USER", "tikcentral")
SSH_KEY = os.getenv("TIKCENTRAL_SSH_KEY", "/etc/tikcentral/ssh/tikcentral_ed25519")
KNOWN_HOSTS = os.getenv("TIKCENTRAL_KNOWN_HOSTS", "/var/lib/tikcentral/known_hosts")
SSH_TIMEOUT = _int("TIKCENTRAL_SSH_TIMEOUT", 20, minimum=3, maximum=300)
READ_RETRIES = _int("TIKCENTRAL_READ_RETRIES", 1, minimum=0, maximum=3)
MUTATION_TIMEOUT = _int("TIKCENTRAL_MUTATION_TIMEOUT", 90, minimum=10, maximum=3600)
MAX_COMMAND_LENGTH = _int("TIKCENTRAL_MAX_COMMAND_LENGTH", 200000, minimum=1000, maximum=1000000)
ROUTER_API_PASSWORD = os.getenv("TIKCENTRAL_ROUTER_API_PASSWORD", "")
PROVISIONING_KEY = os.getenv("TIKCENTRAL_PROVISIONING_KEY", "")

# Fleet concurrency. Read-only work never consumes a router mutation slot.
MAX_WORKERS = _int("TIKCENTRAL_FLEET_WORKERS", 8, minimum=1, maximum=32)
TELEMETRY_WORKERS = _int("TIKCENTRAL_TELEMETRY_WORKERS", 6, minimum=1, maximum=16)
DRIFT_WORKERS = _int("TIKCENTRAL_DRIFT_WORKERS", 3, minimum=1, maximum=8)

# Backups.
BACKUP_ROOT = Path(os.getenv("ROUTER_BACKUP_DIR", "/var/backups/tikcentral/routers"))
BACKUP_FALLBACK_ROOT = Path(os.getenv("TIKCENTRAL_BACKUP_FALLBACK", "/var/lib/tikcentral/router-backups"))
BACKUP_PASSWORD = os.getenv("ROUTER_BACKUP_PASSWORD", "")

# Scheduler / retention.
TELEMETRY_INTERVAL_SECONDS = _int("TIKCENTRAL_TELEMETRY_INTERVAL", 300, minimum=60)
DRIFT_INTERVAL_SECONDS = _int("TIKCENTRAL_DRIFT_INTERVAL", 1800, minimum=300)
TELEMETRY_RETENTION_ROWS = _int("TIKCENTRAL_TELEMETRY_RETENTION_ROWS", 9000, minimum=100)
GUARDIAN_RETENTION_ROWS = _int("TIKCENTRAL_GUARDIAN_RETENTION_ROWS", 45000, minimum=100)
EVENT_RETENTION_ROWS = _int("TIKCENTRAL_EVENT_RETENTION_ROWS", 5000, minimum=100)
EVENT_INFO_RETENTION_ROWS = _int("TIKCENTRAL_EVENT_INFO_RETENTION_ROWS", 750, minimum=50)
EVENT_DEDUP_SECONDS = _int("TIKCENTRAL_EVENT_DEDUP_SECONDS", 300, minimum=30, maximum=86400)

# Probe/change deadlines.
CORE_TELEMETRY_TIMEOUT = _int("TIKCENTRAL_CORE_TELEMETRY_TIMEOUT", 12, minimum=3, maximum=120)
ROUTERBOOT_TELEMETRY_TIMEOUT = _int("TIKCENTRAL_ROUTERBOOT_TELEMETRY_TIMEOUT", 8, minimum=3, maximum=120)
POLICY_PROBE_TIMEOUT = _int("TIKCENTRAL_POLICY_PROBE_TIMEOUT", 8, minimum=3, maximum=120)
DRIFT_EXPORT_TIMEOUT = _int("TIKCENTRAL_DRIFT_EXPORT_TIMEOUT", 90, minimum=10, maximum=600)
UPDATE_CHECK_TIMEOUT = _int("TIKCENTRAL_UPDATE_CHECK_TIMEOUT", 90, minimum=10, maximum=600)
ROUTEROS_RETURN_TIMEOUT = _int("TIKCENTRAL_ROUTEROS_RETURN_TIMEOUT", 1200, minimum=120, maximum=3600)
ROUTERBOOT_RETURN_TIMEOUT = _int("TIKCENTRAL_ROUTERBOOT_RETURN_TIMEOUT", 900, minimum=120, maximum=3600)

# Static local Rescue profile.
RESCUE_ADDRESS = os.getenv("TIKCENTRAL_RESCUE_ADDRESS", "10.255.255.1/24")
RESCUE_NETWORK = os.getenv("TIKCENTRAL_RESCUE_NETWORK", "10.255.255.0/24")
RESCUE_POOL = os.getenv("TIKCENTRAL_RESCUE_POOL", "10.255.255.100-10.255.255.200")
RESCUE_DNS = os.getenv("TIKCENTRAL_RESCUE_DNS", "1.1.1.1")

# One logical asset manifest. Cache version changes once per asset set, not per file.
ASSET_VERSION = os.getenv("TIKCENTRAL_ASSET_VERSION", "7").strip() or "7"
ASSET_FILES = {
    "logo_light": "opticable-logo-light.svg",
    "logo_dark": "opticable-logo-dark.svg",
    "icon": "opticable-icon.png",
}
ASSETS = {key: f"/static/{filename}?v={ASSET_VERSION}" for key, filename in ASSET_FILES.items()}
