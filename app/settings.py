"""Central Tikcentral runtime settings.

Operational defaults live here so web, scheduler, RouterOS execution and
deployment validation cannot silently drift apart. Environment variables may
override deployment-specific values; safe product defaults remain explicit.
"""

import os
from pathlib import Path


def _int(name: str, default: int, *, minimum: int = 0, maximum: int | None = None) -> int:
    value = int(os.getenv(name, str(default)))
    if value < minimum or (maximum is not None and value > maximum):
        raise RuntimeError(f"{name} must be between {minimum} and {maximum if maximum is not None else 'unbounded'}")
    return value


DB_PATH = os.getenv("DB_PATH", "/var/lib/tikcentral/tikcentral.db")
TIMEZONE = os.getenv("TIKCENTRAL_TIMEZONE", "America/Toronto")

SSH_USER = os.getenv("TIKCENTRAL_ROUTER_USER", "tikcentral")
SSH_KEY = os.getenv("TIKCENTRAL_SSH_KEY", "/etc/tikcentral/ssh/tikcentral_ed25519")
KNOWN_HOSTS = os.getenv("TIKCENTRAL_KNOWN_HOSTS", "/var/lib/tikcentral/known_hosts")
SSH_TIMEOUT = _int("TIKCENTRAL_SSH_TIMEOUT", 20, minimum=3, maximum=300)
READ_RETRIES = _int("TIKCENTRAL_READ_RETRIES", 1, minimum=0, maximum=3)
MUTATION_TIMEOUT = _int("TIKCENTRAL_MUTATION_TIMEOUT", 90, minimum=10, maximum=3600)
MAX_COMMAND_LENGTH = _int("TIKCENTRAL_MAX_COMMAND_LENGTH", 200000, minimum=1000, maximum=1000000)

# Read-only work has its own concurrency budget and never consumes a router's
# serialized mutation slot.
MAX_WORKERS = _int("TIKCENTRAL_FLEET_WORKERS", 8, minimum=1, maximum=32)
TELEMETRY_WORKERS = _int("TIKCENTRAL_TELEMETRY_WORKERS", 6, minimum=1, maximum=16)
DRIFT_WORKERS = _int("TIKCENTRAL_DRIFT_WORKERS", 3, minimum=1, maximum=8)

BACKUP_ROOT = Path(os.getenv("ROUTER_BACKUP_DIR", "/var/backups/tikcentral/routers"))
BACKUP_FALLBACK_ROOT = Path(os.getenv("TIKCENTRAL_BACKUP_FALLBACK", "/var/lib/tikcentral/router-backups"))
BACKUP_PASSWORD = os.getenv("ROUTER_BACKUP_PASSWORD", "")

TELEMETRY_INTERVAL_SECONDS = _int("TIKCENTRAL_TELEMETRY_INTERVAL", 300, minimum=60)
DRIFT_INTERVAL_SECONDS = _int("TIKCENTRAL_DRIFT_INTERVAL", 1800, minimum=300)
TELEMETRY_RETENTION_ROWS = _int("TIKCENTRAL_TELEMETRY_RETENTION_ROWS", 9000, minimum=100)
GUARDIAN_RETENTION_ROWS = _int("TIKCENTRAL_GUARDIAN_RETENTION_ROWS", 45000, minimum=100)
EVENT_RETENTION_ROWS = _int("TIKCENTRAL_EVENT_RETENTION_ROWS", 5000, minimum=100)

CORE_TELEMETRY_TIMEOUT = _int("TIKCENTRAL_CORE_TELEMETRY_TIMEOUT", 12, minimum=3, maximum=120)
ROUTERBOOT_TELEMETRY_TIMEOUT = _int("TIKCENTRAL_ROUTERBOOT_TELEMETRY_TIMEOUT", 8, minimum=3, maximum=120)
POLICY_PROBE_TIMEOUT = _int("TIKCENTRAL_POLICY_PROBE_TIMEOUT", 8, minimum=3, maximum=120)
DRIFT_EXPORT_TIMEOUT = _int("TIKCENTRAL_DRIFT_EXPORT_TIMEOUT", 90, minimum=10, maximum=600)
UPDATE_CHECK_TIMEOUT = _int("TIKCENTRAL_UPDATE_CHECK_TIMEOUT", 90, minimum=10, maximum=600)
ROUTEROS_RETURN_TIMEOUT = _int("TIKCENTRAL_ROUTEROS_RETURN_TIMEOUT", 1200, minimum=120, maximum=3600)
ROUTERBOOT_RETURN_TIMEOUT = _int("TIKCENTRAL_ROUTERBOOT_RETURN_TIMEOUT", 900, minimum=120, maximum=3600)

RESCUE_ADDRESS = os.getenv("TIKCENTRAL_RESCUE_ADDRESS", "10.255.255.1/24")
RESCUE_NETWORK = os.getenv("TIKCENTRAL_RESCUE_NETWORK", "10.255.255.0/24")
RESCUE_POOL = os.getenv("TIKCENTRAL_RESCUE_POOL", "10.255.255.100-10.255.255.200")
RESCUE_DNS = os.getenv("TIKCENTRAL_RESCUE_DNS", "1.1.1.1")

ASSETS = {
    "logo_light": "/static/opticable-logo-light.svg?v=6",
    "logo_dark": "/static/opticable-logo-dark.svg?v=6",
    "icon": "/static/opticable-icon.png?v=6",
}
