"""Central Tikcentral runtime settings.

Keep operational defaults in one place so web, scheduler and deployment logic do
not silently drift apart.
"""

import os
from pathlib import Path

DB_PATH = os.getenv("DB_PATH", "/var/lib/tikcentral/tikcentral.db")
TIMEZONE = os.getenv("TIKCENTRAL_TIMEZONE", "America/Toronto")

SSH_USER = os.getenv("TIKCENTRAL_ROUTER_USER", "tikcentral")
SSH_KEY = os.getenv("TIKCENTRAL_SSH_KEY", "/etc/tikcentral/ssh/tikcentral_ed25519")
KNOWN_HOSTS = os.getenv("TIKCENTRAL_KNOWN_HOSTS", "/var/lib/tikcentral/known_hosts")
SSH_TIMEOUT = int(os.getenv("TIKCENTRAL_SSH_TIMEOUT", "20"))
MAX_WORKERS = int(os.getenv("TIKCENTRAL_FLEET_WORKERS", "8"))

BACKUP_ROOT = Path(os.getenv("ROUTER_BACKUP_DIR", "/var/backups/tikcentral/routers"))
BACKUP_FALLBACK_ROOT = Path(os.getenv("TIKCENTRAL_BACKUP_FALLBACK", "/var/lib/tikcentral/router-backups"))
BACKUP_PASSWORD = os.getenv("ROUTER_BACKUP_PASSWORD", "")

TELEMETRY_INTERVAL_SECONDS = int(os.getenv("TIKCENTRAL_TELEMETRY_INTERVAL", "300"))
DRIFT_INTERVAL_SECONDS = int(os.getenv("TIKCENTRAL_DRIFT_INTERVAL", "1800"))
TELEMETRY_RETENTION_ROWS = int(os.getenv("TIKCENTRAL_TELEMETRY_RETENTION_ROWS", "9000"))
GUARDIAN_RETENTION_ROWS = int(os.getenv("TIKCENTRAL_GUARDIAN_RETENTION_ROWS", "45000"))
EVENT_RETENTION_ROWS = int(os.getenv("TIKCENTRAL_EVENT_RETENTION_ROWS", "5000"))

RESCUE_ADDRESS = "10.255.255.1/24"
RESCUE_POOL = "10.255.255.100-10.255.255.200"

ASSETS = {
    "logo_light": "/static/opticable-logo-light.svg?v=6",
    "logo_dark": "/static/opticable-logo-dark.svg?v=6",
    "icon": "/static/opticable-icon.png?v=6",
}

READ_RETRIES = int(os.getenv("TIKCENTRAL_READ_RETRIES", "1"))
MUTATION_TIMEOUT = int(os.getenv("TIKCENTRAL_MUTATION_TIMEOUT", "90"))
