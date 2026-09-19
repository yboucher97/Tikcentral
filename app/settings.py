"""Single source of truth for Tikcentral runtime configuration.

All application modules consume environment-derived values from this module so
safe defaults, validation and deployment behavior cannot silently diverge.
"""

import ipaddress
import os
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


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


DB_PATH = os.getenv("DB_PATH", "/var/lib/tikcentral/tikcentral.db")
TIMEZONE = os.getenv("TIKCENTRAL_TIMEZONE", "America/Toronto").strip() or "America/Toronto"
try:
    ZoneInfo(TIMEZONE)
except (ZoneInfoNotFoundError, ValueError) as exc:
    raise RuntimeError(f"TIKCENTRAL_TIMEZONE is invalid: {TIMEZONE}") from exc
ADMIN_API_KEY = _required("ADMIN_API_KEY")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
BOOTSTRAP_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "")
SESSION_DAYS = _int("SESSION_DAYS", 7, minimum=1, maximum=90)
TOKEN_TTL_HOURS = _int("TOKEN_TTL_HOURS", 24, minimum=1, maximum=168)
TEMP_ACCESS_DAYS = _int("TEMP_ACCESS_DAYS", 5, minimum=1, maximum=90)

WG_HELPER = os.getenv("WG_HELPER", "/usr/local/sbin/tikcentral-wg-peer")
WG_SERVER_PUBLIC_KEY = _required("WG_SERVER_PUBLIC_KEY")
WG_ENDPOINT = _required("WG_ENDPOINT")
try:
    WG_ROUTER_POOL = ipaddress.ip_network(os.getenv("WG_ROUTER_POOL", "10.250.1.0/24"), strict=True)
    WG_ALLOWED_NETWORK_OBJ = ipaddress.ip_network(os.getenv("WG_ALLOWED_NETWORK", "10.250.0.0/16"), strict=True)
except ValueError as exc:
    raise RuntimeError(f"Invalid WireGuard network settings: {exc}") from exc
if WG_ROUTER_POOL.version != 4 or WG_ALLOWED_NETWORK_OBJ.version != 4:
    raise RuntimeError("WG_ROUTER_POOL and WG_ALLOWED_NETWORK must be IPv4 networks")
if not WG_ROUTER_POOL.subnet_of(WG_ALLOWED_NETWORK_OBJ):
    raise RuntimeError("WG_ROUTER_POOL must be contained within WG_ALLOWED_NETWORK")
WG_ALLOWED_NETWORK = str(WG_ALLOWED_NETWORK_OBJ)
ONLINE_SECONDS = _int("ONLINE_SECONDS", 180, minimum=30, maximum=3600)
WG_HELPER_TIMEOUT = _int("TIKCENTRAL_WG_HELPER_TIMEOUT", 10, minimum=2, maximum=120)
PUBLIC_HOSTNAME = os.getenv("PUBLIC_HOSTNAME", WG_ENDPOINT.rsplit(":", 1)[0])

WINBOX_PUBLIC_PORT_MIN = _int("WINBOX_PUBLIC_PORT_MIN", 20000, minimum=1024, maximum=65535)
WINBOX_PUBLIC_PORT_MAX = _int("WINBOX_PUBLIC_PORT_MAX", 49999, minimum=1024, maximum=65535)
if WINBOX_PUBLIC_PORT_MAX < WINBOX_PUBLIC_PORT_MIN:
    raise RuntimeError("WINBOX_PUBLIC_PORT_MAX must be >= WINBOX_PUBLIC_PORT_MIN")
WINBOX_BIND_HOST = os.getenv("WINBOX_BIND_HOST", "0.0.0.0")
WINBOX_TARGET_PORT = _int("WINBOX_TARGET_PORT", 8291, minimum=1, maximum=65535)
WINBOX_RESCAN_SECONDS = _int("WINBOX_RESCAN_SECONDS", 10, minimum=2, maximum=300)
WINBOX_CONNECT_TIMEOUT = _int("TIKCENTRAL_WINBOX_CONNECT_TIMEOUT", 8, minimum=1, maximum=60)

SSH_USER = os.getenv("TIKCENTRAL_ROUTER_USER", "tikcentral")
SSH_KEY = os.getenv("TIKCENTRAL_SSH_KEY", "/etc/tikcentral/ssh/tikcentral_ed25519")
KNOWN_HOSTS = os.getenv("TIKCENTRAL_KNOWN_HOSTS", "/var/lib/tikcentral/known_hosts")
SSH_TIMEOUT = _int("TIKCENTRAL_SSH_TIMEOUT", 20, minimum=3, maximum=300)
READ_RETRIES = _int("TIKCENTRAL_READ_RETRIES", 1, minimum=0, maximum=3)
MUTATION_TIMEOUT = _int("TIKCENTRAL_MUTATION_TIMEOUT", 90, minimum=10, maximum=3600)
MAX_COMMAND_LENGTH = _int("TIKCENTRAL_MAX_COMMAND_LENGTH", 200000, minimum=1000, maximum=1000000)
ROUTER_API_PASSWORD = os.getenv("TIKCENTRAL_ROUTER_API_PASSWORD", "")
PROVISIONING_KEY = os.getenv("TIKCENTRAL_PROVISIONING_KEY", "")

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
EVENT_INFO_RETENTION_ROWS = _int("TIKCENTRAL_EVENT_INFO_RETENTION_ROWS", 750, minimum=50)
EVENT_DEDUP_SECONDS = _int("TIKCENTRAL_EVENT_DEDUP_SECONDS", 300, minimum=30, maximum=86400)

GUARDIAN_WARN_FAILURES = _int("TIKCENTRAL_GUARDIAN_WARN_FAILURES", 3, minimum=2, maximum=30)
GUARDIAN_CRITICAL_MINUTES = _int("TIKCENTRAL_GUARDIAN_CRITICAL_MINUTES", 10, minimum=1, maximum=240)
GUARDIAN_ESCALATE_MINUTES = _int("TIKCENTRAL_GUARDIAN_ESCALATE_MINUTES", 30, minimum=5, maximum=1440)
if GUARDIAN_ESCALATE_MINUTES < GUARDIAN_CRITICAL_MINUTES:
    raise RuntimeError("TIKCENTRAL_GUARDIAN_ESCALATE_MINUTES must be >= TIKCENTRAL_GUARDIAN_CRITICAL_MINUTES")
GUARDIAN_FLAP_WINDOW_MINUTES = _int("TIKCENTRAL_GUARDIAN_FLAP_WINDOW_MINUTES", 120, minimum=10, maximum=1440)
GUARDIAN_FLAP_THRESHOLD = _int("TIKCENTRAL_GUARDIAN_FLAP_THRESHOLD", 6, minimum=2, maximum=100)
SYSTEM_HEALTH_INTERVAL_SECONDS = _int("TIKCENTRAL_SYSTEM_HEALTH_INTERVAL", 900, minimum=60, maximum=86400)
BACKUP_VERIFY_INTERVAL_SECONDS = _int("TIKCENTRAL_BACKUP_VERIFY_INTERVAL", 21600, minimum=300, maximum=604800)

RESOURCE_CPU_WARN = _int("TIKCENTRAL_RESOURCE_CPU_WARN", 85, minimum=50, maximum=100)
RESOURCE_CPU_CRITICAL = _int("TIKCENTRAL_RESOURCE_CPU_CRITICAL", 95, minimum=60, maximum=100)
RESOURCE_MEMORY_WARN_PERCENT = _int("TIKCENTRAL_RESOURCE_MEMORY_WARN_PERCENT", 15, minimum=1, maximum=50)
RESOURCE_MEMORY_CRITICAL_PERCENT = _int("TIKCENTRAL_RESOURCE_MEMORY_CRITICAL_PERCENT", 7, minimum=1, maximum=30)
if RESOURCE_CPU_CRITICAL < RESOURCE_CPU_WARN:
    raise RuntimeError("TIKCENTRAL_RESOURCE_CPU_CRITICAL must be >= TIKCENTRAL_RESOURCE_CPU_WARN")
if RESOURCE_MEMORY_CRITICAL_PERCENT > RESOURCE_MEMORY_WARN_PERCENT:
    raise RuntimeError("TIKCENTRAL_RESOURCE_MEMORY_CRITICAL_PERCENT must be <= TIKCENTRAL_RESOURCE_MEMORY_WARN_PERCENT")
RESOURCE_REBOOT_CORRELATION_MINUTES = _int("TIKCENTRAL_REBOOT_CORRELATION_MINUTES", 30, minimum=5, maximum=240)

# Public-IP enrichment. Free/no-key default; cached locally to minimize calls.
IP_LOOKUP_URL_TEMPLATE = os.getenv("TIKCENTRAL_IP_LOOKUP_URL_TEMPLATE", "https://ipwho.is/{ip}").strip()
IP_LOOKUP_TIMEOUT = _int("TIKCENTRAL_IP_LOOKUP_TIMEOUT", 8, minimum=2, maximum=30)
IP_LOOKUP_REFRESH_DAYS = _int("TIKCENTRAL_IP_LOOKUP_REFRESH_DAYS", 7, minimum=1, maximum=90)

CORE_TELEMETRY_TIMEOUT = _int("TIKCENTRAL_CORE_TELEMETRY_TIMEOUT", 12, minimum=3, maximum=120)
ROUTERBOOT_TELEMETRY_TIMEOUT = _int("TIKCENTRAL_ROUTERBOOT_TELEMETRY_TIMEOUT", 8, minimum=3, maximum=120)
POLICY_PROBE_TIMEOUT = _int("TIKCENTRAL_POLICY_PROBE_TIMEOUT", 8, minimum=3, maximum=120)
DRIFT_EXPORT_TIMEOUT = _int("TIKCENTRAL_DRIFT_EXPORT_TIMEOUT", 90, minimum=10, maximum=600)
UPDATE_CHECK_TIMEOUT = _int("TIKCENTRAL_UPDATE_CHECK_TIMEOUT", 90, minimum=10, maximum=600)
ROUTEROS_RETURN_TIMEOUT = _int("TIKCENTRAL_ROUTEROS_RETURN_TIMEOUT", 1200, minimum=120, maximum=3600)
ROUTERBOOT_RETURN_TIMEOUT = _int("TIKCENTRAL_ROUTERBOOT_RETURN_TIMEOUT", 900, minimum=120, maximum=3600)

# Read-only Codex analysis. Tikcentral invokes only the privileged wrapper; the
# wrapper drops to a separate tikcentral-ai user before starting Codex.
AI_CODEX_HELPER = os.getenv("TIKCENTRAL_CODEX_HELPER", "/usr/local/sbin/tikcentral-codex-analyze")
AI_MODEL = os.getenv("TIKCENTRAL_AI_MODEL", "gpt-5.6-luna").strip() or "gpt-5.6-luna"
if AI_MODEL not in {"gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol", "gpt-6-astra"}:
    raise RuntimeError("TIKCENTRAL_AI_MODEL must be gpt-5.6-luna, gpt-5.6-terra, gpt-5.6-sol, or gpt-6-astra")
AI_TIMEOUT = _int("TIKCENTRAL_AI_TIMEOUT", 300, minimum=30, maximum=1800)
AI_ROUTER_READ_TIMEOUT = _int("TIKCENTRAL_AI_ROUTER_READ_TIMEOUT", 60, minimum=10, maximum=300)
AI_MAX_SECTION_CHARS = _int("TIKCENTRAL_AI_MAX_SECTION_CHARS", 60000, minimum=5000, maximum=250000)
AI_MAX_REPORT_CHARS = _int("TIKCENTRAL_AI_MAX_REPORT_CHARS", 50000, minimum=5000, maximum=200000)

RESCUE_ADDRESS = os.getenv("TIKCENTRAL_RESCUE_ADDRESS", "10.255.255.1/24")
RESCUE_NETWORK = os.getenv("TIKCENTRAL_RESCUE_NETWORK", "10.255.255.0/24")
RESCUE_POOL = os.getenv("TIKCENTRAL_RESCUE_POOL", "10.255.255.100-10.255.255.200")
RESCUE_DNS = os.getenv("TIKCENTRAL_RESCUE_DNS", "1.1.1.1")
try:
    _rescue_interface = ipaddress.ip_interface(RESCUE_ADDRESS)
    _rescue_network = ipaddress.ip_network(RESCUE_NETWORK, strict=True)
    if _rescue_interface.version != 4 or _rescue_network.version != 4:
        raise ValueError("rescue address and network must be IPv4")
    if _rescue_interface.ip not in _rescue_network:
        raise ValueError("rescue address is outside rescue network")
    _pool_start_text, _pool_end_text = RESCUE_POOL.split("-", 1)
    _pool_start = ipaddress.ip_address(_pool_start_text.strip())
    _pool_end = ipaddress.ip_address(_pool_end_text.strip())
    if _pool_start not in _rescue_network or _pool_end not in _rescue_network or int(_pool_start) > int(_pool_end):
        raise ValueError("rescue pool is invalid or outside rescue network")
    if _rescue_network.overlaps(WG_ALLOWED_NETWORK_OBJ):
        raise ValueError("rescue network overlaps the WireGuard management network")
    _rescue_dns = ipaddress.ip_address(RESCUE_DNS)
    if _rescue_dns.version != 4:
        raise ValueError("rescue DNS must be IPv4")
except (ValueError, TypeError) as exc:
    raise RuntimeError(f"Invalid Tikcentral Rescue network settings: {exc}") from exc
RESCUE_GATEWAY = str(_rescue_interface.ip)

ASSET_VERSION = os.getenv("TIKCENTRAL_ASSET_VERSION", "7").strip() or "7"
ASSET_FILES = {
    "logo_light": "opticable-logo-light.svg",
    "logo_dark": "opticable-logo-dark.svg",
    "icon": "opticable-icon.png",
}
ASSETS = {key: f"/static/{filename}?v={ASSET_VERSION}" for key, filename in ASSET_FILES.items()}
