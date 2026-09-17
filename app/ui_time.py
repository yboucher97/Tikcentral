"""User-facing time formatting.

Persistent timestamps remain UTC in SQLite; UI timestamps use the centrally
configured IANA timezone.
"""

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from app import settings

LOCAL_TZ = ZoneInfo(settings.TIMEZONE)
_ISO_RE = re.compile(
    r"(?<![\w])"
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
)


def format_montreal(value: str, *, seconds: bool = False) -> str:
    """Compatibility name: format an ISO timestamp in the configured UI zone."""
    if not value:
        return ""
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local = dt.astimezone(LOCAL_TZ)
        fmt = "%Y-%m-%d %H:%M:%S %Z" if seconds else "%Y-%m-%d %H:%M %Z"
        return local.strftime(fmt)
    except Exception:
        return value


def localize_html_iso_timestamps(text: str) -> str:
    return _ISO_RE.sub(lambda match: format_montreal(match.group(1)), text or "")
