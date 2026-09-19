"""User-facing time formatting.

Persistent timestamps remain UTC in SQLite. Every user-facing timestamp is
rendered in Montréal local time (Eastern time, including DST).
"""

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from app import settings

# Montréal and Toronto share the same Eastern/DST rules. Keep the configured
# IANA zone as the source of truth while presenting it consistently as Montréal.
LOCAL_TZ = ZoneInfo(settings.TIMEZONE)
DISPLAY_ZONE_NAME = "Montréal"
_ISO_RE = re.compile(
    r"""(?<!["'=\w])"""
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
)
_LEGACY_UTC_RE = re.compile(
    r"""(?<!["'=\w])"""
    r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2})?)\s+UTC\b"
)


def format_montreal(value: str, *, seconds: bool = False) -> str:
    """Format an aware/UTC timestamp in Montréal local time."""
    if not value:
        return ""
    try:
        normalized = value.strip()
        if normalized.endswith(" UTC"):
            normalized = normalized[:-4].replace(" ", "T") + "+00:00"
        elif normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local = dt.astimezone(LOCAL_TZ)
        fmt = "%Y-%m-%d %H:%M:%S %Z" if seconds else "%Y-%m-%d %H:%M %Z"
        return local.strftime(fmt)
    except Exception:
        return value


def localize_html_iso_timestamps(text: str) -> str:
    """Convert ISO-aware and legacy UTC text embedded in rendered HTML."""
    out = _ISO_RE.sub(lambda match: format_montreal(match.group(1)), text or "")

    def legacy(match):
        raw = f"{match.group(1)}T{match.group(2)}+00:00"
        return format_montreal(raw, seconds=match.group(2).count(":") == 2)

    return _LEGACY_UTC_RE.sub(legacy, out)
