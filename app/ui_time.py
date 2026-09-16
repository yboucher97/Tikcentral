"""User-facing time formatting for Tikcentral.

Persistent timestamps remain UTC in SQLite. UI timestamps are rendered in
Montreal local time using the IANA America/Toronto zone so DST is automatic.
"""

import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

MONTREAL_TZ = ZoneInfo("America/Toronto")

# ISO timestamps emitted by Tikcentral's UTC persistence layer.
_ISO_RE = re.compile(
    r"(?<![\w])"
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
)


def format_montreal(value: str, *, seconds: bool = False) -> str:
    """Convert an ISO timestamp to Montreal time for display."""
    if not value:
        return ""
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local = dt.astimezone(MONTREAL_TZ)
        fmt = "%Y-%m-%d %H:%M:%S %Z" if seconds else "%Y-%m-%d %H:%M %Z"
        return local.strftime(fmt)
    except Exception:
        return value


def localize_html_iso_timestamps(text: str) -> str:
    """Convert Tikcentral ISO timestamps embedded in rendered HTML."""
    return _ISO_RE.sub(lambda m: format_montreal(m.group(1)), text or "")
