"""Add backup tiers without changing the existing fleet backup implementation.

Daily backups remain rotating. Commissioning and pre-change backups are moved
into retained tier directories and are not touched by automatic daily cleanup.
"""

import shutil
from datetime import datetime, timezone
from pathlib import Path

from app import fleet

_original_backup_one = fleet._backup_one
_installed = False


def _tiered_backup_one(router, stamp, tier="daily"):
    if tier not in {"daily", "pre-change", "commissioning"}:
        raise ValueError("invalid backup tier")
    result = _original_backup_one(router, stamp)
    old_base = Path(fleet.ROUTER_BACKUP_DIR) / str(router["id"])
    new_base = old_base / tier
    new_base.mkdir(parents=True, exist_ok=True)
    moved = []
    for suffix in (".rsc", ".backup"):
        src = old_base / f"{stamp}{suffix}"
        if src.exists():
            dst = new_base / src.name
            shutil.move(str(src), str(dst))
            moved.append(str(dst))
    return "Saved " + ", ".join(moved) if moved else result


def _daily_cleanup_only():
    fleet.ensure_schema()
    with fleet.core.db() as conn:
        days = int(conn.execute("SELECT backup_retention_days FROM fleet_settings WHERE id=1").fetchone()[0])
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    root = Path(fleet.ROUTER_BACKUP_DIR)
    if not root.exists():
        return
    # Only daily/ rotates. commissioning/ and pre-change/ are retained until an
    # administrator deliberately removes them.
    for daily in root.glob("*/daily"):
        if not daily.is_dir():
            continue
        for p in daily.rglob("*"):
            if p.is_file() and p.stat().st_mtime < cutoff:
                p.unlink(missing_ok=True)


def install():
    global _installed
    if _installed:
        return
    fleet._backup_one = _tiered_backup_one
    fleet.cleanup_backups = _daily_cleanup_only
    _installed = True


install()
