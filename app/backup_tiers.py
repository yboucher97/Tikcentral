"""Tiered router backups with writable-storage fallback.

Daily backups rotate. Commissioning and pre-change backups are retained. If the
configured backup root is not writable by the Tikcentral service (for example an
older root-owned router directory), Tikcentral transparently falls back to a
service-writable directory under /var/lib/tikcentral.
"""

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from app import fleet

_original_backup_one = fleet._backup_one
_installed = False
FALLBACK_ROOT = Path("/var/lib/tikcentral/router-backups")


def _root_is_writable(root: Path) -> bool:
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".tikcentral-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _ensure_backup_root(router_id=None) -> Path:
    configured = Path(fleet.ROUTER_BACKUP_DIR)
    candidates = [configured, FALLBACK_ROOT]
    for root in candidates:
        if not _root_is_writable(root):
            continue
        if router_id is not None:
            try:
                router_dir = root / str(router_id)
                router_dir.mkdir(parents=True, exist_ok=True)
                probe = router_dir / ".tikcentral-write-test"
                probe.write_text("ok", encoding="utf-8")
                probe.unlink(missing_ok=True)
            except Exception:
                continue
        if str(root) != fleet.ROUTER_BACKUP_DIR:
            fleet.ROUTER_BACKUP_DIR = str(root)
        return root
    raise PermissionError(
        "Tikcentral cannot write router backups to either the configured backup directory "
        "or /var/lib/tikcentral/router-backups"
    )


def _tiered_backup_one(router, stamp, tier="daily"):
    if tier not in {"daily", "pre-change", "commissioning"}:
        raise ValueError("invalid backup tier")

    root = _ensure_backup_root(router["id"])
    # _original_backup_one reads fleet.ROUTER_BACKUP_DIR dynamically.
    result = _original_backup_one(router, stamp)
    old_base = root / str(router["id"])
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
    try:
        root = _ensure_backup_root()
    except Exception:
        return
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
