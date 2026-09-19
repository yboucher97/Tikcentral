#!/usr/bin/env python3
"""Validate deployment packaging contracts without touching a live system."""

from __future__ import annotations

import shlex
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CURRENT_PREFIX = "/opt/tikcentral/current/"


def fail(message: str) -> None:
    raise SystemExit(f"Tikcentral packaging validation failed: {message}")


def _repo_path(token: str) -> Path | None:
    if not token.startswith(CURRENT_PREFIX):
        return None
    rel = token[len(CURRENT_PREFIX):]
    if rel.startswith(".venv/"):
        return None
    return ROOT / rel


def validate_service_execstarts() -> None:
    units = sorted((ROOT / "deploy").glob("*.service"))
    if not units:
        fail("no deploy/*.service units found")

    for unit in units:
        exec_lines = [
            line.split("=", 1)[1].strip()
            for line in unit.read_text(encoding="utf-8").splitlines()
            if line.startswith("ExecStart=")
        ]
        if not exec_lines:
            fail(f"{unit.name} has no ExecStart")

        for command in exec_lines:
            try:
                argv = shlex.split(command)
            except ValueError as exc:
                fail(f"{unit.name} has invalid ExecStart quoting: {exc}")
            if not argv:
                fail(f"{unit.name} has an empty ExecStart")

            # Any repository path referenced by a unit must exist. Generated
            # .venv paths are intentionally excluded because they are created
            # during the release build.
            for token in argv:
                path = _repo_path(token)
                if path is not None and not path.exists():
                    fail(f"{unit.name} references missing repository path: {token}")

            # If systemd directly executes a repository file, Git/release mode
            # must make that file executable. Interpreter-driven scripts (for
            # example /bin/bash current/scripts/backup.sh) do not need +x.
            direct = _repo_path(argv[0])
            if direct is not None:
                mode = direct.stat().st_mode
                if not (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                    fail(
                        f"{unit.name} directly executes non-executable file: "
                        f"{argv[0]} (use an interpreter or preserve executable mode)"
                    )


def validate_backup_contract() -> None:
    unit = (ROOT / "deploy/tikcentral-backup.service").read_text(encoding="utf-8")
    expected = "ExecStart=/bin/bash /opt/tikcentral/current/scripts/backup.sh"
    if expected not in unit:
        fail("backup service must invoke scripts/backup.sh through /bin/bash")
    script = ROOT / "scripts/backup.sh"
    if not script.is_file():
        fail("scripts/backup.sh is missing")
    text = script.read_text(encoding="utf-8")
    for marker in ("set -euo pipefail", "sqlite3", "tikcentral-", "chown root:tikcentral", "chmod 0640"):
        if marker not in text:
            fail(f"backup script missing required safety marker: {marker}")


def main() -> None:
    validate_service_execstarts()
    validate_backup_contract()
    print("Tikcentral packaging validation: OK")


if __name__ == "__main__":
    main()
