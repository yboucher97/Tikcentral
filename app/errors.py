"""Structured errors for Tikcentral operations.

Operational failures are reduced to stable machine-searchable codes, concise
operator messages and sanitized technical detail. Raw exceptions should never
become user-facing HTTP 500 pages or flood the event timeline.
"""

import sqlite3
import subprocess
from dataclasses import dataclass


class Code:
    OPERATION_FAILED = "OPERATION_FAILED"
    ROUTER_TIMEOUT = "ROUTER_TIMEOUT"
    ROUTER_UNREACHABLE = "ROUTER_UNREACHABLE"
    ROUTER_COMMAND_FAILED = "ROUTER_COMMAND_FAILED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    DATABASE_BUSY = "DATABASE_BUSY"
    INVALID_INPUT = "INVALID_INPUT"
    ROUTER_BUSY = "ROUTER_BUSY"
    JOB_BUSY = "JOB_BUSY"
    INVALID_JOB_TRANSITION = "INVALID_JOB_TRANSITION"
    ACCESS_VERIFY_FAILED = "ACCESS_VERIFY_FAILED"
    GUARDIAN_UNHEALTHY = "GUARDIAN_UNHEALTHY"


@dataclass
class OperationError(RuntimeError):
    code: str
    message: str
    detail: str = ""
    severity: str = "warning"

    def __post_init__(self):
        RuntimeError.__init__(self, self.message)

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "detail": self.detail,
            "severity": self.severity,
        }


def _clean(text: str, limit: int = 500) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    line = text.splitlines()[-1].strip()
    if "timed out after" in line.lower():
        return "command timed out"
    return line[:limit] + ("..." if len(line) > limit else "")


def from_exception(exc: Exception, default_code: str = Code.OPERATION_FAILED, default_message: str = "Operation failed") -> OperationError:
    if isinstance(exc, OperationError):
        return exc
    if isinstance(exc, subprocess.TimeoutExpired):
        return OperationError(Code.ROUTER_TIMEOUT, "Router command timed out", "The router did not answer before the command deadline.")
    if isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc).lower():
        return OperationError(Code.DATABASE_BUSY, "Tikcentral database is temporarily busy", "Retry the action after the current operation finishes.")
    if isinstance(exc, PermissionError):
        return OperationError(Code.PERMISSION_DENIED, "Tikcentral does not have permission to complete this action", _clean(str(exc)))
    if isinstance(exc, ValueError):
        return OperationError(Code.INVALID_INPUT, "The supplied value is invalid", _clean(str(exc)))

    text = _clean(str(exc))
    low = text.lower()
    if "permission denied" in low:
        return OperationError(Code.PERMISSION_DENIED, "Tikcentral does not have permission to complete this action", text)
    if any(x in low for x in ("connection refused", "no route to host", "connection timed out", "network is unreachable")):
        return OperationError(Code.ROUTER_UNREACHABLE, "Router management path is unreachable", text)
    return OperationError(default_code, default_message, text)


def short(exc: Exception) -> str:
    err = from_exception(exc)
    return f"{err.code}: {err.message}" + (f" — {err.detail}" if err.detail else "")
