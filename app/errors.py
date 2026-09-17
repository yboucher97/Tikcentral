"""Structured errors for router operations.

Raw subprocess exceptions should never become user-facing HTTP 500 pages or huge
event details. Every operational failure is reduced to a stable code, concise
operator message and optional technical detail.
"""

import subprocess
from dataclasses import dataclass


@dataclass
class OperationError(RuntimeError):
    code: str
    message: str
    detail: str = ""
    severity: str = "warning"

    def __post_init__(self):
        RuntimeError.__init__(self, self.message)


def _clean(text: str, limit: int = 500) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    # Keep the useful tail from SSH while preventing generated RouterOS command
    # text from filling the UI/event timeline.
    line = text.splitlines()[-1].strip()
    if "timed out after" in line.lower():
        return "command timed out"
    return line[:limit] + ("..." if len(line) > limit else "")


def from_exception(exc: Exception, default_code: str = "OPERATION_FAILED", default_message: str = "Operation failed") -> OperationError:
    if isinstance(exc, OperationError):
        return exc
    if isinstance(exc, subprocess.TimeoutExpired):
        return OperationError("ROUTER_TIMEOUT", "Router command timed out", "The router did not answer before the command deadline.")
    text = _clean(str(exc))
    low = text.lower()
    if "permission denied" in low:
        return OperationError("PERMISSION_DENIED", "Tikcentral does not have permission to complete this action", text)
    if "connection refused" in low or "no route to host" in low or "connection timed out" in low:
        return OperationError("ROUTER_UNREACHABLE", "Router management path is unreachable", text)
    return OperationError(default_code, default_message, text)


def short(exc: Exception) -> str:
    err = from_exception(exc)
    return f"{err.code}: {err.message}" + (f" — {err.detail}" if err.detail else "")
