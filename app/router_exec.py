"""Single RouterOS execution layer.

All SSH/SFTP access goes through this module so timeout behavior, retries,
normalization, secret redaction and error handling stay identical everywhere.
Read-only operations may retry; mutations never retry automatically.
"""

import re
import subprocess
import time
from pathlib import Path

from app import errors, settings

_SECRET_PATTERNS = (
    re.compile(r'(?i)(password\s*=\s*)("[^"]*"|[^\s;]+)'),
    re.compile(r'(?i)(token\s*=\s*)("[^"]*"|[^\s;]+)'),
    re.compile(r'(?i)(private[-_ ]?key\s*=\s*)("[^"]*"|[^\s;]+)'),
    re.compile(r'(?i)(passphrase\s*=\s*)("[^"]*"|[^\s;]+)'),
)


def sanitize(text: str, limit: int = 1200) -> str:
    """Redact common secret-bearing RouterOS fields before persistence/UI use."""
    value = str(text or "")
    for pattern in _SECRET_PATTERNS:
        value = pattern.sub(r'\1<redacted>', value)
    return value[-max(100, int(limit)):]


def ssh_base(ip: str):
    return [
        "ssh", "-T", "-i", settings.SSH_KEY,
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={settings.SSH_TIMEOUT}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={settings.KNOWN_HOSTS}",
        f"{settings.SSH_USER}@{ip}",
    ]


def routeros_single_line(command: str) -> str:
    text = (command or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(text) > 250_000:
        raise errors.OperationError("COMMAND_TOO_LARGE", "RouterOS command is too large")
    if "\n" not in text:
        return text
    parts = []
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("{") or line.endswith(";"):
            parts.append(line)
        else:
            parts.append(line + ";")
    return " ".join(parts)


def _prepare_known_hosts():
    path = Path(settings.KNOWN_HOSTS)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def execute(ip: str, command: str, *, timeout: int | None = None, label: str = "RouterOS command", mutating: bool = False, retries: int | None = None) -> str:
    """Run one RouterOS command through the only supported SSH path.

    Reads may retry according to TIKCENTRAL_READ_RETRIES. Mutations are always
    attempted exactly once because replaying a partially-applied RouterOS change
    is less safe than returning an explicit failure for verification/recovery.
    """
    _prepare_known_hosts()
    remote = routeros_single_line(command)
    attempts = 1 + (0 if mutating else (settings.READ_RETRIES if retries is None else max(0, retries)))
    deadline = max(1, int(timeout or settings.SSH_TIMEOUT + 15))
    last = None
    for attempt in range(attempts):
        try:
            p = subprocess.run(ssh_base(ip) + [remote], capture_output=True, text=True, timeout=deadline)
            if p.returncode != 0:
                msg = sanitize(p.stderr or p.stdout or f"ssh exited {p.returncode}")
                raise errors.OperationError("ROUTER_COMMAND_FAILED", f"{label} failed", msg)
            return (p.stdout or "").strip()
        except errors.OperationError as exc:
            last = exc
        except subprocess.TimeoutExpired:
            last = errors.OperationError("ROUTER_TIMEOUT", f"{label} timed out", f"deadline={deadline}s")
        except Exception as exc:
            last = errors.from_exception(exc, "ROUTER_COMMAND_FAILED", f"{label} failed")
        if attempt + 1 < attempts:
            time.sleep(0.35)
    raise last or errors.OperationError("ROUTER_COMMAND_FAILED", f"{label} failed")


def read(ip: str, command: str, *, timeout: int | None = None, label: str = "Router probe") -> str:
    return execute(ip, command, timeout=timeout, label=label, mutating=False)


def mutate(ip: str, command: str, *, timeout: int | None = None, label: str = "Router change") -> str:
    return execute(ip, command, timeout=timeout, label=label, mutating=True, retries=0)


def dispatch_reboot(ip: str, command: str, *, timeout: int, label: str) -> str:
    """Dispatch a command expected to terminate SSH because the router reboots.

    A timeout is treated as dispatched/unknown rather than immediate failure;
    callers must verify resulting state and Guardian health afterward.
    """
    _prepare_known_hosts()
    remote = routeros_single_line(command)
    try:
        p = subprocess.run(ssh_base(ip) + [remote], capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            return sanitize(p.stderr or p.stdout or f"ssh exited {p.returncode}", 1000)
        return sanitize(((p.stdout or "") + "\n" + (p.stderr or "")).strip(), 1000)
    except subprocess.TimeoutExpired:
        return f"{label} dispatched; SSH ended/timed out during expected reboot"


def sftp_get_remove(ip: str, remote_name: str, local_path: str, *, timeout: int = 120) -> str:
    _prepare_known_hosts()
    batch = f"get {remote_name} {local_path}\nrm {remote_name}\n"
    p = subprocess.run(
        ["sftp", "-b", "-", "-i", settings.SSH_KEY,
         "-o", "BatchMode=yes", "-o", f"ConnectTimeout={settings.SSH_TIMEOUT}",
         "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={settings.KNOWN_HOSTS}",
         f"{settings.SSH_USER}@{ip}"],
        input=batch, capture_output=True, text=True, timeout=timeout,
    )
    if p.returncode != 0:
        msg = sanitize(p.stderr or p.stdout or f"sftp exited {p.returncode}")
        raise errors.OperationError("BACKUP_RETRIEVAL_FAILED", "Binary backup retrieval failed", msg)
    return (p.stdout or "").strip()
