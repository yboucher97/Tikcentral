"""Single RouterOS execution layer.

All SSH/SFTP access goes through this module so timeout behavior, retries,
normalization and error sanitization stay identical across Tikcentral.
"""

import subprocess
import time
from pathlib import Path

from app import errors, settings


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
    """Run one RouterOS command.

    Read-only commands may retry once by default. Mutating commands are never
    retried automatically because repeating a partially applied change is less
    safe than surfacing the failure.
    """
    _prepare_known_hosts()
    remote = routeros_single_line(command)
    attempts = 1 + (0 if mutating else (settings.READ_RETRIES if retries is None else max(0, retries)))
    deadline = timeout or settings.SSH_TIMEOUT + 15
    last = None
    for attempt in range(attempts):
        try:
            p = subprocess.run(ssh_base(ip) + [remote], capture_output=True, text=True, timeout=deadline)
            if p.returncode != 0:
                msg = (p.stderr or p.stdout or f"ssh exited {p.returncode}").strip()
                raise errors.OperationError("ROUTER_COMMAND_FAILED", f"{label} failed", msg[-1000:])
            return (p.stdout or "").strip()
        except errors.OperationError as exc:
            last = exc
        except subprocess.TimeoutExpired as exc:
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

    A timeout is treated as dispatched/unknown rather than an immediate failure;
    the caller must verify Guardian and resulting state afterward.
    """
    _prepare_known_hosts()
    remote = routeros_single_line(command)
    try:
        p = subprocess.run(ssh_base(ip) + [remote], capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            msg = (p.stderr or p.stdout or f"ssh exited {p.returncode}").strip()
            # SSH often exits nonzero when the remote side reboots. Preserve the
            # detail for later verification rather than claiming success here.
            return msg[-1000:]
        return ((p.stdout or "") + "\n" + (p.stderr or "")).strip()[-1000:]
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
        msg = (p.stderr or p.stdout or f"sftp exited {p.returncode}").strip()
        raise errors.OperationError("BACKUP_RETRIEVAL_FAILED", "Binary backup retrieval failed", msg[-1000:])
    return (p.stdout or "").strip()
