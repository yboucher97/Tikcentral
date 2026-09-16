"""Final Tikcentral production ASGI entrypoint.

Adds the server-held RouterOS API credential to the managed router identity after
fleet_web has registered the portal, automation routes, and SSH-key provisioning.
"""

import os

from app import fleet_web
from app import portal

app = fleet_web.app
_base_managed_script = portal.build_routeros_script


def managed_router_script_with_api_password(site_name: str, token: str) -> str:
    script = _base_managed_script(site_name, token)
    password = os.getenv("TIKCENTRAL_ROUTER_API_PASSWORD", "").replace('"', "")
    if not password:
        return script
    lines = script.splitlines()
    insert_at = len(lines)
    if lines and lines[-1].strip() == "}":
        insert_at -= 1
    extra = [
        "",
        "# Set the VM-held RouterOS API credential for the managed identity",
        f'/user set [find where name="tikcentral"] password="{password}"',
    ]
    return "\n".join(lines[:insert_at] + extra + lines[insert_at:])


portal.build_routeros_script = managed_router_script_with_api_password
