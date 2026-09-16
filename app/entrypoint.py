"""Tikcentral production ASGI entrypoint.

Keeps deployment-specific compatibility fixes separate from the core application.
"""

from app import portal

_original_build_routeros_script = portal.build_routeros_script


def build_routeros_script_scoped(site_name: str, token: str) -> str:
    """Return enrollment script as one RouterOS local scope.

    RouterOS treats each line pasted at the terminal as a separate local scope.
    The enrollment generator relies on :local variables across many lines, so the
    entire body must be enclosed in one { ... } block.
    """
    script = _original_build_routeros_script(site_name, token)
    lines = script.splitlines()
    if len(lines) < 3:
        return "{\n" + script + "\n}"
    return "\n".join(lines[:2] + ["{"] + lines[2:] + ["}"])


portal.build_routeros_script = build_routeros_script_scoped
app = portal.app
