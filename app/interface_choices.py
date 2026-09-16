"""Shared physical interface choices for Tikcentral provisioning/rescue UI."""

INTERFACES = tuple(
    [f"ether{i}" for i in range(1, 11)] +
    [f"sfp-sfpplus{i}" for i in range(1, 25)]
)

INTERFACE_SET = frozenset(INTERFACES)


def options_html(selected: str = "") -> str:
    parts = []
    for name in INTERFACES:
        sel = " selected" if name == selected else ""
        parts.append(f'<option value="{name}"{sel}>{name}</option>')
    return "".join(parts)
