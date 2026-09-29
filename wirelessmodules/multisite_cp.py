"""Multi-Site Remote Border control-plane detection.

Genie's ShowWirelessFabricSummary parser matches control-plane rows with

    ^(?P<cp_name>\\S+)\\s+(?P<cp_ip_address>\\S+)\\s+(?P<cp_key>\\S+)\\s+(?P<cp_status>\\S+)$

The `\\S+` on the name means any control plane whose name contains a space is
silently skipped -- no error, no warning, the row simply never reaches the
parsed dict. Multi-Site Remote Border (MSRB) control planes are named after the
site they serve, and those names routinely contain spaces:

    default-control-plane       172.19.1.64     66302309625d422d  Up
    default-control-plane       172.19.1.65     66302309625d422d  Up
    jalejand_San Ange_e9143     172.19.1.100    861c2cb8541243f4  Up
                  ^ space here -- this row is dropped by the parser

That is a false all-clear: the tool shows two healthy control planes while a
third, equally live, is invisible. This module re-reads the raw command output
so every control plane is accounted for, and classifies each one.
"""

import re

# The site-local control plane(s) always carry this reserved name; anything else
# in the control-plane list belongs to a remote site reached through a
# Multi-Site Remote Border.
DEFAULT_CP_NAME = "default-control-plane"

# Anchored on the IP so a name containing spaces is captured whole. The key is
# hex and the status a single word, so working inward from the right is
# unambiguous where a left-to-right \\S+ split is not.
_CP_ROW = re.compile(
    r"^\s*(?P<name>\S.*?)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<key>\S+)\s+"
    r"(?P<status>\S+)\s*$"
)


def parse_control_planes(raw_output: str) -> list[dict]:
    """Every control plane in `show wireless fabric summary`, spaces and all.

    Returns a list of dicts with name/ip_address/key/status/multisite, in the
    order the device listed them. Reads only the Control-plane section: the
    Fabric VNID Mapping table below it has a similar shape and would otherwise
    match too.
    """
    rows, in_section = [], False
    for line in (raw_output or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("Control-plane:"):
            in_section = True
            continue
        if not in_section:
            continue
        # The section ends at the VNID table (or any other banner).
        if stripped.startswith("Fabric VNID Mapping"):
            break
        if (not stripped or stripped.startswith("---")
                or stripped.startswith("Name")):
            continue
        m = _CP_ROW.match(line)
        if not m:
            continue
        name = m.group("name").strip()
        rows.append({
            "name": name,
            "ip_address": m.group("ip"),
            "key": m.group("key"),
            "status": m.group("status"),
            "multisite": name != DEFAULT_CP_NAME,
        })
    return rows


def split_control_planes(raw_output: str):
    """(site_local, multisite) -- the reserved-name CPs and the MSRB ones."""
    cps = parse_control_planes(raw_output)
    return (
        [c for c in cps if not c["multisite"]],
        [c for c in cps if c["multisite"]],
    )
