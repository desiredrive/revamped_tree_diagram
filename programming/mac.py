"""MAC address programming validation.

Source of truth: `show mac address-table address <mac> vlan <vlan>`.
The MAC address-table is deterministic; FED MATM is intentionally not
consulted here — callers needing FED state should use a separate primitive.

Type classification:
  - STATIC: authentication-installed or manually configured.
  - DYNAMIC: MATM-learned from data-plane traffic.
  - CP_LEARN: imported by LISP control plane; egress reads as
    `RLOC <ip>` (remote endpoint, inter-XTR) or `AccessTunnelN`
    (access-tunnel for fabric-attached APs / extended nodes).

The dataclass is shared across the rest of the programming/ package so
future primitives (interfaces, routes, adjacency, MFIB, SGACL) can reuse
the stack-member / sup-role inputs even when this primitive does not need
them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional, Any
import re

import radkit_cli


MacType = Literal["static", "dynamic", "cp_learn", "missing"]
SupRole = Literal["active", "standby"]
ComparisonStatus = Literal[
    "match",
    "wrong_member",
    "misprogrammed",
    "ios_missing",
    "indeterminate",
]


@dataclass
class MacProgrammingInput:
    hostname: str
    mac: str
    vlan: int
    expected_interface: Optional[str] = None
    switch_member: Optional[int] = None
    sup_role: Optional[SupRole] = None

    def __post_init__(self):
        if self.vlan is None or str(self.vlan).strip().lower() in ("", "none"):
            raise ValueError("MacProgrammingInput.vlan is mandatory.")


@dataclass
class MacProgrammingResult:
    programmed: bool
    mac_type: MacType
    interface: Optional[str] = None
    rloc_ip: Optional[str] = None
    access_tunnel: Optional[str] = None
    matches_expected: Optional[bool] = None
    raw_cli: str = ""
    raw_parsed: dict = field(default_factory=dict)


@dataclass
class FedMacResult:
    """Hardware (FED MATM) view of a MAC. Source: `show platform software fed
    switch <m>|active|standby matm macTable vlan <v> mac <m>`. Used as the
    dataplane cross-check against the software MAC table."""
    programmed: bool
    interface: Optional[str] = None
    rloc_ip: Optional[str] = None
    type: Optional[str] = None
    flags: Optional[str] = None
    seq: Optional[str] = None
    ec_bi: Optional[str] = None
    machandle: Optional[str] = None
    si_handle: Optional[str] = None
    ri_handle: Optional[str] = None
    di_handle: Optional[str] = None
    a_time: Optional[str] = None
    e_time: Optional[str] = None
    con: Optional[str] = None
    raw_cli: str = ""
    raw_fields: dict = field(default_factory=dict)


_MAC_CANON_RE = re.compile(r"[^0-9a-fA-F]")
_RLOC_RE = re.compile(r"^\s*RLOC\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s*$", re.IGNORECASE)
_ACCESS_TUNNEL_RE = re.compile(r"^\s*(?P<intf>AccessTunnel\d+)\s*$", re.IGNORECASE)
_CP_LEARN_PREFIXES = ("rloc", "accesstunnel", "l2lisp", "tu", "lisp")


def _is_cp_learned_iface(name: Optional[str]) -> bool:
    """True if `name` is a control-plane / overlay egress (RLOC, AccessTunnelN,
    L2LISP, Tunnel, LISP). These are all forms of the same thing — the MAC was
    imported by LISP, not learned on a local physical port."""
    if not name:
        return False
    s = name.strip().lower()
    return any(s.startswith(p) for p in _CP_LEARN_PREFIXES)


def canonicalize_mac(mac: str) -> str:
    """Normalize any common MAC format to dotted lowercase (xxxx.xxxx.xxxx)."""
    hexonly = _MAC_CANON_RE.sub("", mac or "").lower()
    if len(hexonly) != 12:
        return (mac or "").lower()
    return f"{hexonly[0:4]}.{hexonly[4:8]}.{hexonly[8:12]}"


def _classify(type_field: Optional[str], interface: Optional[str]) -> tuple[MacType, Optional[str], Optional[str]]:
    """Return (mac_type, rloc_ip, access_tunnel) from the row's TYPE + interface."""
    intf = (interface or "").strip()
    rloc_match = _RLOC_RE.match(intf)
    if rloc_match:
        return ("cp_learn", rloc_match.group("ip"), None)
    at_match = _ACCESS_TUNNEL_RE.match(intf)
    if at_match:
        return ("cp_learn", None, at_match.group("intf"))
    if _is_cp_learned_iface(intf):
        # L2LISP / Tu / LISP — overlay egress without an explicit RLOC/AT token.
        return ("cp_learn", None, None)
    t = (type_field or "").strip().upper()
    if t == "STATIC":
        return ("static", None, None)
    if t == "DYNAMIC":
        return ("dynamic", None, None)
    # Some releases emit literal "CP_LEARN" in the TYPE column.
    if t in ("CP_LEARN", "CP-LEARN", "CPLEARN"):
        return ("cp_learn", None, None)
    return ("dynamic" if intf else "missing", None, None)


def _row_from_genie(parsed: Any, mac_canon: str, vlan: int) -> Optional[dict]:
    """Pick the row for (mac, vlan) out of either Genie schema we see in the wild.

    Older parser shape: {"macAddress": {"<mac>": {"Type": ..., "Ports": ..., "VLAN": ...}}}
    Modern shape:       {"mac_table": {"vlans": {"<vlan>": {"mac_addresses":
                          {"<mac>": {"interfaces": {"<intf>": {"entry_type": ...}}}}}}}}
    Returns a normalized {"type": str, "interface": str, "vlan": int} dict, or None.
    """
    if not isinstance(parsed, dict):
        return None

    legacy = parsed.get("macAddress")
    if isinstance(legacy, dict):
        for key in (mac_canon, mac_canon.upper(), mac_canon.replace(".", "")):
            row = legacy.get(key)
            if isinstance(row, dict):
                return {
                    "type": row.get("Type") or row.get("type"),
                    "interface": row.get("Ports") or row.get("ports") or row.get("Port"),
                    "vlan": row.get("VLAN") or row.get("vlan") or vlan,
                }

    modern = parsed.get("mac_table", {}).get("vlans", {})
    if isinstance(modern, dict):
        vlan_blob = modern.get(str(vlan)) or modern.get(vlan)
        macs = (vlan_blob or {}).get("mac_addresses") or {}
        entry = macs.get(mac_canon) or macs.get(mac_canon.upper())
        if isinstance(entry, dict):
            interfaces = entry.get("interfaces") or {}
            for intf_name, intf_blob in interfaces.items():
                return {
                    "type": (intf_blob or {}).get("entry_type"),
                    "interface": intf_name,
                    "vlan": vlan,
                }

    return None


def _row_from_raw_text(text: str, mac_canon: str, vlan: int) -> Optional[dict]:
    """Regex fallback when no Genie parser is available.

    The standard IOS-XE table looks like:
        Vlan    Mac Address       Type        Ports
        ----    -----------       --------    -----
        1234    aabb.ccdd.eeff    DYNAMIC     Te1/0/4
    For LISP-imported entries the Ports column contains "RLOC 10.0.0.1" or
    "AccessTunnel0" — the column-based split below preserves that whitespace.
    """
    if not text:
        return None
    pattern = re.compile(
        r"^\s*(?P<vlan>\d+)\s+"
        r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<ports>.+?)\s*$",
        re.MULTILINE,
    )
    for m in pattern.finditer(text):
        if m.group("mac").lower() != mac_canon:
            continue
        try:
            row_vlan = int(m.group("vlan"))
        except ValueError:
            continue
        if row_vlan != vlan:
            continue
        return {
            "type": m.group("type"),
            "interface": m.group("ports").strip(),
            "vlan": row_vlan,
        }
    return None


def validate_mac_programming(inp: MacProgrammingInput, service) -> MacProgrammingResult:
    """Run the MAC-table query and classify the result.

    `service` is the radkit Service handle used by the rest of the codebase;
    we go through radkit_cli to stay consistent with logging/error handling.
    """
    mac_canon = canonicalize_mac(inp.mac)
    cmd = f"show mac address-table address {mac_canon} vlan {inp.vlan}"

    parsed = None
    try:
        parsed = radkit_cli.get_single_output_genie(inp.hostname, cmd, service)
    except BaseException:
        parsed = None

    raw_text = ""
    try:
        raw_text = radkit_cli.get_any_single_output(inp.hostname, cmd, service) or ""
    except BaseException:
        raw_text = ""

    row = _row_from_genie(parsed, mac_canon, inp.vlan) if parsed else None
    if row is None:
        row = _row_from_raw_text(raw_text, mac_canon, inp.vlan)

    if row is None:
        return MacProgrammingResult(
            programmed=False,
            mac_type="missing",
            raw_cli=raw_text,
            raw_parsed=parsed if isinstance(parsed, dict) else {},
        )

    mac_type, rloc_ip, access_tunnel = _classify(row.get("type"), row.get("interface"))
    interface = (row.get("interface") or "").strip() or None

    matches_expected: Optional[bool] = None
    if inp.expected_interface:
        # Allow case-insensitive prefix match so callers that pass "Te1/0/4"
        # match a CLI line that emitted "TenGigabitEthernet1/0/4".
        exp = inp.expected_interface.strip().lower()
        actual = (interface or "").lower()
        matches_expected = (
            exp == actual
            or actual.startswith(exp)
            or exp.startswith(actual[: len(exp)]) if actual else False
        )

    return MacProgrammingResult(
        programmed=True,
        mac_type=mac_type,
        interface=interface,
        rloc_ip=rloc_ip,
        access_tunnel=access_tunnel,
        matches_expected=matches_expected,
        raw_cli=raw_text,
        raw_parsed=parsed if isinstance(parsed, dict) else {},
    )


def _fed_switch_token(inp: MacProgrammingInput) -> str:
    if inp.switch_member is not None:
        return f"switch {int(inp.switch_member)}"
    if inp.sup_role:
        return f"switch {inp.sup_role}"
    return "switch active"


_FED_ROW_RE = re.compile(
    r"^\s*(?P<vlan>\d+)\s+"
    r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<rest>.+?)\s*$",
    re.MULTILINE,
)


def _fed_parse(text: str, mac_canon: str, vlan: int) -> Optional[dict]:
    """Pull the row for (mac, vlan) out of FED MATM output.

    Header (Catalyst 9k 17.x):
        VLAN MAC Type Seq# EC_Bi Flags machandle siHandle riHandle diHandle
        *a_time *e_time ports Con
    `Con` is absent on older releases. `ports` may contain a single token
    (TenGigabitEthernet1/0/4, RLOC, AccessTunnelN, ...).
    """
    if not text:
        return None
    for m in _FED_ROW_RE.finditer(text):
        if m.group("mac").lower() != mac_canon:
            continue
        try:
            row_vlan = int(m.group("vlan"))
        except ValueError:
            continue
        if row_vlan != vlan:
            continue
        tokens = m.group("rest").split()
        names = ["type", "seq", "ec_bi", "flags", "machandle", "si_handle",
                 "ri_handle", "di_handle", "a_time", "e_time", "ports", "con"]
        fields_ = {}
        for name, value in zip(names, tokens):
            fields_[name] = value
        # FED prints overlay egress as "RLOC 10.0.0.1" — two whitespace-split
        # tokens that should be treated as one logical port. When we see that
        # shape, fold the IP into the ports column and capture it separately.
        ip_re = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
        if (
            fields_.get("ports", "").upper() == "RLOC"
            and len(tokens) >= 12
            and ip_re.match(tokens[11])
        ):
            fields_["rloc_ip"] = tokens[11]
            fields_["ports"] = f"RLOC {tokens[11]}"
            fields_["con"] = tokens[12] if len(tokens) > 12 else None
        fields_["raw_row"] = m.group(0).strip()
        fields_["tokens"] = tokens
        return fields_
    return None


def validate_fed_mac_programming(inp: MacProgrammingInput, service) -> FedMacResult:
    """Hardware MATM view from FED. Returns programmed=False if the MAC isn't
    in the FED table for that VLAN. Caller decides what to do when this and
    `validate_mac_programming` disagree."""
    mac_canon = canonicalize_mac(inp.mac)
    sw = _fed_switch_token(inp)
    cmd = f"show platform software fed {sw} matm macTable vlan {inp.vlan} mac {mac_canon}"

    raw_text = ""
    try:
        raw_text = radkit_cli.get_any_single_output(inp.hostname, cmd, service) or ""
    except BaseException:
        raw_text = ""

    row = _fed_parse(raw_text, mac_canon, inp.vlan)
    if row is None:
        return FedMacResult(programmed=False, raw_cli=raw_text)

    return FedMacResult(
        programmed=True,
        interface=row.get("ports"),
        rloc_ip=row.get("rloc_ip"),
        type=row.get("type"),
        flags=row.get("flags"),
        seq=row.get("seq"),
        ec_bi=row.get("ec_bi"),
        machandle=row.get("machandle"),
        si_handle=row.get("si_handle"),
        ri_handle=row.get("ri_handle"),
        di_handle=row.get("di_handle"),
        a_time=row.get("a_time"),
        e_time=row.get("e_time"),
        con=row.get("con"),
        raw_cli=raw_text,
        raw_fields=row,
    )


@dataclass
class MacComparisonResult:
    status: ComparisonStatus
    detail: str
    ios_interface: Optional[str] = None
    fed_interface: Optional[str] = None
    queried_switch_member: Optional[int] = None
    interface_switch_member: Optional[int] = None


_IFACE_SPLIT_RE = re.compile(r"^([A-Za-z\-]+)(\d.*)$")


def _split_iface(name: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Split 'TenGigabitEthernet1/0/4' → ('tengigabitethernet', '1/0/4')."""
    if not name:
        return (None, None)
    m = _IFACE_SPLIT_RE.match(name.strip())
    if not m:
        return (None, None)
    return (m.group(1).lower(), m.group(2))


def _interfaces_equal(a: Optional[str], b: Optional[str]) -> bool:
    """Match Cisco interface names allowing abbreviation: Te1/0/4 == TenGigabitEthernet1/0/4."""
    pa, ta = _split_iface(a)
    pb, tb = _split_iface(b)
    if not (pa and pb and ta and tb):
        return False
    if ta != tb:
        return False
    return pa.startswith(pb) or pb.startswith(pa)


_NON_PHYSICAL_PREFIXES = ("rloc", "accesstunnel", "vlan", "loopback",
                          "tunnel", "port-channel", "po", "lisp")


def _is_physical(iface: Optional[str]) -> bool:
    """True if `iface` looks like a stacked-physical port (Te1/0/4, Gi2/0/24)."""
    prefix, tail = _split_iface(iface)
    if not (prefix and tail):
        return False
    if any(prefix.startswith(p) for p in _NON_PHYSICAL_PREFIXES):
        return False
    # Physical ports start with member/slot/port (at least two '/').
    return tail.count("/") >= 2


def _switch_member_of(iface: Optional[str]) -> Optional[int]:
    """Return the stack member implied by a physical interface name, or None."""
    if not _is_physical(iface):
        return None
    _, tail = _split_iface(iface)
    head = tail.split("/", 1)[0] if tail else ""
    try:
        return int(head)
    except ValueError:
        return None


def compare_mac_programming(
    ios: MacProgrammingResult,
    fed: FedMacResult,
    queried_switch_member: Optional[int] = None,
) -> MacComparisonResult:
    """Cross-check software MAC table against FED MATM. Encodes the four
    triage scenarios:

      1. match           — interfaces agree (abbreviation-tolerant).
      2. wrong_member    — queried switch ≠ interface's stack member; FED
                           state is expected to disagree, ignore.
      3. misprogrammed   — IOS has the MAC but FED is either missing or
                           reports a different interface, on the correct
                           switch member. Investigate TCAM, RP→FMAN→FED.
      4. ios_missing     — no IOS entry; nothing to compare.
    """
    ios_intf = ios.interface if ios.programmed else None
    fed_intf = fed.interface if fed.programmed else None
    iface_member = _switch_member_of(ios_intf) if ios_intf else None

    if not ios.programmed:
        return MacComparisonResult(
            status="ios_missing",
            detail="IOS MAC table has no entry; FED comparison not applicable.",
            ios_interface=ios_intf,
            fed_interface=fed_intf,
            queried_switch_member=queried_switch_member,
            interface_switch_member=iface_member,
        )

    # Control-plane / overlay-learned MACs (L2LISP, Tu, RLOC, AccessTunnel,
    # LISP) live on the active sup only — switch_member doesn't apply, and
    # FED encodes the same egress as RLOC / AccessTunnel.
    ios_is_cp = ios.mac_type == "cp_learn" or _is_cp_learned_iface(ios_intf)
    if ios_is_cp:
        if not fed.programmed:
            return MacComparisonResult(
                status="misprogrammed",
                detail=(
                    f"IOS shows {ios_intf} (CP-learned) but FED has no MATM entry. "
                    f"Hardware programming missing — check TCAM exhaustion and the "
                    f"RP→FMAN→FED object chain."
                ),
                ios_interface=ios_intf,
                fed_interface=fed_intf,
                queried_switch_member=queried_switch_member,
                interface_switch_member=iface_member,
            )
        if _is_cp_learned_iface(fed_intf):
            return MacComparisonResult(
                status="match",
                detail=f"IOS shows {ios_intf} and FED shows {fed_intf} — both CP-learned.",
                ios_interface=ios_intf,
                fed_interface=fed_intf,
                queried_switch_member=queried_switch_member,
                interface_switch_member=iface_member,
            )
        return MacComparisonResult(
            status="misprogrammed",
            detail=(
                f"IOS shows {ios_intf} (CP-learned) but FED has {fed_intf} — "
                f"expected an RLOC / AccessTunnel egress. Hardware programming "
                f"diverges from software."
            ),
            ios_interface=ios_intf,
            fed_interface=fed_intf,
            queried_switch_member=queried_switch_member,
            interface_switch_member=iface_member,
        )

    # Wrong-member only applies to physical IOS interfaces.
    if (
        queried_switch_member is not None
        and iface_member is not None
        and queried_switch_member != iface_member
    ):
        return MacComparisonResult(
            status="wrong_member",
            detail=(
                f"IOS shows {ios_intf} (member {iface_member}) but FED was queried "
                f"on switch {queried_switch_member}. Mismatch is expected — re-run "
                f"with --switch-member {iface_member}."
            ),
            ios_interface=ios_intf,
            fed_interface=fed_intf,
            queried_switch_member=queried_switch_member,
            interface_switch_member=iface_member,
        )

    if not fed.programmed:
        return MacComparisonResult(
            status="misprogrammed",
            detail=(
                f"IOS shows {ios_intf} but FED has no MATM entry on this switch. "
                f"Hardware programming missing — check TCAM exhaustion and the "
                f"RP→FMAN→FED object chain."
            ),
            ios_interface=ios_intf,
            fed_interface=fed_intf,
            queried_switch_member=queried_switch_member,
            interface_switch_member=iface_member,
        )

    if _interfaces_equal(ios_intf, fed_intf):
        return MacComparisonResult(
            status="match",
            detail=f"IOS and FED agree on {ios_intf}.",
            ios_interface=ios_intf,
            fed_interface=fed_intf,
            queried_switch_member=queried_switch_member,
            interface_switch_member=iface_member,
        )

    return MacComparisonResult(
        status="misprogrammed",
        detail=(
            f"IOS shows {ios_intf} but FED has {fed_intf}. Hardware programming "
            f"diverges from software — check TCAM exhaustion and the RP→FMAN→FED "
            f"object chain."
        ),
        ios_interface=ios_intf,
        fed_interface=fed_intf,
        queried_switch_member=queried_switch_member,
        interface_switch_member=iface_member,
    )
