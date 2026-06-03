"""IPv4 adjacency programming validation.

Software view:  `show adjacency [vrf <name>] <addr> [vlan <id>] detail`
Hardware view:  `show platform software fed switch active ip adj <addr> detail`

The adjacency tells you the L2 rewrite (dest MAC, src MAC, ethertype) that
will be stamped on packets toward `<addr>`. Validation pairs the software
adjacency entry with FED's hardware adj table — they must agree on:

  - egress interface (e.g. Vlan1021)
  - destination MAC
  - the IP address itself

FED is queried on `switch active` regardless of caller-provided sup/member.
FED's `ip adj` has no per-vrf filter, so the VRF parameter only shapes the
IOS command.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import re

import radkit_cli

from programming.mac import (
    SupRole,
    ComparisonStatus,
    canonicalize_mac,
)


@dataclass
class AdjacencyInput:
    hostname: str
    address: str
    vrf: Optional[str] = None
    vlan: Optional[int] = None
    sup_role: Optional[SupRole] = None  # accepted for parity; FED always active.

    def __post_init__(self):
        if not self.address:
            raise ValueError("AdjacencyInput.address is mandatory.")


@dataclass
class IosAdjacencyResult:
    programmed: bool
    protocol: Optional[str] = None
    interface: Optional[str] = None
    address: Optional[str] = None
    encap_hex: Optional[str] = None
    encap_length: Optional[int] = None
    dst_mac: Optional[str] = None
    src_mac: Optional[str] = None
    ethertype: Optional[str] = None
    source: Optional[str] = None  # ARP, LISP, etc.
    raw_cli: str = ""


@dataclass
class FedAdjacencyResult:
    programmed: bool
    address: Optional[str] = None
    interface: Optional[str] = None
    dst_mac: Optional[str] = None
    si_hdl: Optional[str] = None
    ri_hdl: Optional[str] = None
    adj_id: Optional[str] = None
    pd_flags: Optional[str] = None
    pmap_interfaces: list[str] = field(default_factory=list)
    raw_cli: str = ""
    raw_fields: dict = field(default_factory=dict)


@dataclass
class AdjacencyComparisonResult:
    status: ComparisonStatus
    detail: str
    address: Optional[str] = None
    ios_interface: Optional[str] = None
    fed_interface: Optional[str] = None
    ios_dst_mac: Optional[str] = None
    fed_dst_mac: Optional[str] = None


_DEFAULT_VRF_TOKENS = (None, "", "default", "DEFAULT")


def _vrf_clause(vrf: Optional[str]) -> str:
    return "" if vrf in _DEFAULT_VRF_TOKENS else f"vrf {vrf} "


# IOS layout:
#   Protocol Interface                 Address
#   IP       Vlan1021                  172.19.10.10(8)
#                                      Encap length 14
#                                      AAAABBBBDDDD00000C9FFA7E0800
#                                      ...
#                                      ARP
_IOS_HEADER_RE = re.compile(
    r"^\s*(?P<protocol>IP|IPV6|MPLS|TAG)\s+"
    r"(?P<intf>\S+)\s+"
    r"(?P<addr>\d+\.\d+\.\d+\.\d+|[0-9A-Fa-f:]+)\s*\(?\d*\)?",
    re.MULTILINE,
)
_IOS_ENCAP_LEN_RE = re.compile(r"Encap length\s+(\d+)", re.IGNORECASE)
_IOS_ENCAP_HEX_RE = re.compile(r"^\s*([0-9A-Fa-f]{20,})\s*$", re.MULTILINE)
_IOS_SOURCE_RE = re.compile(r"^\s*(ARP|LISP|incomplete|punt|drop)\s*$",
                            re.MULTILINE | re.IGNORECASE)
_IOS_NOT_FOUND_RE = re.compile(
    r"%\s*Adjacency\s+not\s+found|%\s*No\s+adjacency", re.IGNORECASE
)


def _hex_to_mac(hex12: str) -> Optional[str]:
    if not hex12 or len(hex12) != 12:
        return None
    s = hex12.lower()
    return f"{s[0:4]}.{s[4:8]}.{s[8:12]}"


def validate_adjacency_programming(inp: AdjacencyInput, service) -> IosAdjacencyResult:
    """Run `show adjacency ... detail` and pull encap + interface.

    Note: `show adjacency` does NOT take a VRF argument — adjacencies are
    keyed on (interface, address). The `vrf` field on AdjacencyInput is
    accepted for API parity (CEF passes it through) but is intentionally
    unused here.
    """
    vlan_clause = f" vlan {inp.vlan}" if inp.vlan is not None else ""
    cmd = f"show adjacency {inp.address}{vlan_clause} detail"
    raw_text = ""
    try:
        raw_text = radkit_cli.get_any_single_output(inp.hostname, cmd, service) or ""
    except BaseException:
        raw_text = ""

    if not raw_text or _IOS_NOT_FOUND_RE.search(raw_text):
        return IosAdjacencyResult(programmed=False, raw_cli=raw_text)

    header = _IOS_HEADER_RE.search(raw_text)
    if header is None:
        return IosAdjacencyResult(programmed=False, raw_cli=raw_text)

    encap_len_m = _IOS_ENCAP_LEN_RE.search(raw_text)
    encap_length = int(encap_len_m.group(1)) if encap_len_m else None

    encap_hex: Optional[str] = None
    for m in _IOS_ENCAP_HEX_RE.finditer(raw_text):
        candidate = m.group(1)
        if encap_length and len(candidate) >= encap_length * 2:
            encap_hex = candidate.lower()
            break
        encap_hex = encap_hex or candidate.lower()

    dst_mac = _hex_to_mac(encap_hex[0:12]) if encap_hex else None
    src_mac = _hex_to_mac(encap_hex[12:24]) if encap_hex and len(encap_hex) >= 24 else None
    ethertype = (encap_hex[24:28] if encap_hex and len(encap_hex) >= 28 else None)

    src_m = _IOS_SOURCE_RE.search(raw_text)
    source = src_m.group(1).upper() if src_m else None

    return IosAdjacencyResult(
        programmed=True,
        protocol=header.group("protocol"),
        interface=header.group("intf"),
        address=header.group("addr"),
        encap_hex=encap_hex,
        encap_length=encap_length,
        dst_mac=dst_mac,
        src_mac=src_mac,
        ethertype=ethertype,
        source=source,
        raw_cli=raw_text,
    )


# FED row (Cat9k 17.x):
#   dest                  if_name      dst_mac          si_hdl         ri_hdl         pd_flags adj_id
#   172.19.10.10          Vlan1021     aaaa.bbbb.dddd   0x7f...        0x7f...        0x0      0xbc
_FED_ROW_RE = re.compile(
    r"^\s*(?P<dest>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<intf>\S+)\s+"
    r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
    r"(?P<si>0x[0-9a-fA-F]+)\s+"
    r"(?P<ri>0x[0-9a-fA-F]+)\s+"
    r"(?P<pd>0x[0-9a-fA-F]+)\s+"
    r"(?P<adj>0x[0-9a-fA-F]+)",
    re.MULTILINE,
)
_FED_PMAP_INTF_RE = re.compile(r"pmap_intf\s*:\s*\[(?P<intf>[^\]]+)\]", re.IGNORECASE)


def validate_fed_adjacency_programming(
    address: str, hostname: str, service
) -> FedAdjacencyResult:
    """FED adj table is global — VRF doesn't shape this query."""
    cmd = f"show platform software fed switch active ip adj {address} detail"
    raw_text = ""
    try:
        raw_text = radkit_cli.get_any_single_output(hostname, cmd, service) or ""
    except BaseException:
        raw_text = ""

    if not raw_text:
        return FedAdjacencyResult(programmed=False, raw_cli=raw_text)

    matched_row = None
    for m in _FED_ROW_RE.finditer(raw_text):
        if m.group("dest") == address:
            matched_row = m
            break
    if matched_row is None:
        return FedAdjacencyResult(programmed=False, raw_cli=raw_text)

    pmap_intfs: list[str] = []
    for pm in _FED_PMAP_INTF_RE.finditer(raw_text):
        intf = pm.group("intf").strip()
        if intf and intf not in pmap_intfs:
            pmap_intfs.append(intf)

    return FedAdjacencyResult(
        programmed=True,
        address=matched_row.group("dest"),
        interface=matched_row.group("intf"),
        dst_mac=canonicalize_mac(matched_row.group("mac")),
        si_hdl=matched_row.group("si"),
        ri_hdl=matched_row.group("ri"),
        pd_flags=matched_row.group("pd"),
        adj_id=matched_row.group("adj"),
        pmap_interfaces=pmap_intfs,
        raw_cli=raw_text,
        raw_fields={"raw_row": matched_row.group(0).strip()},
    )


def _interfaces_equal(a: Optional[str], b: Optional[str]) -> bool:
    """Cisco interface compare with abbreviation tolerance (Vlan1021 == Vl1021)."""
    if not a or not b:
        return False
    sa, sb = a.strip().lower(), b.strip().lower()
    if sa == sb:
        return True
    return sa.startswith(sb) or sb.startswith(sa)


def compare_adjacency_programming(
    ios: IosAdjacencyResult, fed: FedAdjacencyResult
) -> AdjacencyComparisonResult:
    """Match requires: same address, same egress interface (abbreviation
    tolerant), same destination MAC."""
    if not ios.programmed:
        return AdjacencyComparisonResult(
            status="ios_missing",
            detail="IOS adjacency table has no entry; FED comparison not applicable.",
        )
    if not fed.programmed:
        return AdjacencyComparisonResult(
            status="misprogrammed",
            detail=(
                f"IOS adjacency present for {ios.address} on {ios.interface} "
                f"({ios.dst_mac}) but FED has no hardware adj. Check TCAM "
                f"exhaustion and the RP→FMAN→FED object chain."
            ),
            address=ios.address,
            ios_interface=ios.interface,
            ios_dst_mac=ios.dst_mac,
        )

    same_addr = ios.address == fed.address
    same_intf = _interfaces_equal(ios.interface, fed.interface)
    same_mac = (ios.dst_mac or "").lower() == (fed.dst_mac or "").lower()

    if same_addr and same_intf and same_mac:
        return AdjacencyComparisonResult(
            status="match",
            detail=(
                f"IOS and FED agree on {ios.address} via {ios.interface} → {ios.dst_mac}."
            ),
            address=ios.address,
            ios_interface=ios.interface,
            fed_interface=fed.interface,
            ios_dst_mac=ios.dst_mac,
            fed_dst_mac=fed.dst_mac,
        )

    diffs = []
    if not same_addr:
        diffs.append(f"address (IOS={ios.address} FED={fed.address})")
    if not same_intf:
        diffs.append(f"interface (IOS={ios.interface} FED={fed.interface})")
    if not same_mac:
        diffs.append(f"dst_mac (IOS={ios.dst_mac} FED={fed.dst_mac})")
    return AdjacencyComparisonResult(
        status="misprogrammed",
        detail=f"Adjacency disagreement on {ios.address}: " + "; ".join(diffs),
        address=ios.address,
        ios_interface=ios.interface,
        fed_interface=fed.interface,
        ios_dst_mac=ios.dst_mac,
        fed_dst_mac=fed.dst_mac,
    )
