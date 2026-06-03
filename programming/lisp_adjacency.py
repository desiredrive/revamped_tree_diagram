"""LISP adjacency programming validation.

Software view:  `show adjacency lisp0.<iid> <rloc> detail`
Hardware view:  `show platform software fed switch active ip lisp adj rloc <rloc>`

LISP adjacencies are distinct from regular IPv4 adjacencies — the egress is
the LISP virtual interface (lisp0.<instance-id>), and the encap is a 50-byte
VXLAN rewrite (outer Ethernet + outer IPv4 + UDP + VXLAN/LISP shim) toward the
RLOC. The next-chain step then resolves through the underlay adjacency.

Validation pairs the software entry with FED's LISP adj table — both must
agree on RLOC, LISP instance ID, and the destination MAC of the underlay
rewrite.

FED is queried on `switch active` regardless of caller-provided sup/member.
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
class LispAdjacencyInput:
    hostname: str
    rloc: str                       # underlay RLOC IP (e.g. 172.19.1.64).
    instance_id: int                # LISP IID — names the lisp0 sub-iface.
    sup_role: Optional[SupRole] = None  # parity only; FED is always active.

    def __post_init__(self):
        if not self.rloc:
            raise ValueError("LispAdjacencyInput.rloc is mandatory.")
        if self.instance_id is None:
            raise ValueError("LispAdjacencyInput.instance_id is mandatory.")


@dataclass
class IosLispAdjacencyResult:
    programmed: bool
    lisp_interface: Optional[str] = None     # e.g. LISP0.4099
    instance_id: Optional[int] = None
    rloc: Optional[str] = None
    encap_hex: Optional[str] = None          # IPv4 outer header bytes; no L2.
    encap_length: Optional[int] = None       # 50 for VXLAN.
    next_chain_address: Optional[str] = None  # underlay nexthop walked to
    next_chain_interface: Optional[str] = None
    raw_cli: str = ""


@dataclass
class FedLispAdjacencyResult:
    programmed: bool
    rloc: Optional[str] = None
    if_name: Optional[str] = None            # e.g. LISP0.4099
    instance_id: Optional[int] = None        # parsed from if_name
    si_hdl: Optional[str] = None
    ri_hdl: Optional[str] = None
    pd_flags: Optional[str] = None
    adj_id: Optional[str] = None
    adj_handle: Optional[str] = None
    encap_iid: Optional[str] = None
    raw_cli: str = ""
    raw_fields: dict = field(default_factory=dict)


@dataclass
class LispAdjacencyComparisonResult:
    status: ComparisonStatus
    detail: str
    rloc: Optional[str] = None
    instance_id: Optional[int] = None
    ios_if_name: Optional[str] = None
    fed_if_name: Optional[str] = None


# IOS layout (Cat9k 17.x, IPv4 path only — IPv6 sibling row is skipped):
#   Protocol Interface                 Address
#   IP       LISP0.4099                172.19.1.64(N)
#                                      Encap length 50
#                                      AAAABBBB....  (100 hex chars)
#                                      LISP
#                                      Next chain element:
#                                        IP adj out of GigabitEthernet1/0/1, addr 10.0.0.1
_IOS_HEADER_RE = re.compile(
    r"^\s*IP\s+(?P<intf>LISP\d+(?:\.\d+)?)\s+"
    r"(?P<rloc>\d+\.\d+\.\d+\.\d+)\s*\(?\d*\)?",
    re.MULTILINE | re.IGNORECASE,
)
_IOS_ENCAP_LEN_RE = re.compile(r"Encap length\s+(\d+)", re.IGNORECASE)
_IOS_ENCAP_HEX_RE = re.compile(r"^\s*([0-9A-Fa-f]{40,})\s*$", re.MULTILINE)
_IOS_NEXT_CHAIN_RE = re.compile(
    r"IP\s+adj\s+out\s+of\s+(?P<intf>\S+?),\s*addr\s+(?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)
_IOS_NOT_FOUND_RE = re.compile(
    r"%\s*Adjacency\s+not\s+found|%\s*No\s+adjacency", re.IGNORECASE
)
_IOS_LISP_IID_RE = re.compile(r"LISP\d+\.(\d+)", re.IGNORECASE)


def _hex_to_mac(hex12: str) -> Optional[str]:
    if not hex12 or len(hex12) != 12:
        return None
    s = hex12.lower()
    return f"{s[0:4]}.{s[4:8]}.{s[8:12]}"


def validate_lisp_adjacency_programming(
    inp: LispAdjacencyInput, service
) -> IosLispAdjacencyResult:
    """Run `show adjacency lisp0.<iid> <rloc> detail` and pull encap + next-chain."""
    cmd = f"show adjacency lisp0.{inp.instance_id} {inp.rloc} detail"
    raw_text = ""
    try:
        raw_text = radkit_cli.get_any_single_output(inp.hostname, cmd, service) or ""
    except BaseException:
        raw_text = ""

    if not raw_text or _IOS_NOT_FOUND_RE.search(raw_text):
        return IosLispAdjacencyResult(programmed=False, raw_cli=raw_text)

    header = _IOS_HEADER_RE.search(raw_text)
    if header is None:
        return IosLispAdjacencyResult(programmed=False, raw_cli=raw_text)

    iid_m = _IOS_LISP_IID_RE.search(header.group("intf"))
    iid = int(iid_m.group(1)) if iid_m else None

    encap_len_m = _IOS_ENCAP_LEN_RE.search(raw_text)
    encap_length = int(encap_len_m.group(1)) if encap_len_m else None

    encap_hex: Optional[str] = None
    for m in _IOS_ENCAP_HEX_RE.finditer(raw_text):
        candidate = m.group(1)
        if encap_length and len(candidate) >= encap_length * 2:
            encap_hex = candidate.lower()
            break
        encap_hex = encap_hex or candidate.lower()

    nc_m = _IOS_NEXT_CHAIN_RE.search(raw_text)
    next_intf = nc_m.group("intf") if nc_m else None
    next_addr = nc_m.group("ip") if nc_m else None

    return IosLispAdjacencyResult(
        programmed=True,
        lisp_interface=header.group("intf"),
        instance_id=iid,
        rloc=header.group("rloc"),
        encap_hex=encap_hex,
        encap_length=encap_length,
        next_chain_address=next_addr,
        next_chain_interface=next_intf,
        raw_cli=raw_text,
    )


# FED LISP adj table (Cat9k 17.x):
#   IPV4 Lisp Adj entries
#   RLOC          if_name      si_hdl          ri_hdl          pd_flags  adj_id    adj_handle    encap_iid   ref count
#   ----          -------      ------          ------          --------  ------    ----------    ---------   ---------
#   172.19.1.64   LISP0.4099   0x7f71e4e4ee98  0x7f71e4e508b8  0x60      0x9e      0x4400004a    -           -
#   172.19.1.64   LISP0.4100   0x7f71e4e6daa8  0x7f71e4e6dc58  0x60      0xad      0x3d00004c    -           -
#
# A given RLOC has one row per LISP instance — filter by both RLOC and IID.
# This command does not surface dst_mac / src_ip / dst_ip; those live in the
# resource-handle dump, which we can layer in later if needed.
_FED_ROW_RE = re.compile(
    r"^\s*(?P<rloc>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<if_name>LISP\d+(?:\.\d+)?)\s+"
    r"(?P<si>0x[0-9a-fA-F]+)\s+"
    r"(?P<ri>0x[0-9a-fA-F]+)\s+"
    r"(?P<pd>0x[0-9a-fA-F]+)\s+"
    r"(?P<adj_id>0x[0-9a-fA-F]+)\s+"
    r"(?P<adj_handle>0x[0-9a-fA-F]+)\s+"
    r"(?P<encap_iid>\S+)\s+"
    r"(?P<ref>\S+)",
    re.MULTILINE,
)
_FED_NOT_FOUND_RE = re.compile(
    r"(no entry|not found|%\s*Invalid|object not found)", re.IGNORECASE
)
_FED_IF_IID_RE = re.compile(r"LISP\d+\.(\d+)", re.IGNORECASE)


def validate_fed_lisp_adjacency_programming(
    rloc: str, hostname: str, service, instance_id: Optional[int] = None
) -> FedLispAdjacencyResult:
    """FED LISP adj table is global to the active sup. The command lists one
    row per (RLOC, LISP IID); supply `instance_id` to disambiguate when more
    than one row matches the RLOC.
    """
    cmd = f"show platform software fed switch active ip lisp adj rloc {rloc}"
    raw_text = ""
    try:
        raw_text = radkit_cli.get_any_single_output(hostname, cmd, service) or ""
    except BaseException:
        raw_text = ""

    if not raw_text or _FED_NOT_FOUND_RE.search(raw_text):
        return FedLispAdjacencyResult(programmed=False, raw_cli=raw_text)

    matched = None
    for m in _FED_ROW_RE.finditer(raw_text):
        if m.group("rloc") != rloc:
            continue
        if instance_id is not None:
            iid_m = _FED_IF_IID_RE.search(m.group("if_name"))
            if iid_m and int(iid_m.group(1)) != instance_id:
                continue
        matched = m
        break

    if matched is None:
        return FedLispAdjacencyResult(programmed=False, raw_cli=raw_text)

    iid_m = _FED_IF_IID_RE.search(matched.group("if_name"))
    parsed_iid = int(iid_m.group(1)) if iid_m else None

    return FedLispAdjacencyResult(
        programmed=True,
        rloc=matched.group("rloc"),
        if_name=matched.group("if_name"),
        instance_id=parsed_iid,
        si_hdl=matched.group("si"),
        ri_hdl=matched.group("ri"),
        pd_flags=matched.group("pd"),
        adj_id=matched.group("adj_id"),
        adj_handle=matched.group("adj_handle"),
        encap_iid=matched.group("encap_iid"),
        raw_cli=raw_text,
        raw_fields={"raw_row": matched.group(0).strip()},
    )


def compare_lisp_adjacency_programming(
    ios: IosLispAdjacencyResult, fed: FedLispAdjacencyResult
) -> LispAdjacencyComparisonResult:
    """Match requires: same RLOC and same LISP instance ID. There is no L2
    rewrite in this adjacency (`L2 destination address byte length 0`), so
    MAC comparison happens in the underlay adjacency walked via the IOS
    next-chain element.
    """
    if not ios.programmed:
        return LispAdjacencyComparisonResult(
            status="ios_missing",
            detail="IOS LISP adjacency has no entry; FED comparison not applicable.",
        )
    if not fed.programmed:
        return LispAdjacencyComparisonResult(
            status="misprogrammed",
            detail=(
                f"IOS LISP adjacency present for RLOC {ios.rloc} via "
                f"{ios.lisp_interface} but FED has no hardware LISP adj row "
                f"for that (RLOC, IID). Check TCAM exhaustion and the "
                f"RP→FMAN→FED object chain."
            ),
            rloc=ios.rloc,
            instance_id=ios.instance_id,
            ios_if_name=ios.lisp_interface,
        )

    same_rloc = (ios.rloc or "") == (fed.rloc or "")
    same_iid = (
        ios.instance_id is not None
        and fed.instance_id is not None
        and ios.instance_id == fed.instance_id
    )

    if same_rloc and same_iid:
        return LispAdjacencyComparisonResult(
            status="match",
            detail=(
                f"IOS and FED agree on LISP adjacency RLOC {ios.rloc} "
                f"(IID {ios.instance_id}) — IOS via {ios.lisp_interface}, "
                f"FED row {fed.if_name} (adj_id {fed.adj_id})."
            ),
            rloc=ios.rloc,
            instance_id=ios.instance_id,
            ios_if_name=ios.lisp_interface,
            fed_if_name=fed.if_name,
        )

    diffs = []
    if not same_rloc:
        diffs.append(f"rloc (IOS={ios.rloc} FED={fed.rloc})")
    if not same_iid:
        diffs.append(
            f"instance_id (IOS={ios.instance_id} FED={fed.instance_id})"
        )
    return LispAdjacencyComparisonResult(
        status="misprogrammed",
        detail=f"LISP adjacency disagreement: " + "; ".join(diffs),
        rloc=ios.rloc,
        instance_id=ios.instance_id,
        ios_if_name=ios.lisp_interface,
        fed_if_name=fed.if_name,
    )
