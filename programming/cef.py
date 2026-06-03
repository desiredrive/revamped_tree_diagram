"""L3 route (CEF) programming validation.

Software view:  `show ip cef [vrf <name>] <prefix> internal`
Hardware view:  `show platform software fed switch active ip route [vrf <name>] <prefix>/<mask>`

CEF lookups are relaxed — querying 10.1.2.3 may resolve to a less-specific
prefix (e.g. 10.0.0.0/8). FED requires the exact prefix CEF actually
matched, so the FED query is built from CEF's matched_prefix/mask, NOT
from the caller's input.

FED is queried on `switch active` regardless of caller-provided sup/member.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional
import re

import radkit_cli

from programming.mac import SupRole, ComparisonStatus


@dataclass
class CefProgrammingInput:
    hostname: str
    prefix: str
    mask: Optional[int] = None  # Optional — CEF lookup is relaxed; the matched
                                # mask comes back in CefIosResult.matched_mask.
    vrf: Optional[str] = None
    sup_role: Optional[SupRole] = None  # accepted for API parity; FED always active.

    def __post_init__(self):
        if not self.prefix:
            raise ValueError("CefProgrammingInput.prefix is mandatory.")


@dataclass
class CefIosResult:
    programmed: bool
    matched_prefix: Optional[str] = None
    matched_mask: Optional[int] = None
    nexthops: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    is_receive: bool = False
    is_attached: bool = False  # CEF said "attached to <intf>" — directly on the
                                # wire OR adjacency-type "attached" for a
                                # recursively resolved /32. Distinguish via FED.
    raw_cli: str = ""
    raw_parsed: dict = field(default_factory=dict)


@dataclass
class CefFedResult:
    programmed: bool
    nexthops: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    is_receive: bool = False
    raw_cli: str = ""
    raw_fields: dict = field(default_factory=dict)


@dataclass
class CefComparisonResult:
    status: ComparisonStatus
    detail: str
    matched_prefix: Optional[str] = None
    matched_mask: Optional[int] = None
    ios_nexthops: list[str] = field(default_factory=list)
    fed_nexthops: list[str] = field(default_factory=list)
    ios_interfaces: list[str] = field(default_factory=list)
    fed_interfaces: list[str] = field(default_factory=list)


_DEFAULT_VRF_TOKENS = (None, "", "default", "DEFAULT")


def _vrf_clause(vrf: Optional[str]) -> str:
    return "" if vrf in _DEFAULT_VRF_TOKENS else f"vrf {vrf} "


_PREFIX_HEADER_RE = re.compile(
    r"^\s*(?P<prefix>\d+\.\d+\.\d+\.\d+)/(?P<mask>\d+)\s*,",
    re.MULTILINE,
)
# CEF "internal" lists nexthops on lines like:
#   nexthop 192.168.1.1 GigabitEthernet1/0/1
#   nexthop 10.0.0.5 Vlan100
#   attached to GigabitEthernet1/0/4
# The interface token may be followed by a comma or other punctuation when
# the line continues ("attached to Te1/0/3, adjacency ..."), so we strip
# trailing punctuation after capture.
_NEXTHOP_RE = re.compile(
    r"^\s*nexthop\s+(?P<ip>\d+\.\d+\.\d+\.\d+)(?:\s+(?P<intf>\S+))?",
    re.MULTILINE,
)
_ATTACHED_RE = re.compile(r"^\s*attached to\s+(?P<intf>\S+)", re.MULTILINE)
_RECEIVE_RE = re.compile(r"^\s*receive(?:\s+for\s+(?P<intf>\S+))?", re.MULTILINE | re.IGNORECASE)
_NOT_FOUND_RE = re.compile(r"%\s*(Network not in table|No\s+CEF)", re.IGNORECASE)


def _clean_intf(token: Optional[str]) -> Optional[str]:
    if not token:
        return token
    return token.rstrip(",.;:)")


def validate_cef_programming(inp: CefProgrammingInput, service) -> CefIosResult:
    """Run `show ip cef ... internal` and pull the matched prefix + nexthops."""
    cmd = f"show ip cef {_vrf_clause(inp.vrf)}{inp.prefix} internal"
    raw_text = ""
    try:
        raw_text = radkit_cli.get_any_single_output(inp.hostname, cmd, service) or ""
    except BaseException:
        raw_text = ""

    if not raw_text or _NOT_FOUND_RE.search(raw_text):
        return CefIosResult(programmed=False, raw_cli=raw_text)

    header = _PREFIX_HEADER_RE.search(raw_text)
    if header is None:
        return CefIosResult(programmed=False, raw_cli=raw_text)

    matched_prefix = header.group("prefix")
    try:
        matched_mask = int(header.group("mask"))
    except ValueError:
        matched_mask = None

    nexthops: list[str] = []
    interfaces: list[str] = []
    is_receive = False
    is_attached = False
    for m in _NEXTHOP_RE.finditer(raw_text):
        ip = m.group("ip")
        intf = _clean_intf(m.group("intf"))
        if ip and ip not in nexthops:
            nexthops.append(ip)
        if intf and intf not in interfaces:
            interfaces.append(intf)
    for m in _ATTACHED_RE.finditer(raw_text):
        is_attached = True
        intf = _clean_intf(m.group("intf"))
        if intf and intf not in interfaces:
            interfaces.append(intf)
    for m in _RECEIVE_RE.finditer(raw_text):
        is_receive = True
        intf = _clean_intf(m.group("intf"))
        if intf and intf not in interfaces:
            interfaces.append(intf)

    return CefIosResult(
        programmed=True,
        matched_prefix=matched_prefix,
        matched_mask=matched_mask,
        nexthops=nexthops,
        interfaces=interfaces,
        is_receive=is_receive,
        is_attached=is_attached,
        raw_cli=raw_text,
    )


# FED `ip route` layout (Cat9k 17.x):
#   vrf  dest         htm           flags ...
#   0    0.0.0.0/0    0x7f71e4eabea8 0x0
#     FIB: prefix_hdl:0x70000001 ...
#     ========== OCE chain =====
#     ADJ:objid:146 {link_type:IP ifnum:0x45, adj:0xfc000048, si: 0x...  IPv4: 172.19.2.6 }
# `ifnum` is an opaque numeric handle — not a Cisco interface name — so the
# FED view only contributes nexthop IPs. The interface name comes from CEF.
_FED_ROUTE_ROW_RE = re.compile(
    r"^\s*\d+\s+(?P<prefix>\d+\.\d+\.\d+\.\d+)/(?P<mask>\d+)\s+0x[0-9a-f]+",
    re.MULTILINE | re.IGNORECASE,
)
_FED_ADJ_IPV4_RE = re.compile(r"IPv4:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
_FED_NOT_FOUND_RE = re.compile(
    r"(no entry|not found|%\s*Invalid|object not found)", re.IGNORECASE
)


def validate_fed_cef_programming(
    hostname: str,
    matched_prefix: str,
    matched_mask: int,
    vrf: Optional[str],
    service,
) -> CefFedResult:
    """FED is queried with CEF's matched prefix (NOT the original input)."""
    cmd = (
        f"show platform software fed switch active ip route "
        f"{_vrf_clause(vrf)}{matched_prefix}/{matched_mask}"
    )
    raw_text = ""
    try:
        raw_text = radkit_cli.get_any_single_output(hostname, cmd, service) or ""
    except BaseException:
        raw_text = ""

    if not raw_text or _FED_NOT_FOUND_RE.search(raw_text):
        return CefFedResult(programmed=False, raw_cli=raw_text)

    row = _FED_ROUTE_ROW_RE.search(raw_text)
    if row is None:
        return CefFedResult(programmed=False, raw_cli=raw_text)

    if (
        row.group("prefix") != matched_prefix
        or int(row.group("mask")) != matched_mask
    ):
        # FED returned a different prefix than asked — treat as not-programmed
        # for the queried key; the caller can re-query with the actual prefix.
        return CefFedResult(programmed=False, raw_cli=raw_text)

    nexthops: list[str] = []
    for m in _FED_ADJ_IPV4_RE.finditer(raw_text):
        ip = m.group("ip")
        if ip not in nexthops:
            nexthops.append(ip)

    is_receive = bool(re.search(r"ADJ\s+RECEIVE|objid:ADJ\s+RECEIVE", raw_text, re.IGNORECASE))

    return CefFedResult(
        programmed=True,
        nexthops=nexthops,
        interfaces=[],  # ifnum is opaque; interface name comes from CEF.
        is_receive=is_receive,
        raw_cli=raw_text,
        raw_fields={"prefix": f"{matched_prefix}/{matched_mask}"},
    )


def compare_cef_programming(ios: CefIosResult, fed: CefFedResult) -> CefComparisonResult:
    """Triage CEF vs FED:
      - ios_missing   — CEF has no entry; nothing to validate.
      - misprogrammed — CEF programmed but FED missing, or path lists diverge.
      - match         — both report the same nexthop set (interfaces ignored
                        when nexthops agree; FED sometimes omits the intf token).
    """
    if not ios.programmed:
        return CefComparisonResult(
            status="ios_missing",
            detail="CEF has no entry for this prefix; FED comparison not applicable.",
            matched_prefix=ios.matched_prefix,
            matched_mask=ios.matched_mask,
        )
    if not fed.programmed:
        return CefComparisonResult(
            status="misprogrammed",
            detail=(
                f"CEF programmed {ios.matched_prefix}/{ios.matched_mask} but FED "
                f"has no hardware route. Check TCAM exhaustion and the "
                f"RP→FMAN→FED object chain."
            ),
            matched_prefix=ios.matched_prefix,
            matched_mask=ios.matched_mask,
            ios_nexthops=ios.nexthops,
            ios_interfaces=ios.interfaces,
        )

    if ios.is_receive and fed.is_receive:
        return CefComparisonResult(
            status="match",
            detail=f"CEF and FED agree — {ios.matched_prefix}/{ios.matched_mask} "
                   f"is a receive (local) route.",
            matched_prefix=ios.matched_prefix,
            matched_mask=ios.matched_mask,
            ios_interfaces=ios.interfaces,
        )
    if ios.is_receive ^ fed.is_receive:
        return CefComparisonResult(
            status="misprogrammed",
            detail=(
                f"Receive-route disagreement on {ios.matched_prefix}/{ios.matched_mask}: "
                f"CEF receive={ios.is_receive}, FED receive={fed.is_receive}."
            ),
            matched_prefix=ios.matched_prefix,
            matched_mask=ios.matched_mask,
            ios_nexthops=ios.nexthops,
            fed_nexthops=fed.nexthops,
            ios_interfaces=ios.interfaces,
            fed_interfaces=fed.interfaces,
        )

    ios_nh = set(ios.nexthops)
    fed_nh = set(fed.nexthops)
    if ios_nh and ios_nh == fed_nh:
        return CefComparisonResult(
            status="match",
            detail=f"CEF and FED agree on {ios.matched_prefix}/{ios.matched_mask} "
                   f"with nexthops {sorted(ios_nh)}.",
            matched_prefix=ios.matched_prefix,
            matched_mask=ios.matched_mask,
            ios_nexthops=ios.nexthops,
            fed_nexthops=fed.nexthops,
            ios_interfaces=ios.interfaces,
            fed_interfaces=fed.interfaces,
        )

    # CEF "attached" form with no explicit nexthop (either a directly attached
    # /31/32 or a recursively resolved host /32). FED is authoritative for
    # what hardware will use; trust its nexthops in this case.
    if not ios_nh and ios.is_attached and fed_nh:
        return CefComparisonResult(
            status="match",
            detail=(
                f"CEF programmed {ios.matched_prefix}/{ios.matched_mask} as "
                f"attached on {ios.interfaces or '?'}; FED resolved nexthops "
                f"{sorted(fed_nh)}. Adjacency walk uses FED nexthops."
            ),
            matched_prefix=ios.matched_prefix,
            matched_mask=ios.matched_mask,
            ios_nexthops=ios.nexthops,
            fed_nexthops=fed.nexthops,
            ios_interfaces=ios.interfaces,
            fed_interfaces=fed.interfaces,
        )

    return CefComparisonResult(
        status="misprogrammed",
        detail=(
            f"Nexthop sets differ for {ios.matched_prefix}/{ios.matched_mask}: "
            f"CEF={sorted(ios_nh) or '-'}, FED={sorted(fed_nh) or '-'}."
        ),
        matched_prefix=ios.matched_prefix,
        matched_mask=ios.matched_mask,
        ios_nexthops=ios.nexthops,
        fed_nexthops=fed.nexthops,
        ios_interfaces=ios.interfaces,
        fed_interfaces=fed.interfaces,
    )
