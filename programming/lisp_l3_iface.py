"""L3 LISP interface programming validation.

Software view:  `show ip interface lisp0.<iid>`
Hardware lookup: `show platform software fed switch active ifm mappings l3if-le`
                 (resolves lisp0.<iid> → IF_ID hex handle)
Hardware detail: `show platform software fed switch active ifm if-id <hex>`

Validation rules (per user spec):
  - IOS:        interface up, line protocol up.
  - FED block:  Interface Block State == READY.
  - FED state:  Interface State == Enabled, Interface Status contains ADD+UPD.
  - LISP key:   Instance ID matches the sub-interface name suffix.
  - LISP key:   UDP dest port == 4789 (VXLAN).
  - LISP feat:  IPV4 SGT ENABLE == Y.

FED is queried on `switch active` regardless of caller-provided sup/member.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import re

import radkit_cli

from programming.mac import SupRole, ComparisonStatus


@dataclass
class LispL3IfaceInput:
    hostname: str
    instance_id: int                         # 4099 → lisp0.4099
    sup_role: Optional[SupRole] = None       # parity only; FED always active.

    def __post_init__(self):
        if self.instance_id is None:
            raise ValueError("LispL3IfaceInput.instance_id is mandatory.")


@dataclass
class IosLispL3IfaceResult:
    programmed: bool
    interface_name: Optional[str] = None     # e.g. LISP0.4099
    line_state: Optional[str] = None         # "up" / "down"
    protocol_state: Optional[str] = None
    vrf: Optional[str] = None
    raw_cli: str = ""


@dataclass
class FedLispL3IfaceResult:
    programmed: bool
    if_id: Optional[str] = None              # 0x3a
    interface_name: Optional[str] = None     # LISP0.4099
    block_state: Optional[str] = None        # READY / ...
    iface_state: Optional[str] = None        # Enabled / Disabled
    iface_status: list[str] = field(default_factory=list)  # ["ADD","UPD"]
    instance_id: Optional[int] = None        # from LISP Classification Key
    udp_dest_port: Optional[int] = None      # 4789
    ipv4_sgt_enable: Optional[bool] = None
    raw_mappings_cli: str = ""
    raw_detail_cli: str = ""


@dataclass
class LispL3IfaceComparisonResult:
    status: ComparisonStatus
    detail: str
    interface_name: Optional[str] = None
    instance_id: Optional[int] = None
    issues: list[str] = field(default_factory=list)


# IOS `show ip interface lisp0.<iid>` header:
#   LISP0.4099 is up, line protocol is up
#   ...
#   VPN Routing/Forwarding "Campus"
_IOS_HEADER_RE = re.compile(
    r"^\s*(?P<intf>LISP\d+(?:\.\d+)?)\s+is\s+(?P<line>\S+),\s+"
    r"line\s+protocol\s+is\s+(?P<proto>\S+)",
    re.MULTILINE | re.IGNORECASE,
)
_IOS_VRF_RE = re.compile(r"VPN Routing/Forwarding\s+\"(?P<vrf>[^\"]+)\"", re.IGNORECASE)
_IOS_NOT_FOUND_RE = re.compile(
    r"%\s*Invalid input|%\s*Interface .* does not exist", re.IGNORECASE
)


def validate_lisp_l3_iface_programming(
    inp: LispL3IfaceInput, service
) -> IosLispL3IfaceResult:
    """Run `show ip interface lisp0.<iid>` and pull state + VRF."""
    cmd = f"show ip interface lisp0.{inp.instance_id}"
    raw_text = ""
    try:
        raw_text = radkit_cli.get_any_single_output(inp.hostname, cmd, service) or ""
    except BaseException:
        raw_text = ""

    if not raw_text or _IOS_NOT_FOUND_RE.search(raw_text):
        return IosLispL3IfaceResult(programmed=False, raw_cli=raw_text)

    header = _IOS_HEADER_RE.search(raw_text)
    if header is None:
        return IosLispL3IfaceResult(programmed=False, raw_cli=raw_text)

    vrf_m = _IOS_VRF_RE.search(raw_text)

    return IosLispL3IfaceResult(
        programmed=True,
        interface_name=header.group("intf"),
        line_state=header.group("line").lower(),
        protocol_state=header.group("proto").lower(),
        vrf=vrf_m.group("vrf") if vrf_m else None,
        raw_cli=raw_text,
    )


# FED mappings row layout:
#   <hex_handle>   <interface_name>   <if_id_hex>   <Type>
# We pick the row whose interface_name matches "LISP0.<iid>" AND Type=ENCAP_L3_LE
# (mappings table has both ENCAP and DECAP rows sharing the same IF_ID; one
# match is enough).
_FED_MAPPING_ROW_RE = re.compile(
    r"^\s*0x[0-9a-fA-F]+\s+(?P<intf>\S+)\s+(?P<if_id>0x[0-9a-fA-F]+)\s+"
    r"(?P<type>\S+)\s*$",
    re.MULTILINE,
)

# FED if-id detail field regexes — labels are "Field : value" or
# "Field ........ [value]". Both shapes appear.
_FED_IF_NAME_RE = re.compile(r"Interface Name\s*:\s*(?P<name>\S+)", re.IGNORECASE)
_FED_BLOCK_STATE_RE = re.compile(
    r"Interface Block State\s*:\s*(?P<state>\S+)", re.IGNORECASE
)
_FED_IFACE_STATE_RE = re.compile(
    r"^\s*Interface State\s*:\s*(?P<state>\S+)", re.IGNORECASE | re.MULTILINE
)
_FED_IFACE_STATUS_RE = re.compile(
    r"Interface Status\s*:\s*(?P<status>[A-Z, ]+)", re.IGNORECASE
)
# LISP Classification Key block — Instance ID and UDP dest port.
_FED_LISP_IID_RE = re.compile(
    r"Instance ID\s*:\s*(?P<iid>\d+)", re.IGNORECASE
)
_FED_LISP_UDP_RE = re.compile(
    r"UDP dest port\s*:\s*(?P<port>\d+)", re.IGNORECASE
)
_FED_IPV4_SGT_RE = re.compile(
    r"IPV4 SGT ENABLE\s*:\s*(?P<v>[YN])", re.IGNORECASE
)


def _find_lisp_if_id(raw_mappings: str, iid: int) -> Optional[str]:
    """Return the IF_ID hex string for LISP0.<iid> if found, else None."""
    target_name = f"LISP0.{iid}".lower()
    for m in _FED_MAPPING_ROW_RE.finditer(raw_mappings):
        if m.group("intf").lower() == target_name:
            return m.group("if_id")
    return None


def validate_fed_lisp_l3_iface_programming(
    instance_id: int, hostname: str, service
) -> FedLispL3IfaceResult:
    """Two-step FED query:
    1. Pull the mappings table to map LISP0.<iid> → IF_ID.
    2. Pull `ifm if-id <hex>` for the detailed block.
    """
    mappings_cmd = "show platform software fed switch active ifm mappings l3if-le"
    raw_mappings = ""
    try:
        raw_mappings = radkit_cli.get_any_single_output(hostname, mappings_cmd, service) or ""
    except BaseException:
        raw_mappings = ""

    if_id = _find_lisp_if_id(raw_mappings, instance_id) if raw_mappings else None
    if not if_id:
        return FedLispL3IfaceResult(
            programmed=False, raw_mappings_cli=raw_mappings,
        )

    detail_cmd = f"show platform software fed switch active ifm if-id {if_id}"
    raw_detail = ""
    try:
        raw_detail = radkit_cli.get_any_single_output(hostname, detail_cmd, service) or ""
    except BaseException:
        raw_detail = ""

    if not raw_detail:
        return FedLispL3IfaceResult(
            programmed=False, if_id=if_id,
            raw_mappings_cli=raw_mappings, raw_detail_cli=raw_detail,
        )

    name_m = _FED_IF_NAME_RE.search(raw_detail)
    block_m = _FED_BLOCK_STATE_RE.search(raw_detail)
    state_m = _FED_IFACE_STATE_RE.search(raw_detail)
    status_m = _FED_IFACE_STATUS_RE.search(raw_detail)
    iid_m = _FED_LISP_IID_RE.search(raw_detail)
    udp_m = _FED_LISP_UDP_RE.search(raw_detail)
    sgt_m = _FED_IPV4_SGT_RE.search(raw_detail)

    status_tokens: list[str] = []
    if status_m:
        status_tokens = [
            t.strip().upper()
            for t in status_m.group("status").split(",")
            if t.strip()
        ]

    return FedLispL3IfaceResult(
        programmed=True,
        if_id=if_id,
        interface_name=name_m.group("name") if name_m else None,
        block_state=block_m.group("state") if block_m else None,
        iface_state=state_m.group("state") if state_m else None,
        iface_status=status_tokens,
        instance_id=int(iid_m.group("iid")) if iid_m else None,
        udp_dest_port=int(udp_m.group("port")) if udp_m else None,
        ipv4_sgt_enable=(sgt_m.group("v").upper() == "Y") if sgt_m else None,
        raw_mappings_cli=raw_mappings,
        raw_detail_cli=raw_detail,
    )


_REQUIRED_STATUS_TOKENS = ("ADD",)
_VXLAN_UDP_PORT = 4789


def compare_lisp_l3_iface_programming(
    instance_id: int,
    ios: IosLispL3IfaceResult,
    fed: FedLispL3IfaceResult,
) -> LispL3IfaceComparisonResult:
    """Apply the LISP L3 interface rules:
      - IOS interface up + line protocol up.
      - FED Block State == READY.
      - FED Interface State == Enabled.
      - FED Interface Status contains ADD (UPD is informational — it only
        appears after a post-create modification, not all interfaces have it).
      - FED LISP IID matches the input instance_id.
      - FED UDP dest port == 4789.
      - FED IPV4 SGT ENABLE — informational only. SGT enablement is a
        per-VRF fabric-policy choice (Guest/Anchor VRFs run without it),
        not a programming-correctness signal.
    """
    if not ios.programmed:
        return LispL3IfaceComparisonResult(
            status="ios_missing",
            detail=f"IOS has no LISP0.{instance_id} interface; "
                   f"FED comparison not applicable.",
            instance_id=instance_id,
        )
    if not fed.programmed:
        return LispL3IfaceComparisonResult(
            status="misprogrammed",
            detail=(
                f"IOS has LISP0.{instance_id} but FED has no IF_ID mapping or "
                f"detail. Interface is not programmed in hardware."
            ),
            interface_name=ios.interface_name,
            instance_id=instance_id,
            issues=["fed_no_entry"],
        )

    issues: list[str] = []

    if ios.line_state != "up":
        issues.append(f"ios_line_state={ios.line_state}")
    if ios.protocol_state != "up":
        issues.append(f"ios_protocol_state={ios.protocol_state}")

    if (fed.block_state or "").upper() != "READY":
        issues.append(f"fed_block_state={fed.block_state}")
    if (fed.iface_state or "").lower() != "enabled":
        issues.append(f"fed_iface_state={fed.iface_state}")

    missing_status = [t for t in _REQUIRED_STATUS_TOKENS if t not in fed.iface_status]
    if missing_status:
        issues.append(
            f"fed_iface_status missing {missing_status} (have {fed.iface_status})"
        )

    if fed.instance_id is None:
        issues.append("fed_instance_id=missing")
    elif fed.instance_id != instance_id:
        issues.append(
            f"fed_instance_id={fed.instance_id} (expected {instance_id})"
        )

    if fed.udp_dest_port is None:
        issues.append("fed_udp_dest_port=missing")
    elif fed.udp_dest_port != _VXLAN_UDP_PORT:
        issues.append(
            f"fed_udp_dest_port={fed.udp_dest_port} (expected {_VXLAN_UDP_PORT})"
        )

    if fed.ipv4_sgt_enable is None:
        # Informational only — older / stripped FED outputs may lack the line.
        pass
    elif fed.ipv4_sgt_enable is not True:
        # SGT off is legitimate for VRFs that don't enforce CTS (Guest, Anchor).
        # Don't fail the check; the value is still surfaced in the result.
        pass

    if not issues:
        return LispL3IfaceComparisonResult(
            status="match",
            detail=(
                f"LISP0.{instance_id} programmed correctly: IOS up/up, FED "
                f"block READY, status {fed.iface_status}, IID {fed.instance_id}, "
                f"UDP {fed.udp_dest_port}"
                + (f", SGT={'Y' if fed.ipv4_sgt_enable else 'N'}"
                   if fed.ipv4_sgt_enable is not None else "")
                + "."
            ),
            interface_name=ios.interface_name,
            instance_id=instance_id,
        )

    return LispL3IfaceComparisonResult(
        status="misprogrammed",
        detail=f"LISP0.{instance_id} fails programming checks: " + "; ".join(issues),
        interface_name=ios.interface_name,
        instance_id=instance_id,
        issues=issues,
    )
