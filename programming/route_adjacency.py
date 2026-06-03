"""Combined CEF → adjacency programming validation.

Validates that a route is fully programmed end-to-end:

  1. CEF (IOS) and FED route agree on the matched prefix and nexthops.
  2. For every CEF nexthop:
       a. The adjacency exists (IOS) and is hardware-programmed (FED).
       b. The adjacency address equals the nexthop IP.
       c. The adjacency egress interface matches the CEF-reported
          interface for that nexthop.

This is the orchestration layer — it calls into programming.cef and
programming.adjacency primitives without re-implementing parsing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import re

from programming.mac import ComparisonStatus
from programming.cef import (
    CefIosResult,
    CefFedResult,
    CefComparisonResult,
    compare_cef_programming,
    validate_cef_programming,
    validate_fed_cef_programming,
    CefProgrammingInput,
)
from programming.adjacency import (
    AdjacencyInput,
    IosAdjacencyResult,
    FedAdjacencyResult,
    AdjacencyComparisonResult,
    validate_adjacency_programming,
    validate_fed_adjacency_programming,
    compare_adjacency_programming,
    _interfaces_equal,
)


_VLAN_FROM_INTF_RE = re.compile(r"^Vlan(\d+)$", re.IGNORECASE)


@dataclass
class NexthopAdjacencyResult:
    nexthop: str
    expected_interface: Optional[str]        # interface CEF claims for the nexthop
    ios: IosAdjacencyResult
    fed: FedAdjacencyResult
    adj_compare: AdjacencyComparisonResult
    interface_match: bool                    # CEF's intf == adj's intf
    address_match: bool                      # adj.address == nexthop


@dataclass
class CefFullComparisonResult:
    status: ComparisonStatus                 # match | misprogrammed | ios_missing
    detail: str
    cef_compare: CefComparisonResult
    nexthop_results: list[NexthopAdjacencyResult] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


def _derive_vlan(interface: Optional[str]) -> Optional[int]:
    if not interface:
        return None
    m = _VLAN_FROM_INTF_RE.match(interface.strip())
    return int(m.group(1)) if m else None


def _clean_intf(token: Optional[str]) -> Optional[str]:
    if not token:
        return token
    return token.rstrip(",.;:)")


def _pair_nexthops(ios: CefIosResult) -> list[tuple[str, Optional[str]]]:
    """Pair each CEF nexthop with the interface that follows it on the same
    `nexthop <ip> <intf>` line. Falls back to the parsed nexthops list (with
    the first attached interface, if any) when the raw text uses the
    attached-host form."""
    pairs: list[tuple[str, Optional[str]]] = []
    nexthop_re = re.compile(
        r"^\s*nexthop\s+(?P<ip>\d+\.\d+\.\d+\.\d+)(?:\s+(?P<intf>\S+))?",
        re.MULTILINE,
    )
    for m in nexthop_re.finditer(ios.raw_cli or ""):
        pairs.append((m.group("ip"), _clean_intf(m.group("intf"))))
    if pairs:
        return pairs
    # Attached-host fallback: cef.py already injected the prefix into
    # ios.nexthops when the route printed `attached to <intf>` instead of a
    # nexthop line. Pair each nexthop with the first known interface.
    intf = ios.interfaces[0] if ios.interfaces else None
    return [(nh, intf) for nh in ios.nexthops]


def validate_route_with_adjacencies(
    hostname: str,
    prefix: str,
    mask: Optional[int],
    vrf: Optional[str],
    service,
) -> CefFullComparisonResult:
    """End-to-end: validate CEF, then per-nexthop adjacency.

    Returns a single aggregated result. Status is `match` only if CEF
    matches AND every nexthop has a matching adjacency with consistent
    address + interface.
    """
    ios_cef = validate_cef_programming(
        CefProgrammingInput(hostname=hostname, prefix=prefix, mask=mask, vrf=vrf),
        service,
    )

    if ios_cef.programmed and ios_cef.matched_prefix and ios_cef.matched_mask is not None:
        fed_cef = validate_fed_cef_programming(
            hostname, ios_cef.matched_prefix, ios_cef.matched_mask, vrf, service,
        )
    elif mask is not None:
        fed_cef = validate_fed_cef_programming(hostname, prefix, mask, vrf, service)
    else:
        fed_cef = CefFedResult(
            programmed=False,
            raw_cli="(skipped — CEF had no matched prefix and no input mask)",
        )

    cef_cmp = compare_cef_programming(ios_cef, fed_cef)

    issues: list[str] = []
    nh_results: list[NexthopAdjacencyResult] = []

    if cef_cmp.status == "ios_missing":
        return CefFullComparisonResult(
            status="ios_missing",
            detail=cef_cmp.detail,
            cef_compare=cef_cmp,
        )
    if cef_cmp.status != "match":
        issues.append(f"cef_compare={cef_cmp.status}: {cef_cmp.detail}")

    if ios_cef.is_receive:
        # Receive routes have no nexthop/adjacency to walk.
        return CefFullComparisonResult(
            status=cef_cmp.status,
            detail=(
                f"{ios_cef.matched_prefix}/{ios_cef.matched_mask} is a receive "
                f"route — no adjacency walk required."
            ),
            cef_compare=cef_cmp,
            issues=issues,
        )

    pairs = _pair_nexthops(ios_cef)

    # CEF "attached" form (directly attached /31/32, or recursively resolved
    # host /32) — use FED's nexthops paired with CEF's interface for the walk.
    if not pairs and ios_cef.is_attached and fed_cef.programmed and fed_cef.nexthops:
        intf = ios_cef.interfaces[0] if ios_cef.interfaces else None
        pairs = [(nh, intf) for nh in fed_cef.nexthops]

    if not pairs:
        issues.append("no nexthops parsed from CEF; cannot walk adjacencies")
        return CefFullComparisonResult(
            status="misprogrammed",
            detail=f"CEF reports {ios_cef.matched_prefix}/{ios_cef.matched_mask} "
                   f"but lists no nexthops. " + "; ".join(issues),
            cef_compare=cef_cmp,
            issues=issues,
        )

    for nh, expected_intf in pairs:
        adj_inp = AdjacencyInput(
            hostname=hostname,
            address=nh,
            vrf=vrf,
            vlan=_derive_vlan(expected_intf),
        )
        ios_adj = validate_adjacency_programming(adj_inp, service)
        fed_adj = validate_fed_adjacency_programming(nh, hostname, service)
        adj_cmp = compare_adjacency_programming(ios_adj, fed_adj)

        addr_match = (ios_adj.address or "") == nh if ios_adj.programmed else False
        if expected_intf and ios_adj.programmed:
            iface_match = _interfaces_equal(expected_intf, ios_adj.interface)
        elif not expected_intf and ios_adj.programmed:
            iface_match = True  # CEF didn't pin an interface — nothing to mismatch.
        else:
            iface_match = False

        nh_results.append(NexthopAdjacencyResult(
            nexthop=nh,
            expected_interface=expected_intf,
            ios=ios_adj,
            fed=fed_adj,
            adj_compare=adj_cmp,
            interface_match=iface_match,
            address_match=addr_match,
        ))

        if adj_cmp.status != "match":
            issues.append(f"nexthop {nh}: adj_compare={adj_cmp.status} "
                          f"({adj_cmp.detail})")
        else:
            if not addr_match:
                issues.append(
                    f"nexthop {nh}: adjacency address {ios_adj.address} "
                    f"does not equal CEF nexthop {nh}"
                )
            if expected_intf and not iface_match:
                issues.append(
                    f"nexthop {nh}: CEF interface {expected_intf} != "
                    f"adjacency interface {ios_adj.interface}"
                )

    if not issues:
        nhs = ", ".join(f"{r.nexthop} via {r.ios.interface}" for r in nh_results)
        return CefFullComparisonResult(
            status="match",
            detail=(
                f"CEF and FED agree on {ios_cef.matched_prefix}/"
                f"{ios_cef.matched_mask}; all adjacencies programmed: {nhs}."
            ),
            cef_compare=cef_cmp,
            nexthop_results=nh_results,
        )

    return CefFullComparisonResult(
        status="misprogrammed",
        detail=(
            f"Route {ios_cef.matched_prefix}/{ios_cef.matched_mask} fails "
            f"end-to-end validation: " + "; ".join(issues)
        ),
        cef_compare=cef_cmp,
        nexthop_results=nh_results,
        issues=issues,
    )
