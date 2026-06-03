"""Shared helpers for the east-west (L2 inter-XTR) check chain.

Mirrors the patterns in checks_shared but namespaces state under ew_* so it
never collides with the DHCP chain. Legacy traffic_flows functions expect a
device-shaped object (sourcextr.hostname / .dnac / .loopback / ...); the
_build_src_xtr_shim helper composes that from the values populated by the
shared profile / fabric / role checks.
"""

from types import SimpleNamespace

from checks import CheckResult, CheckStatus, RunContext
from checks_shared import _legacy_fail  # re-exported

__all__ = [
    "_legacy_fail",
    "_need",
    "_skip_if_l3",
    "_skip_if_intra",
    "_fmt_kv",
    "_fmt_list",
    "_endpoint_node_spec",
    "_build_src_xtr_shim",
    "_build_dst_xtr_shim",
]


def _need(ctx: RunContext, *keys: str) -> "CheckResult | None":
    """Return a SKIP CheckResult if any state key is missing, else None.

    Lets each check open with a single guard line:
        miss = _need(ctx, "ew_sourceep", "ew_l2lispsrc")
        if miss: return miss
    """
    missing = [k for k in keys if ctx.state.get(k) is None]
    if missing:
        return CheckResult(
            CheckStatus.SKIP,
            f"Skipped — required state missing: {', '.join(missing)}.",
        )
    return None


def _skip_if_l3(ctx: RunContext) -> "CheckResult | None":
    """SKIP if EwFlowElection marked the run as L3 (routed east-west)."""
    if ctx.state.get("ew_l3_skip"):
        return CheckResult(
            CheckStatus.SKIP,
            "L3 east-west not yet supported (transit / inter-VRF routing is "
            "not implemented in the legacy reference either).",
        )
    return None


def _skip_if_intra(ctx: RunContext, label: str = "Same-Edge flow") -> "CheckResult | None":
    """SKIP for checks that only make sense when source/dest are on different Edges."""
    if ctx.state.get("ew_is_intra_xtr"):
        return CheckResult(
            CheckStatus.SKIP,
            f"Skipped — {label}; no inter-Edge traversal to validate.",
        )
    return None


def _fmt_list(items, empty: str = "(none)") -> str:
    """Render a list as comma-separated for use in OK bodies."""
    if not items:
        return empty
    return ", ".join(str(i) for i in items)


def _fmt_kv(pairs) -> str:
    """Render an iterable of (label, value) pairs as a bullet list.

    Hides entries whose value is None, '', 'Unknown', or [] per the
    human-readable feedback memory.
    """
    lines = []
    for label, value in pairs:
        if value is None or value == "" or value == [] or value == "Unknown":
            continue
        if isinstance(value, (list, tuple, set)):
            value = _fmt_list(value)
        lines.append(f"• {label}: {value}")
    return "\n".join(lines) if lines else "(no fields populated)"


def _endpoint_node_spec(
    node_id: str,
    ep,
    connect_to: str,
    label_prefix: str = "EP",
) -> dict:
    """Build an add_nodes entry for an endpoint discovered by host onboarding.

    `ep` is an EndpointInfo instance — pulls sourceip / sourcemac / sourceport
    / sourcevlan / sourcevrf defensively (any of them may be None on a stub).
    """
    ip = getattr(ep, "sourceip", None) or ""
    mac = getattr(ep, "sourcemac", None) or ""
    port = getattr(ep, "sourceport", None) or ""
    vlan = getattr(ep, "sourcevlan", None) or ""
    label_lines = [f"{label_prefix} {ip}" if ip else label_prefix]
    if mac:
        label_lines.append(mac)
    if port:
        label_lines.append(str(port))
    return {
        "id": node_id,
        "role": "endpoint",
        "label": "\n".join(label_lines),
        "ip": ip or None,
        "mac": mac or None,
        "port": port or None,
        "vlan": vlan or None,
        "connect_to": connect_to,
        "edge_label": str(port) if port else "",
    }


def _build_src_xtr_shim(ctx: RunContext):
    """Compose a Device-shaped SimpleNamespace for the source XTR.

    Mirrors device_profiler.Device's attribute surface for fields legacy
    east-west helpers reach into (hostname, mgmtip, dnac, fabric_id,
    fabric_site_hierarchy, loopback, isfabric, edge, l2handoff, iborder,
    siteNameHierarchy, uuid).
    """
    return SimpleNamespace(
        hostname=ctx.state.get("xtr_hostname"),
        mgmtip=ctx.state.get("xtr_mgmtip") or ctx.payload.get("device_source_ip"),
        dnac=ctx.state.get("catc_name"),
        fabric_id=ctx.state.get("fabric_id"),
        fabric_site_hierarchy=ctx.state.get("xtr_site_hierarchy")
        or ctx.state.get("fabric_site_hierarchy"),
        siteNameHierarchy=ctx.state.get("xtr_site_hierarchy"),
        loopback=ctx.state.get("xtr_loopback"),
        isfabric=ctx.state.get("xtr_is_fabric"),
        edge=ctx.state.get("edge"),
        l2handoff=ctx.state.get("l2handoff"),
        iborder=ctx.state.get("iborder"),
        ispubsub=ctx.state.get("is_pubsub"),
        uuid=ctx.state.get("xtr_uuid"),
        roles=ctx.state.get("xtr_roles") or [],
    )


def _build_dst_xtr_shim(ctx: RunContext):
    """Return the destination XTR (real Device when inter-Edge, src shim when intra)."""
    dst = ctx.state.get("ew_dstxtr")
    if dst is not None:
        return dst
    return _build_src_xtr_shim(ctx)
