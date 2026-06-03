"""East-West Phase D: underlay validation (RIB, CEF, physical, MTU, ping).

Mirrors forwardinglogic.l2_inter_xtr_ew lines 299-399. All checks here SKIP
on intra-XTR (same Edge) and on L3 east-west.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.ew_shared import (
    _legacy_fail,
    _need,
    _skip_if_l3,
    _skip_if_intra,
    _build_src_xtr_shim,
)


class EwUnderlayRibLookup(Check):
    """RIB lookup for the destination RLOC on the source XTR (requires /32)."""

    name = "Underlay RIB lookup (dest RLOC)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_l2mapcache")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        rloc = ctx.state["ew_l2mapcache"].rloc
        try:
            from routingmodules import iprouting
            route = iprouting.IPRoute(rloc, None, srcxtr.hostname)
            route.iproute_prefix(ctx.service, 0)
        except BaseException as e:
            return _legacy_fail(e, "Underlay RIB lookup")
        ctx.state["ew_rloc_route"] = route
        mask = getattr(route, "mask", None)
        prefix = getattr(route, "prefix", None)
        nexthops = getattr(route, "nexthops", None) or []
        body = (
            f"• Prefix: {prefix}\n"
            f"• Mask: {mask}\n"
            f"• Next-hops: {', '.join(str(n) for n in nexthops) or '(none)'}"
        )
        if mask is None:
            return CheckResult(CheckStatus.FAIL, f"No route to {rloc}.\n{body}")
        try:
            if int(mask) != 32:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"L2 LISP requires a /32 host route to each RLOC; got /{mask}.\n{body}",
                )
        except (TypeError, ValueError):
            return CheckResult(CheckStatus.WARN, f"Could not parse mask {mask!r}.\n{body}")
        return CheckResult(CheckStatus.OK, body)


class EwUnderlayCef(Check):
    """CEF internal lookup for the destination RLOC; flags Null0 adjacencies."""

    name = "Underlay CEF (dest RLOC)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_l2mapcache")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        rloc = ctx.state["ew_l2mapcache"].rloc
        try:
            from routingmodules import cef
            ipc = cef.IPCef(rloc, None, srcxtr.hostname)
            ipc.get_cef_internal(ctx.service)
        except BaseException as e:
            return _legacy_fail(e, "Underlay CEF lookup")
        ctx.state["ew_rloc_cef"] = ipc
        null0 = []
        ports = []
        for nh in getattr(ipc, "nexthops", []) or []:
            oif = nh.get("oif") if isinstance(nh, dict) else None
            if oif:
                ports.append(oif)
                if oif == "Null0":
                    null0.append(nh)
        # Reuse the DHCP chain's UnderlayCdpDiscovery for free.
        ctx.state["underlay_ports_list"] = ports
        body_lines = [f"• Next-hop interfaces: {', '.join(ports) or '(none)'}"]
        nh_ips = [nh.get("nexthop") for nh in (getattr(ipc, "nexthops", []) or []) if isinstance(nh, dict) and nh.get("nexthop")]
        if nh_ips:
            body_lines.append(f"• Next-hop IPs: {', '.join(nh_ips)}")
        if null0:
            return CheckResult(
                CheckStatus.FAIL,
                "Null0 adjacency present — total/partial packet loss to RLOC.\n"
                + "\n".join(body_lines),
            )
        return CheckResult(CheckStatus.OK, "\n".join(body_lines))


class EwUnderlayPhysical(Check):
    """Resolve virtual interfaces down to physical interfaces; collect per-intf MTU."""

    name = "Underlay physical interfaces"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_rloc_cef")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        try:
            from routingmodules import cef
            from switchingmodules.interfaces import Interfaces
            phys = cef.physical_recursion(ctx.state["ew_rloc_cef"], srcxtr.hostname)
            phys.get_physical_interfaces(ctx.service, 0)
            interfaceobjects = []
            mtus = []
            phys_list = []
            for i in (getattr(phys, "nexthops", []) or []):
                oif = i.get("oif") if isinstance(i, dict) else None
                if not oif:
                    continue
                phys_list.append(oif)
                intf = Interfaces(oif, srcxtr.hostname)
                intf.show_interface(ctx.service)
                interfaceobjects.append(intf)
                if getattr(intf, "mtu", None) is not None:
                    mtus.append(intf.mtu)
        except BaseException as e:
            return _legacy_fail(e, "Underlay physical resolution")
        ctx.state["ew_phys_interfaces"] = phys_list
        ctx.state["ew_intf_objects"] = interfaceobjects
        ctx.state["ew_mtus"] = mtus
        # Refresh underlay_ports_list with physical (more granular than CEF oif).
        if phys_list:
            ctx.state["underlay_ports_list"] = phys_list
        lines = ["Per-interface MTU:"]
        for intf in interfaceobjects:
            lines.append(f"  • {getattr(intf, 'interface', '?')}: MTU {getattr(intf, 'mtu', '?')}")
        return CheckResult(CheckStatus.OK, "\n".join(lines))


class EwUnderlayMtu(Check):
    """Compute the minimum MTU across underlay physical interfaces."""

    name = "Minimum underlay MTU"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_intf_objects")
        if miss:
            return miss
        intfs = ctx.state["ew_intf_objects"]
        valid = [(getattr(i, "interface", "?"), getattr(i, "mtu", None)) for i in intfs]
        valid = [(n, m) for n, m in valid if m is not None]
        if not valid:
            return CheckResult(CheckStatus.WARN, "No MTU values collected.")
        min_intf, min_mtu = min(valid, key=lambda t: int(t[1]))
        ctx.state["ew_min_mtu"] = min_mtu
        return CheckResult(
            CheckStatus.OK,
            f"• Minimum MTU: {min_mtu}\n• Interface: {min_intf}",
        )


class EwUnderlayPingNoMtu(Check):
    """Ping the destination RLOC from Lo0 with default MTU (warn ≤ 70%)."""

    name = "Underlay ping (no MTU)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_rloc_cef")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        rloc_ip = ctx.state["ew_rloc_cef"].ip
        try:
            from traffic_flows.operational_tests import Ping
            p = Ping(rloc_ip, srcxtr.hostname)
            p.ping_with_source(None, "Lo0", None, False, ctx.service)
        except BaseException as e:
            return _legacy_fail(e, "Underlay ping (no MTU)")
        ctx.state["ew_ping_normal"] = p
        result = getattr(p, "result", None)
        body = f"• Target RLOC: {rloc_ip}\n• Source: Lo0\n• Success: {result}%"
        try:
            if int(result) <= 70:
                return CheckResult(CheckStatus.WARN, body + "\n• Below 70% threshold.")
        except (TypeError, ValueError):
            return CheckResult(CheckStatus.WARN, body + "\n• Could not parse success %.")
        return CheckResult(CheckStatus.OK, body)


class EwUnderlayPingMtu(Check):
    """Ping the destination RLOC at minimum MTU with DF-bit set (warn ≤ 70%)."""

    name = "Underlay ping (min MTU + DF)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_rloc_cef", "ew_min_mtu")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        rloc_ip = ctx.state["ew_rloc_cef"].ip
        min_mtu = ctx.state["ew_min_mtu"]
        try:
            from traffic_flows.operational_tests import Ping
            p = Ping(rloc_ip, srcxtr.hostname)
            p.ping_with_source(None, "Lo0", min_mtu, True, ctx.service)
        except BaseException as e:
            return _legacy_fail(e, "Underlay ping (min MTU)")
        ctx.state["ew_ping_mtu"] = p
        result = getattr(p, "result", None)
        body = (
            f"• Target RLOC: {rloc_ip}\n"
            f"• Source: Lo0\n"
            f"• MTU: {min_mtu} (DF set)\n"
            f"• Success: {result}%"
        )
        try:
            if int(result) <= 70:
                return CheckResult(
                    CheckStatus.WARN,
                    body + "\n• Below 70% — possible MTU mismatch in path.",
                )
        except (TypeError, ValueError):
            return CheckResult(CheckStatus.WARN, body + "\n• Could not parse success %.")
        return CheckResult(CheckStatus.OK, body)
