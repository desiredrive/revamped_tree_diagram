"""Underlay / forwarding checks.

CEF Forwarding (legacy: Edge Node Forwarding), underlay reachability to the
selected destination, and underlay CDP discovery for next-hops.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks_shared import _legacy_fail, _build_edge_shim


class EdgeForwarding(Check):
    """DHCP — recurse Map-Cache → CEF → underlay nexthops/ports on the XTR.

    Branches on is_infravn (CLI lines 2081-2099):
      - INFRA_VN: infra_vn_forwarding() + validate_infra_vn_underlay_nexthops()
      - non-INFRA_VN: process_map_cache_recursion() → forwarding_parameters()
    Stashes loopback/forwarding_prefixes/rlocs/ports for the next Checks.
    """

    name = "CEF Forwarding"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        dhcp_info = ctx.state.get("dhcpparameters_info")
        lisp_info = ctx.state.get("lispparameters_info")
        is_infravn = ctx.state.get("is_infravn")
        mac = ctx.payload.get("mac")
        vlan = ctx.payload.get("vlan")
        vrf = ctx.payload.get("vrf")
        loopback = ctx.state.get("xtr_loopback")

        if not (service and hostname and dhcp_info and lisp_info and loopback):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires dhcpparameters_info / lispparameters_info / xtr_loopback.",
            )

        shim = _build_edge_shim(ctx)
        iid = getattr(lisp_info, "iid", None)

        try:
            if not is_infravn:
                from traffic_flows.dhcp_troubleshooting import (
                    process_map_cache_recursion,
                )
                from routingmodules.lisp import CEFForwardingState
                from traffic_flows.dhcp_troubleshooting import (
                    forwarding_parameters_recursion,
                    underlay_ports,
                )
                _, forwarding_prefixes = process_map_cache_recursion(
                    shim, mac, vlan, service, 0, iid, vrf
                )

                svivrf = getattr(dhcp_info, "svivrf", vrf)
                cefinternallist = CEFForwardingState(svivrf, hostname)
                cefinternallist.cef_resolution(forwarding_prefixes, service, 0)
                final_rlocs = forwarding_parameters_recursion(
                    cefinternallist, ctx.state.get("catc_name"), 0, hostname
                )
                cefinternallist.cef_underlay(final_rlocs, service)
                cefinternallist.underlay_phy(service)
                underlay_ports(cefinternallist.physical_interfaces, hostname, 0)

                ctx.state["forwarding_prefixes"] = forwarding_prefixes
                ctx.state["final_rlocs"] = final_rlocs
                ctx.state["underlay_ports_list"] = cefinternallist.physical_interfaces
                ctx.state["cefinternallist_info"] = cefinternallist
                fallback_dstip = None
                if forwarding_prefixes:
                    fallback_dstip = forwarding_prefixes[0].get("prefix")
                if not fallback_dstip:
                    helpers_fb = getattr(dhcp_info, "helper_address", None) or []
                    if helpers_fb:
                        fallback_dstip = helpers_fb[0]
                if fallback_dstip:
                    ctx.state["dhcp_dstip"] = fallback_dstip

                def _fmt_list(items):
                    return ", ".join(str(i) for i in items) if items else "(none)"

                prefix_strs = [p.get("prefix") for p in (forwarding_prefixes or []) if p.get("prefix")]
                rloc_strs = [r.get("rloc") if isinstance(r, dict) else str(r) for r in (final_rlocs or [])]
                msg = (
                    f"• Prefixes: {_fmt_list(prefix_strs)}\n"
                    f"• RLOCs: {_fmt_list(rloc_strs)}\n"
                    f"• Underlay Ports: {_fmt_list(cefinternallist.physical_interfaces)}"
                )
            else:
                from traffic_flows.dhcp_troubleshooting import (
                    process_infra_vn_underlay_recursion,
                    validate_infra_vn_underlay_nexthops,
                )
                helpers = getattr(dhcp_info, "helper_address", None) or []
                localsgt = ctx.state.get("localsgt")
                routes, cefhops, total_phys = process_infra_vn_underlay_recursion(
                    helpers, loopback, localsgt, hostname, service, 0
                )
                validate_infra_vn_underlay_nexthops(cefhops, total_phys, hostname, service, 0)
                ctx.state["upstreamroutes"] = routes
                ctx.state["upstreamcef"] = cefhops
                ctx.state["upstreamphy"] = total_phys
                if helpers:
                    ctx.state["dhcp_dstip"] = helpers[0]

                def _fmt_list(items):
                    return ", ".join(str(i) for i in items) if items else "(none)"

                msg = (
                    f"• Prefixes: {_fmt_list(helpers)}\n"
                    f"• RLOCs: {_fmt_list([getattr(h, 'nexthop', h) for h in cefhops])}\n"
                    f"• Underlay Ports: {_fmt_list(total_phys)}"
                )
        except BaseException as e:
            return _legacy_fail(e, "CEF Forwarding")

        return CheckResult(CheckStatus.OK, msg)


class UnderlayReachability(Check):
    """DHCP — verify reachability between Edge and destination RLOC over the underlay.

    Mirrors dhcp_troubleshooting.py:2101-2113. Skips on INFRA_VN (handled inline
    by validate_infra_vn_underlay_nexthops in EdgeForwarding) and just records
    src/dst for the upcoming border-validation Check.
    """

    name = "Underlay Reachability"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        loopback = ctx.state.get("xtr_loopback")
        is_infravn = ctx.state.get("is_infravn")
        dhcp_info = ctx.state.get("dhcpparameters_info")

        if not (service and hostname and loopback and dhcp_info):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires xtr_hostname / xtr_loopback / dhcpparameters_info.",
            )

        try:
            if not is_infravn:
                from traffic_flows.dhcp_troubleshooting import rloc_reachability
                ports = ctx.state.get("underlay_ports_list") or []
                rlocs = ctx.state.get("final_rlocs") or []
                forwarding_prefixes = ctx.state.get("forwarding_prefixes") or []
                if not forwarding_prefixes:
                    return CheckResult(
                        CheckStatus.FAIL,
                        "No forwarding prefixes available — CEF Forwarding did not "
                        "produce a destination RLOC.",
                    )
                rloc_reachability(ports, hostname, service, rlocs, 0)
                srcip = loopback
                dstip = forwarding_prefixes[0]["prefix"]
            else:
                srcip = loopback
                helpers = getattr(dhcp_info, "helper_address", None) or []
                if not helpers:
                    return CheckResult(
                        CheckStatus.FAIL,
                        "INFRA_VN path: no helper-address available for reachability test.",
                    )
                dstip = helpers[0]
        except BaseException as e:
            return _legacy_fail(e, "Underlay Reachability")

        ctx.state["dhcp_srcip"] = srcip
        ctx.state["dhcp_dstip"] = dstip
        return CheckResult(
            CheckStatus.OK,
            f"RLOC {srcip} → DHCP Server {dstip}",
            data={
                "srcip": srcip,
                "dstip": dstip,
                "add_nodes": [{
                    "id": "dhcp-server",
                    "role": "dhcp-server",
                    "label": "DHCP " + dstip,
                    "ip": dstip,
                    "connect_to": "xtr",
                    "edge_label": "helper",
                }],
            },
        )


class UnderlayCdpDiscovery(Check):
    """Underlay — draw a node for each CEF underlay interface using CDP info.

    For every physical interface in `underlay_ports_list` (collected by EdgeForwarding),
    ask the XTR for its CDP neighbor. If a neighbor is found, emit an `add_nodes`
    entry with the neighbor's hostname / platform / port. If no CDP neighbor is
    seen on that interface, emit a generic grey "switch" placeholder so the
    operator still sees the underlay topology fan-out from the XTR.
    """

    name = "Underlay CDP Discovery"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        ports = (
            ctx.state.get("underlay_ports_list")
            or ctx.state.get("upstreamphy")
            or []
        )
        if not (service and hostname):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires service / xtr_hostname.",
            )
        if not ports:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no underlay ports collected (INFRA_VN path or no CEF nexthops).",
            )

        try:
            from switchingmodules.cdp import CDPinfo
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not import CDPinfo: {type(e).__name__}: {e}",
            )

        from traffic_flows.dhcp_troubleshooting import abbrev_port

        add_nodes = []
        found = 0
        unknown = 0
        for idx, port in enumerate(ports):
            neighbors = []
            try:
                cdp = CDPinfo(hostname)
                cdp.cdpneighborinterface(port, service)
                neighbors = getattr(cdp, "cdpneighbors", []) or []
            except Exception:
                neighbors = []

            node_id = f"underlay-{idx+1}"
            if neighbors:
                n = neighbors[0]
                device_id = n.get("device_id") or f"neighbor-{idx+1}"
                platform = n.get("platform") or ""
                remote = n.get("remoteinterface") or ""
                mgmt = n.get("management_addresses") or ""
                if isinstance(mgmt, dict):
                    mgmt_ip = next(iter(mgmt.keys()), "") if mgmt else ""
                elif isinstance(mgmt, list):
                    mgmt_ip = mgmt[0] if mgmt else ""
                else:
                    mgmt_ip = str(mgmt)
                label_lines = [device_id]
                if platform:
                    label_lines.append(platform)
                if mgmt_ip:
                    label_lines.append(mgmt_ip)
                add_nodes.append({
                    "id": node_id,
                    "role": "underlay-switch",
                    "label": "\n".join(label_lines),
                    "ip": mgmt_ip or None,
                    "cdp_device_id": device_id or None,
                    "connect_to": "xtr",
                    "edge_label": f"{abbrev_port(port)} ↔ {abbrev_port(remote)}" if remote else abbrev_port(port),
                })
                found += 1
            else:
                add_nodes.append({
                    "id": node_id,
                    "role": "underlay-unknown",
                    "label": f"unknown\n({abbrev_port(port)})",
                    "connect_to": "xtr",
                    "edge_label": abbrev_port(port),
                })
                unknown += 1

        ctx.state["underlay_nodes"] = add_nodes

        from traffic_flows.dhcp_troubleshooting import abbrev_port as _ap
        bullet_lines = []
        for n, port in zip(add_nodes, ports):
            if n.get("role") == "underlay-switch":
                dev = (n.get("label") or "").split("\n", 1)[0]
                mgmt = n.get("ip") or "?"
                bullet_lines.append(f"• {dev} ({mgmt}) via {_ap(port)}")
            else:
                bullet_lines.append(f"• unknown neighbor via {_ap(port)}")
        body = "\n".join(bullet_lines) if bullet_lines else "(no underlay ports)"
        return CheckResult(
            CheckStatus.OK,
            body,
            data={"add_nodes": add_nodes},
        )

