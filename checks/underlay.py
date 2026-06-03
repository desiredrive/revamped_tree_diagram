"""Underlay / forwarding checks.

CEF Forwarding (legacy: Edge Node Forwarding), underlay reachability to the
selected destination, and underlay CDP discovery for next-hops.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.shared import _legacy_fail, _build_edge_shim


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

                def _hop_rloc(h):
                    nh = getattr(h, "nexthopip", None) or getattr(h, "ip", None)
                    return nh if nh else str(h)

                msg = (
                    f"• Helpers: {_fmt_list(helpers)}\n"
                    f"• Next-hops: {_fmt_list([_hop_rloc(h) for h in cefhops])}\n"
                    f"• Underlay Ports: {_fmt_list(total_phys)}\n"
                    f"(INFRA_VN forwards natively in the underlay — no LISP/RLOC encap.)"
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
        label = (
            f"Loopback {srcip} → DHCP Server {dstip} (native underlay, no RLOC)"
            if is_infravn
            else f"RLOC {srcip} → DHCP Server {dstip}"
        )
        return CheckResult(
            CheckStatus.OK,
            label,
            data={
                "srcip": srcip,
                "dstip": dstip,
                "add_nodes": [{
                    "id": "dhcp-server",
                    "role": "dhcp-server",
                    "label": "DHCP " + dstip,
                    "ip": dstip,
                    "floating": True,
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

        # Resolve actual source node id (may have been remapped by a prior check,
        # e.g. wireless XTR roam). target_node_id is the logical "xtr" handle.
        remap = ctx.state.get("node_remap") or {}
        source_node_id = remap.get(self.target_node_id, self.target_node_id)

        add_nodes = []
        unresolved_ports = []
        for idx, port in enumerate(ports):
            neighbors = []
            try:
                cdp = CDPinfo(hostname)
                cdp.cdpneighborinterface(port, service)
                neighbors = getattr(cdp, "cdpneighbors", []) or []
            except Exception:
                neighbors = []

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
                    "id": f"underlay-{idx+1}",
                    "role": "underlay-switch",
                    "label": "\n".join(label_lines),
                    "ip": mgmt_ip or None,
                    "cdp_device_id": device_id or None,
                    "connect_to": source_node_id,
                    "edge_label": f"{abbrev_port(port)} ↔ {abbrev_port(remote)}" if remote else abbrev_port(port),
                })
            else:
                # CDP miss — fold into the shared "Fabric" cloud (singleton node)
                # so every source that can't resolve a next-hop ends at the same
                # icon instead of cluttering the graph with one node per port.
                unresolved_ports.append(port)

        # Emit the Fabric cloud once if any port went unresolved. The node id is
        # a fixed singleton so repeated emissions from other source checks land
        # on the same node; the per-source edge carries that source's port list.
        if unresolved_ports:
            edge_label = ", ".join(abbrev_port(p) for p in unresolved_ports)
            add_nodes.append({
                "id": "fabric-cloud",
                "role": "fabric",
                "label": "Fabric",
                "connect_to": source_node_id,
                "edge_label": edge_label,
            })

        ctx.state["underlay_nodes"] = add_nodes
        # Per-source mirror so the border merge can find matches across multiple
        # Edges (e.g. wireless roam queues a second discovery against the
        # original Edge, and a Border that CDP-neighbors both should connect to
        # both underlay-switch nodes).
        by_source = ctx.state.setdefault("underlay_nodes_by_source", {})
        by_source[source_node_id] = add_nodes

        from traffic_flows.dhcp_troubleshooting import abbrev_port as _ap
        bullet_lines = []
        for n in add_nodes:
            if n.get("role") == "underlay-switch":
                dev = (n.get("label") or "").split("\n", 1)[0]
                mgmt = n.get("ip") or "?"
                bullet_lines.append(f"• {dev} ({mgmt}) via {n.get('edge_label')}")
        if unresolved_ports:
            bullet_lines.append(
                f"• Fabric (no CDP neighbor) via {', '.join(_ap(p) for p in unresolved_ports)}"
            )
        body = "\n".join(bullet_lines) if bullet_lines else "(no underlay ports)"
        return CheckResult(
            CheckStatus.OK,
            body,
            data={"add_nodes": add_nodes},
        )


class OriginalEdgeUnderlayDiscovery(Check):
    """Wireless roam — shadow CDP discovery against the user-supplied Edge.

    When the wireless client has roamed off the elected Edge, the main chain
    is remapped to the discovered Edge and the original Edge is left visually
    orphaned. This check runs `show cdp neighbors detail` on the original
    Edge and wires up its underlay neighbors so both Edges show their fabric
    topology.

    SKIPs cleanly when no roam happened (state key not set).
    """

    name = "Underlay CDP Discovery (Original Edge)"
    target_node_id = "xtr"
    bypass_remap = True  # always anchor on the original "xtr" node

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        orig_hostname = ctx.state.get("original_xtr_hostname")
        if not (service and orig_hostname):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no wireless roam detected (original Edge identity not set).",
            )

        # Restrict the discovery to CEF underlay next-hops, not every CDP
        # neighbor on the box (which would drag in APs and unrelated access-
        # side switches). Reuse final_rlocs from the main run — the original
        # Edge reaches the same destination RLOCs via its own underlay, so its
        # CEF resolution of those RLOCs gives us the right port set.
        rlocs = ctx.state.get("final_rlocs") or []
        # INFRA_VN fallback: helpers are the underlay-routed destinations.
        if not rlocs:
            dhcp_info = ctx.state.get("dhcpparameters_info")
            helpers = getattr(dhcp_info, "helper_address", None) or []
            rlocs = list(helpers)
        if not rlocs:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no final_rlocs / helpers available to resolve original Edge underlay ports.",
            )

        try:
            from routingmodules.lisp import CEFForwardingState
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not import CEFForwardingState: {type(e).__name__}: {e}",
            )

        try:
            cef = CEFForwardingState(None, orig_hostname)
            cef.cef_underlay(rlocs, service)
            cef.underlay_phy(service)
            ports = list(cef.physical_interfaces or [])
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"CEF underlay resolution failed on original Edge {orig_hostname}: "
                f"{type(e).__name__}: {e}",
            )

        if not ports:
            return CheckResult(
                CheckStatus.SKIP,
                f"No underlay next-hop ports resolved on original Edge {orig_hostname}.",
            )

        try:
            from switchingmodules.cdp import CDPinfo
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not import CDPinfo: {type(e).__name__}: {e}",
            )

        from traffic_flows.dhcp_troubleshooting import abbrev_port

        source_node_id = "xtr"  # bypass_remap is True
        add_nodes = []
        unresolved_ports = []
        for idx, port in enumerate(ports):
            neighbors = []
            try:
                cdp = CDPinfo(orig_hostname)
                cdp.cdpneighborinterface(port, service)
                neighbors = getattr(cdp, "cdpneighbors", []) or []
            except BaseException:
                neighbors = []

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
                    "id": f"underlay-orig-{idx+1}",
                    "role": "underlay-switch",
                    "label": "\n".join(label_lines),
                    "ip": mgmt_ip or None,
                    "cdp_device_id": device_id or None,
                    "connect_to": source_node_id,
                    "edge_label": (
                        f"{abbrev_port(port)} ↔ {abbrev_port(remote)}"
                        if remote else abbrev_port(port)
                    ),
                })
            else:
                unresolved_ports.append(port)

        if unresolved_ports:
            edge_label = ", ".join(abbrev_port(p) for p in unresolved_ports)
            add_nodes.append({
                "id": "fabric-cloud",
                "role": "fabric",
                "label": "Fabric",
                "connect_to": source_node_id,
                "edge_label": edge_label,
            })

        if not add_nodes:
            return CheckResult(
                CheckStatus.WARN,
                f"No usable underlay neighbors on original Edge {orig_hostname}.",
            )

        ctx.state["underlay_nodes_orig"] = add_nodes
        by_source = ctx.state.setdefault("underlay_nodes_by_source", {})
        by_source[source_node_id] = add_nodes

        body_lines = []
        for n in add_nodes:
            if n.get("role") == "underlay-switch":
                dev = (n.get("label") or "").split("\n", 1)[0]
                mgmt = n.get("ip") or "?"
                body_lines.append(f"• {dev} ({mgmt}) via {n.get('edge_label')}")
        if unresolved_ports:
            body_lines.append(
                f"• Fabric (no CDP neighbor) via {', '.join(abbrev_port(p) for p in unresolved_ports)}"
            )
        return CheckResult(
            CheckStatus.OK,
            "Original Edge underlay neighbors (CEF next-hops):\n" + "\n".join(body_lines),
            data={"add_nodes": add_nodes},
        )

