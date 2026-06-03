"""Border / Control-Plane discovery and validation checks.

Border discovery (per-fabric-site), Control Plane Discovery, per-border data
collection, the 16 split BorderValidate steps, and ACL/multi-border checks.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks_shared import _legacy_fail


def _border_label(b, idx):
    return (
        getattr(b, "hostname", None)
        or getattr(getattr(b, "profiled_device", None), "hostname", None)
        or getattr(b, "mgmtip", None)
        or f"border{idx+1}"
    )


class BorderDiscovery(Check):
    """Border — lightweight discovery only. Calls CatC to list borders (one fast
    API call), emits `add_nodes` for each border immediately, and queues a
    ControlPlaneListing Check (slower) plus the per-border data-collection +
    validation + ACL chain.
    """

    name = "Border Discovery"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        fabric_id = ctx.state.get("fabric_id")

        if not (service and dnac and fabric_id):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires catc_name / fabric_id from earlier checks.",
            )

        try:
            from traffic_flows.iptransit import in_site_fabric_borders
            l3_borders = in_site_fabric_borders(0, fabric_id, dnac, service) or []
        except BaseException as e:
            return _legacy_fail(e, "Border discovery")

        ctx.state["l3_borders_raw"] = l3_borders
        ctx.state["border_objects"] = []  # populated by BorderCollect runs

        add_nodes = []
        followups: list[Check] = [ControlPlaneListing()]
        # Per-idx followup registry so BorderCollect can retarget Validate/Acl
        # after deciding (post-profile) whether a border merged into an
        # underlay node by CDP-hostname match.
        border_followups: dict = {}
        ctx.state["border_followups"] = border_followups

        # Draw a border node per discovered border; label = mgmt IP until
        # BorderCollect relabels it with the hostname.
        for idx, b in enumerate(l3_borders):
            bid = f"border-{idx+1}"
            mgmt = b.get("managementIpAddress") or f"border{idx+1}"
            status = (b.get("status") or "").strip().lower()
            add_nodes.append({
                "id": bid,
                "role": "border",
                "label": mgmt,
                "ip": b.get("managementIpAddress") or None,
                "connect_to": "xtr",
                "edge_label": "fabric",
            })
            if status == "reachable":
                collect = BorderCollect(idx=idx, border_id=bid, mgmt=mgmt)
                validate_steps = [
                    BorderValidateStep(
                        idx=idx, border_id=bid, mgmt=mgmt,
                        display_name=disp, func_name=fn, extra_args=extras,
                    )
                    for (disp, fn, extras) in BORDER_VALIDATION_STEPS
                ]
                acl = BorderAclCheck(idx=idx, border_id=bid, mgmt=mgmt)
                border_followups[idx] = {"validate_steps": validate_steps, "acl": acl}
                followups.append(collect)
                followups.extend(validate_steps)
                followups.append(acl)

        # After all per-border work, run the fabric-wide steps.
        followups.append(MultiBorderValidation())
        followups.append(BorderInterconnect())
        from checks_dhcp import DhcpServerCompatibility
        followups.append(DhcpServerCompatibility())

        reachable = sum(
            1 for b in l3_borders if (b.get("status") or "").strip().lower() == "reachable"
        )
        bullet_lines = []
        for b in l3_borders:
            hn = b.get("hostname") or b.get("name") or b.get("managementIpAddress") or "?"
            rloc = b.get("rloc") or b.get("loopback") or b.get("managementIpAddress") or "—"
            bullet_lines.append(f"• {hn} — RLOC {rloc}")
        body = "\n".join(bullet_lines) if bullet_lines else "(no borders found)"
        return CheckResult(
            CheckStatus.OK,
            body,
            data={
                "border_count": len(l3_borders),
                "add_nodes": add_nodes,
                "queue_checks": followups,
            },
        )


class ControlPlaneListing(Check):
    """Control planes — profile each fabric CP (device profiler + LISP ops). This
    is slower than border listing because each CP gets a CLI/RSA roundtrip,
    so it's its own Check that runs after the borders have already drawn.
    """

    name = "Control Plane Discovery"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        fabric_id = ctx.state.get("fabric_id")
        iid = ctx.state.get("lisp_iid")
        if not (service and dnac and fabric_id):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires catc_name / fabric_id.",
            )
        try:
            from traffic_flows.iptransit import validate_control_plane_status
            control_planes = validate_control_plane_status(
                fabric_id, iid, dnac, service, 0,
            ) or []
        except BaseException as e:
            return _legacy_fail(e, "Control plane listing")

        ctx.state["control_planes"] = control_planes
        l3_borders = ctx.state.get("l3_borders_raw") or []
        # IPs/hostnames of borders we already drew — used to suppress duplicate
        # CP nodes when a CP is colocated on a border (will surface as a
        # "Control Plane" tag on the border node instead).
        border_ips = {
            (b.get("managementIpAddress") or "").strip()
            for b in l3_borders if b.get("managementIpAddress")
        }
        border_hosts = {
            (b.get("hostname") or b.get("name") or "").strip().lower().split(".", 1)[0]
            for b in l3_borders
        }
        border_hosts.discard("")
        add_nodes = []
        bullet_lines = []
        for cp_idx, cp in enumerate(control_planes):
            cphost = (
                getattr(cp, "hostname", None)
                or getattr(getattr(cp, "profiled_device", None), "hostname", None)
                or getattr(cp, "mgmtip", None)
                or f"cp{cp_idx+1}"
            )
            rloc = (
                getattr(cp, "rloc", None)
                or getattr(cp, "loopback", None)
                or getattr(getattr(cp, "profiled_device", None), "loopback", None)
                or getattr(cp, "mgmtip", None)
                or "—"
            )
            cp_mgmt = (getattr(cp, "mgmtip", None) or "").strip()
            cp_host_norm = (str(cphost) or "").strip().lower().split(".", 1)[0]
            colocated = (cp_mgmt and cp_mgmt in border_ips) or (cp_host_norm and cp_host_norm in border_hosts)
            if colocated:
                bullet_lines.append(f"• {cphost} — RLOC {rloc}  (colocated with border — see border node)")
                continue
            add_nodes.append({
                "id": f"cp-{cp_idx+1}",
                "role": "control-plane",
                "label": cphost,
                "ip": getattr(cp, "mgmtip", None) or None,
                "connect_to": "xtr",
                "edge_label": "LISP",
            })
            bullet_lines.append(f"• {cphost} — RLOC {rloc}")
        body = "\n".join(bullet_lines) if bullet_lines else "(no control planes found)"
        return CheckResult(
            CheckStatus.OK,
            body,
            data={"add_nodes": add_nodes},
        )


class BorderCollect(Check):
    """Per-border — calls _fetch_single_border_data for ONE border. The slow part
    (CLI parsing, BGP/CEF/LISP/ACL collection) but scoped to one border so the
    other borders aren't blocked behind it.
    """

    def __init__(self, idx: int, border_id: str, mgmt: str):
        self.idx = idx
        self.target_node_id = border_id
        self.mgmt = mgmt
        self.name = f"Border Node Information [{mgmt}]"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        fabric_id = ctx.state.get("fabric_id")
        vrf = ctx.payload.get("vrf")
        vlan = ctx.payload.get("vlan")
        srcip = ctx.state.get("dhcp_srcip")
        dstip = ctx.state.get("dhcp_dstip")
        iid = ctx.state.get("lisp_iid")
        l3_borders = ctx.state.get("l3_borders_raw") or []
        control_planes = ctx.state.get("control_planes") or []

        if not (service and l3_borders and self.idx < len(l3_borders)):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — border discovery state missing.",
            )

        border_dict = l3_borders[self.idx]
        try:
            from traffic_flows.iptransit import _fetch_single_border_data
            bobj = _fetch_single_border_data(
                border_dict, fabric_id=fabric_id, vrf=vrf, vlanid=vlan,
                srcip=srcip, dstip=dstip, service=service, isdhcp=True,
                iid=iid, catc_name=dnac, control_planes=control_planes, step=0,
            )
        except BaseException as e:
            return _legacy_fail(e, f"Border data collection [{self.mgmt}]")

        if bobj is None:
            return CheckResult(
                CheckStatus.SKIP,
                f"Border '{self.mgmt}' was not reachable — skipping collection.",
            )

        bobjs = ctx.state.setdefault("border_objects", [])
        # Keep the list index-aligned with l3_borders so later checks can find it.
        while len(bobjs) <= self.idx:
            bobjs.append(None)
        bobjs[self.idx] = bobj

        hostname = getattr(
            getattr(bobj, "profiled_device", None), "hostname", None,
        ) or self.mgmt
        catc_hostname = getattr(
            getattr(bobj, "profiled_device", None), "catc_hostname", None,
        )
        btype = getattr(bobj, "type", "") or "unknown"
        # Pull the profiled RLOC (Loopback0) so the node carries the same
        # identity the Edge node shows after its own profiling.
        rloc = getattr(bobj, "rloc", None) or getattr(
            getattr(bobj, "profiled_device", None), "rloc", None,
        )
        # Hostname-based merge: match CatC's `hostname` (real configured
        # hostname / CDP-advertised) against each underlay node's CDP
        # `device_id`. If they match, fold this border node into that underlay
        # node — the underlay was the same physical device all along.
        def _norm(s):
            if not s:
                return ""
            s = str(s).lower()
            # Strip domain suffix so "edge1.sdawest.com" matches "edge1".
            return s.split(".", 1)[0]

        merge_into = None
        extra_merge_ids = []
        match_key = _norm(catc_hostname)
        if match_key:
            # Collect every underlay-switch node (across all source Edges) whose
            # CDP device_id matches this border's CatC hostname. First match is
            # the primary merge (relabel + retarget follow-ups); the rest are
            # additional fabric edges so a Border shared by multiple Edges
            # visually connects to all of them.
            seen_ids = set()
            sources = ctx.state.get("underlay_nodes_by_source") or {}
            # Iterate by-source first (covers main + original-Edge sources),
            # then fall back to the legacy flat list and the orig key in case
            # nothing was mirrored.
            candidates = []
            for src_id, nodes in sources.items():
                for u in nodes or []:
                    candidates.append(u)
            for u in (ctx.state.get("underlay_nodes") or []):
                candidates.append(u)
            for u in (ctx.state.get("underlay_nodes_orig") or []):
                candidates.append(u)
            for u in candidates:
                uid = u.get("id")
                if not uid or uid in seen_ids:
                    continue
                if _norm(u.get("cdp_device_id")) != match_key:
                    continue
                seen_ids.add(uid)
                if merge_into is None:
                    merge_into = uid
                else:
                    extra_merge_ids.append(uid)

        # Retarget Validate / AclCheck for this border so subsequent check
        # status / messages land on the merged node.
        if merge_into:
            followups = (ctx.state.get("border_followups") or {}).get(self.idx, {})
            for key, val in followups.items():
                if isinstance(val, list):
                    for chk in val:
                        chk.target_node_id = merge_into
                else:
                    val.target_node_id = merge_into

        # Display name on the node: prefer the real CDP/CatC hostname over the
        # RSA inventory name.
        display_name = catc_hostname or hostname
        # Tag preserved across the relabel so the Border role stays visible on
        # nodes that were merged with a CDP next-hop.
        tags = ["Border"]
        # If this border is also a control plane (colocated), surface it on the
        # same node so users see both roles on one icon.
        def _norm_host(s):
            return (str(s) or "").strip().lower().split(".", 1)[0]
        bmgmt = (self.mgmt or "").strip()
        bhost_norm = _norm_host(display_name)
        for cp in (control_planes or []):
            cp_mgmt = (getattr(cp, "mgmtip", None) or "").strip()
            cp_host = (
                getattr(cp, "hostname", None)
                or getattr(getattr(cp, "profiled_device", None), "hostname", None)
                or ""
            )
            if (cp_mgmt and cp_mgmt == bmgmt) or (bhost_norm and _norm_host(cp_host) == bhost_norm):
                tags.append("CP")
                break
        result_data = {
            "node_relabel": display_name,
            "node_tags": tags,
        }
        if rloc:
            result_data["node_rloc"] = rloc
        if merge_into:
            result_data["merge_into"] = {
                "source": self.target_node_id,
                "target": merge_into,
                "edge_label": "fabric",
            }
        # For each additional underlay-switch that matches this border's
        # hostname (i.e. same physical Border showing up as a CDP neighbor on
        # a second Edge — wireless roam case), draw an extra "fabric" edge
        # from the merged border node to that underlay-switch. The frontend
        # treats add_edges as idempotent on (source, target).
        if extra_merge_ids and merge_into:
            result_data["add_edges"] = [
                {"source": merge_into, "target": uid, "label": "fabric"}
                for uid in extra_merge_ids
            ]

        # Human-readable role + type
        type_label = {
            "isinternal": "Internal Border",
            "isexternal": "External Border",
            "isanywhere": "Anywhere Border",
        }.get(str(btype).lower(), str(btype) or "unknown")

        # Pull BGP local AS from bobj.bgpinfo (set by bgp_parameters).
        local_as = None
        try:
            bgpinfo = getattr(bobj, "bgpinfo", None)
            bgsum = getattr(bgpinfo, "bgsum", {}) or {}
            vrf_name = getattr(bgpinfo, "vrf", "default")
            local_as = (
                bgsum.get("vrf", {})
                .get(vrf_name, {})
                .get("bgp_id")
            )
        except Exception:
            local_as = None

        body = (
            f"Border Node Information\n"
            f"• Hostname: {display_name}\n"
            f"• Role: {type_label}\n"
            f"• Border Type: {btype or '—'}\n"
            f"• RLOC: {rloc or '—'}\n"
            f"• BGP AS: {local_as if local_as is not None else '—'}"
        )
        # If this border has no BGP route upstream for the VRF (neither a
        # destination-specific entry nor a default route), mark the result as
        # WARN and skip the destination-anchored sub-checks downstream —
        # _fetch_single_border_data has already short-circuited the heavy
        # collection so the rest of the border's per-flow validations would
        # have nothing real to verify.
        if getattr(bobj, "no_bgp_upstream", False):
            body += (
                f"\n• Upstream BGP: NONE in VRF {vrf or '—'} "
                f"(no specific route for {dstip or '—'} and no 0.0.0.0/0)."
                f"\n  Skipping destination-anchored sub-checks (forwarding to "
                f"destination, LISP parameters, ping)."
            )
            return CheckResult(
                CheckStatus.WARN,
                body,
                data=result_data,
            )
        return CheckResult(
            CheckStatus.OK,
            body,
            data=result_data,
        )


def _describe_border_validation(func_name: str, b, hostname: str) -> str:
    """Produce a descriptive success body for a per-border validation step.

    Validators side-effect-log to the file but only return a step counter.
    Read back attributes set on the border object to render a human summary.
    """
    def _yn(v):
        if v is True:
            return "Yes"
        if v is False:
            return "No"
        return "—" if v is None else str(v)

    _btype_label = {
        "isinternal": "Internal Border",
        "isexternal": "External Border",
        "isanywhere": "Anywhere Border",
    }

    try:
        vrf = getattr(b, "vrf", None)
        btype = (getattr(b, "type", "") or "").strip().lower()
        btype_human = _btype_label.get(btype, btype or "—")

        if func_name == "validate_anycast_gateway_recursion":
            gw_fwd = getattr(b, "anycastgw", None)
            nexthops = (
                getattr(gw_fwd, "nexthops", None)
                or (gw_fwd.get("nexthops") if isinstance(gw_fwd, dict) else [])
                or []
            )
            nh_lines = []
            matched_oif = None
            for nh in nexthops:
                nh_val = (nh.get("nexthop") or "").strip() if isinstance(nh, dict) else (
                    getattr(nh, "nexthop", "") or ""
                ).strip()
                oif_val = nh.get("oif") if isinstance(nh, dict) else getattr(nh, "oif", None)
                oifs = list(oif_val.keys()) if isinstance(oif_val, dict) else (
                    [oif_val] if isinstance(oif_val, str) else []
                )
                oif_str = ", ".join(str(o) for o in oifs) or "—"
                nh_lines.append(f"    – Next-hop {nh_val or '—'} via {oif_str}")
                if nh_val.lower() == "receive" and any(str(o).startswith(("Loopback", "Vlan")) for o in oifs):
                    matched_oif = next((str(o) for o in oifs if str(o).startswith(("Loopback", "Vlan"))), None)
            ag = getattr(b, "anycastgwinfo", None) or {}
            ip4 = ((ag.get("ipPoolDetails", {}) or {}).get("ipV4AddressSpace", {}) or {})
            subnet = ip4.get("subnet")
            plen = ip4.get("prefixLength")
            pool = f"{subnet}/{plen}" if subnet and plen else "—"
            gw_ip = ip4.get("gatewayIpAddress") or "—"
            return (
                f"• VRF: {vrf or '—'}\n"
                f"• Anycast Gateway Pool: {pool}  (Gateway IP {gw_ip})\n"
                f"• CEF Next-hops Examined ({len(nexthops)}):\n" + "\n".join(nh_lines) +
                f"\n• Local Receive Adjacency Found On: {matched_oif or '—'}"
            )

        if func_name == "validate_petr_settings":
            if btype not in {"isexternal", "isanywhere"}:
                return (
                    f"• Border Type: {btype_human}\n"
                    f"• PETR Validation: Not Applicable (only External and Anywhere borders act as PETR)."
                )
            ls = getattr(b, "lispstatus", None) or {}
            petr = (ls.get("petr") if isinstance(ls, dict) else getattr(ls, "petr", None)) or {}
            usepetrs = (ls.get("usepetrs") if isinstance(ls, dict) else getattr(ls, "usepetrs", None)) or {}
            petr_locs = list(petr.keys()) if isinstance(petr, dict) else []
            use_locs = list(usepetrs.keys()) if isinstance(usepetrs, dict) else []
            return (
                f"• Border Type: {btype_human}\n"
                f"• Proxy-ETR (PETR) Enabled: {'Yes' if petr_locs else 'No'}\n"
                f"• PETR Locators ({len(petr_locs)}): {', '.join(map(str, petr_locs)) or '(none)'}\n"
                f"• use-PETR Configured: {'Yes' if use_locs else 'No'}\n"
                f"• use-PETR Locators ({len(use_locs)}): {', '.join(map(str, use_locs)) or '(none)'}"
            )

        if func_name == "validate_control_plane_logic":
            cps = getattr(b, "control_planes", []) or []
            target_iid = getattr(b, "lispiid", None)
            ls = getattr(b, "lispstatus", None) or {}
            target_ip = ls.get("rloc") if isinstance(ls, dict) else getattr(ls, "rloc", None)
            ag = getattr(b, "anycastgwinfo", None) or {}
            ip4 = ((ag.get("ipPoolDetails", {}) or {}).get("ipV4AddressSpace", {}) or {})
            subnet = ip4.get("subnet")
            plen = ip4.get("prefixLength")
            pool = f"{subnet}/{plen}" if subnet and plen else "—"
            lines = [
                f"• Instance-ID (VNI): {target_iid}",
                f"• Subnet Checked: {pool}",
                f"• Border Loopback RLOC: {target_ip or '—'}",
                f"• Control Planes Evaluated: {len(cps)}",
            ]
            for cp in cps:
                cp_host = getattr(cp, "hostname", "?")
                ispubsub = getattr(cp, "ispubsub", False)
                cp_config = getattr(cp, "lispcpconfig", {})
                cfg = vars(cp_config) if hasattr(cp_config, "__dict__") else cp_config
                lispsvc = ((cfg.get("lispservice", {}) or {}).get("lisp_id", {}) or {}).get(0, {}) or {}
                ms_en = (lispsvc.get("map_server", {}) or {}).get("enabled")
                mr_en = (lispsvc.get("map_resolver", {}) or {}).get("enabled")
                site_uci = cfg.get("site_uci", {}) or {}
                eid_records = (site_uci.get("eid_records", {}) or {}).get(target_iid, [])
                eid_present = pool in eid_records
                allow_locs = (site_uci.get("allow_locator_default_etr", {}) or {}).get(target_iid, [])
                sess_obj = getattr(cp, "lispsession", {})
                sess = vars(sess_obj) if hasattr(sess_obj, "__dict__") else sess_obj
                peer_sessions = (sess.get("peers", {}) or {}).get(target_ip, []) or []
                states = [s.get("state") for s in peer_sessions if isinstance(s, dict)]
                lines.append(f"  Control Plane: {cp_host}")
                lines.append(f"    – Map-Server Enabled: {_yn(ms_en)}")
                lines.append(f"    – Map-Resolver Enabled: {_yn(mr_en)}")
                lines.append(f"    – Pub/Sub Mode: {_yn(ispubsub)}")
                lines.append(f"    – Fabric Subnet Registered as EID Record: {'Yes' if eid_present else 'No'}")
                lines.append(f"    – Default-ETR Locator Families Allowed: {', '.join(map(str, allow_locs)) or '(none)'}")
                lines.append(f"    – LISP Session States to this Border: {', '.join(map(str, states)) or '(none)'}")
            return "\n".join(lines)

        if func_name == "validate_vrf_configuration":
            vd = getattr(b, "vrfdetail_info", None) or {}
            rd = (vd.get("route_distinguisher") or "").strip()
            interfaces = vd.get("interfaces") or []
            li_intf = next((i for i in interfaces if str(i).startswith("LI")), None)
            ipv4_af = (vd.get("address_family", {}) or {}).get("ipv4 unicast", {}) or {}
            rts = list((ipv4_af.get("route_targets", {}) or {}).keys())
            return (
                f"• VRF Name: {vrf or '—'}\n"
                f"• Route Distinguisher: {rd or '—'}\n"
                f"• LISP Sub-interface: {li_intf or '—'}\n"
                f"• Member Interfaces ({len(interfaces)}): {', '.join(map(str, interfaces)) or '(none)'}\n"
                f"• IPv4 Route-Targets: {', '.join(map(str, rts)) or '(none)'}"
            )

        if func_name == "validate_bgp_summary":
            bgp = getattr(b, "bgpinfo", None) or {}
            ipprot = getattr(bgp, "ipprotocols", None) or {}
            ipv4 = (
                ((((ipprot.get("protocols", {}) or {}).get("bgp", {}) or {}).get("instance", {}) or {})
                 .get("default", {}) or {}).get("vrf", {}) or {}
            )
            vrf_name = next(iter(ipv4.keys()), vrf)
            af = (((ipv4.get(vrf_name, {}) or {}).get("address_family", {}) or {}).get("ipv4", {}) or {})
            redists = af.get("redistributing") or []
            nbr_map = af.get("neighbors", {}) or {}
            bgsum = getattr(bgp, "bgsum", None) or {}
            vrf_bgp = ((bgsum.get("vrf", {}) or {}).get(vrf_name, {}) or {})
            sum_nbrs = vrf_bgp.get("neighbor", {}) or {}
            nbr_lines = []
            for nbr, ndata in nbr_map.items():
                rm = ndata.get("route_map") or "—"
                afs_sum = (sum_nbrs.get(nbr, {}) or {}).get("address_family", {}) or {}
                total = next((d.get("prefixes", {}).get("total_entries") for d in afs_sum.values() if isinstance(d, dict)), None)
                nbr_lines.append(
                    f"    – {nbr}: Route-Map = {rm}, Prefixes Received = "
                    f"{total if total is not None else '?'}"
                )
            ispubsub = getattr(getattr(b, "profiled_device", None), "ispubsub", False)
            return (
                f"• VRF: {vrf_name or '—'}\n"
                f"• Protocols Redistributed Into BGP: {', '.join(redists) or '(none)'}\n"
                f"• Pub/Sub Mode: {_yn(ispubsub)}\n"
                f"• BGP Neighbors ({len(nbr_map)}):\n" + ("\n".join(nbr_lines) if nbr_lines else "    (none)")
            )

        if func_name == "validate_bgp_neighbors":
            nbrs = getattr(b, "bgpneighborsinfo", None) or []
            lines = []
            for n in nbrs:
                nbr_ip = getattr(n, "neighborip", None)
                nbr_vrf = getattr(n, "vrf", None)
                bgpneighbor = getattr(n, "bgpneighbor", None) or {}
                nd = ((((bgpneighbor.get("vrf", {}) or {}).get(nbr_vrf, {}) or {})
                       .get("neighbor", {}) or {}).get(nbr_ip, {}) or {})
                state = nd.get("session_state") or "?"
                ras = nd.get("remote_as") or "?"
                link = (nd.get("link") or "—").strip().capitalize()
                dg = (((nd.get("bgp_session_transport", {}) or {}).get("datagram", {}) or {})
                      .get("datagram_sent", {}) or {})
                retr = dg.get("retransmit", 0) or 0
                fretr = dg.get("fastretransmit", 0) or 0
                lines.append(
                    f"• Neighbor {nbr_ip} (VRF {nbr_vrf}, AS {ras}, {link} peer)\n"
                    f"    – Session State: {state}\n"
                    f"    – TCP Retransmits: {retr}\n"
                    f"    – Fast Retransmits: {fretr}"
                )
            return "\n".join(lines) if lines else "• No BGP neighbors were found on this border."

        if func_name == "validate_bgp_neighbor_policies":
            nbrs = getattr(b, "bgpneighborsinfo", None) or []
            bgp_info_obj = getattr(b, "bgpinfo", {}) or {}
            ipprot = getattr(bgp_info_obj, "ipprotocols", {}) or {}
            lines = []
            for n in nbrs:
                nbr_ip = getattr(n, "neighborip", None)
                nbr_vrf = getattr(n, "vrf", None)
                weight = (getattr(n, "bgpneighbor", {}) or {}).get("default_weight", 0)
                bgp_obj = getattr(n, "bgpneighbor", {}) or {}
                nd = ((bgp_obj.get("vrf", {}) or {}).get(nbr_vrf, {}) or {}).get("neighbor", {}).get(nbr_ip, {}) or {}
                link_raw = (nd.get("link") or "").strip().lower()
                link_h = "External (eBGP)" if link_raw == "external" else ("Internal (iBGP)" if link_raw == "internal" else "—")
                af = (
                    ipprot.get("protocols", {}).get("bgp", {}).get("instance", {}).get("default", {})
                    .get("vrf", {}).get(nbr_vrf, {}).get("address_family", {}).get("ipv4", {})
                )
                rm_in = af.get("neighbors", {}).get(nbr_ip, {}).get("route_map") if isinstance(af, dict) else None
                lines.append(
                    f"• Neighbor {nbr_ip} ({link_h})\n"
                    f"    – Weight: {weight}\n"
                    f"    – Inbound Route-Map: {rm_in or '—'}"
                )
            return "\n".join(lines) if lines else "• No BGP neighbors to evaluate."

        if func_name == "validate_advertised_local_prefix":
            vrf_name = vrf
            local_route = getattr(b, "local_route", None) or {}
            if (vrf_name or "").lower() == "default":
                local_prefixes = (
                    ((((local_route.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
                     .get(vrf_name, {}) or {}).get("address_family", {}) or {}
                ).get("", {}).get("prefixes", {}) or {}
            else:
                local_prefixes = (
                    ((((local_route.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
                     .get(vrf_name, {}) or {}).get("address_family", {}) or {}
                ).get("vpnv4 unicast", {}).get("prefixes", {}) or {}
            local_prefix = next(iter(local_prefixes.keys()), None)
            advertised_to = []
            for n in (getattr(b, "bgpneighborsinfo", None) or []):
                nbr_ip = getattr(n, "neighborip", None)
                adv = getattr(n, "advertisdedroutes", None) or getattr(n, "advertisedroutes", None) or {}
                af = (
                    ((((adv.get("vrf", {}) or {}).get(vrf_name, {}) or {}).get("neighbor", {}) or {}).get(nbr_ip, {}) or {})
                    .get("address_family", {}) or {}
                )
                for _, af_data in af.items():
                    ad = (af_data.get("advertised", {}) or {})
                    if local_prefix and local_prefix in ad:
                        idx = (ad[local_prefix].get("index", {}) or {}).get(1, {}) or {}
                        advertised_to.append(
                            f"{nbr_ip} (next-hop {idx.get('next_hop','—')}, origin {idx.get('origin_codes','—')})"
                        )
                        break
            return (
                f"• VRF: {vrf or '—'}\n"
                f"• Local Prefix Selected: {local_prefix or '(none)'}\n"
                f"• Advertised To: " +
                ("\n    – " + "\n    – ".join(advertised_to) if advertised_to else "(no Established neighbor received it)")
            )

        if func_name == "validate_source_recursion":
            srcip = getattr(b, "srcip", None) or getattr(b, "sourceip", None)
            ports = (
                getattr(b, "srcoutgoingports", None)
                or getattr(b, "outgoingports", None)
                or []
            )
            return (
                f"• Source IP Examined: {srcip or '—'}\n"
                f"• VRF: {vrf or '—'}\n"
                f"• Resolved Outgoing Interface(s): {', '.join(map(str, ports)) or '(none)'}"
            )

        if func_name == "validate_destination_not_lisp":
            dstip = getattr(b, "dstip", None)
            ports = getattr(b, "destoutgoingports", None) or []
            cef = getattr(b, "destcefinformation", None) or {}
            nexthops = getattr(cef, "nexthops", None) or []
            pair_lines = []
            for nh in nexthops:
                nh_ip = (nh.get("nexthop") or "").strip() if isinstance(nh, dict) else (getattr(nh, "nexthop", "") or "").strip()
                oif_val = nh.get("oif") if isinstance(nh, dict) else getattr(nh, "oif", None)
                oifs = list(oif_val.keys()) if isinstance(oif_val, dict) else (
                    [oif_val] if isinstance(oif_val, str) else []
                )
                pair_lines.append(f"    – Next-hop {nh_ip or '—'} via {', '.join(map(str, oifs)) or '—'}")
            return (
                f"• Destination IP: {dstip or '—'}\n"
                f"• CEF Next-hops:\n" + ("\n".join(pair_lines) if pair_lines else "    (none)") +
                f"\n• Outgoing Physical Ports: {', '.join(map(str, ports)) or '(none)'}"
            )

        if func_name == "validate_ping_results":
            pr = getattr(b, "ping_results", None)
            res = getattr(pr, "result", None) if pr else None
            dstip = getattr(b, "dstip", None)
            try:
                r = int(res)
                verdict = "Above 70% threshold (healthy)" if r > 70 else "Below 70% threshold (expected for all-but-one border in anycast)"
            except Exception:
                verdict = "—"
            return (
                f"• Ping Source: {hostname}\n"
                f"• Ping Destination: {dstip or '—'}\n"
                f"• Success Rate: {res if res is not None else '—'}%\n"
                f"• Verdict: {verdict}"
            )

        if func_name == "validate_route_import":
            if btype == "isexternal":
                return (
                    f"• Border Type: {btype_human}\n"
                    f"• Route-Import Validation: Not Applicable (External-only borders do not import routes into LISP)."
                )
            bgp = getattr(b, "bgpinfo", None) or {}
            route_obj = getattr(bgp, "route", None) or {}
            vrf_name = vrf
            if (vrf_name or "").lower() == "default":
                prefs = (
                    ((((route_obj.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
                     .get(vrf_name, {}) or {}).get("address_family", {}) or {}
                ).get("", {}).get("prefixes", {}) or {}
            else:
                prefs = (
                    ((((route_obj.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
                     .get(vrf_name, {}) or {}).get("address_family", {}) or {}
                ).get("vpnv4 unicast", {}).get("prefixes", {}) or {}
            bgp_prefix = next(iter(prefs.keys()), None)
            ls = getattr(b, "lispstatus", None) or {}
            ri = (((ls.get("database", {}) or {}).get("route_import", {}) or {})) if isinstance(ls, dict) else {}
            ri_size = ri.get("size")
            ri_limit = ri.get("limit")
            ld = getattr(b, "lispdbroute", None) or {}
            eid = (ld.get("eid") if isinstance(ld, dict) else getattr(ld, "eid", None)) or "—"
            locators = ld.get("locators") if isinstance(ld, dict) else (getattr(ld, "locators", None) or [])
            mss = ld.get("mapservers") if isinstance(ld, dict) else (getattr(ld, "mapservers", None) or [])
            ack_lines = []
            for ms in (mss or []):
                if isinstance(ms, dict):
                    ms_name = ms.get('ms') or ms.get('peer') or '?'
                    ack_lines.append(f"{ms_name} → {ms.get('ack') or '?'}")
            util = (
                f"{ri_size} / {ri_limit}"
                if (ri_size is not None and ri_limit is not None) else "—"
            )
            return (
                f"• VRF: {vrf or '—'}\n"
                f"• Best BGP Prefix Selected: {bgp_prefix or '(none)'}\n"
                f"• LISP Route-Import DB Utilization: {util}\n"
                f"• LISP Database EID Entry: {eid}\n"
                f"• Locators Bound to EID: {len(locators or [])}\n"
                f"• Map-Server Acknowledgements: {', '.join(ack_lines) or '(none)'}"
            )

        if func_name == "validate_default_route_and_default_etr":
            if btype not in {"isexternal", "isanywhere"}:
                return (
                    f"• Border Type: {btype_human}\n"
                    f"• Default Route / Default-ETR Check: Not Applicable (only External and Anywhere borders)."
                )
            ls = getattr(b, "lispstatus", None) or {}
            rloc = ls.get("rloc") if isinstance(ls, dict) else getattr(ls, "rloc", None)
            bgp = getattr(b, "bgpinfo", None) or {}
            defroute = getattr(bgp, "defroute", None) or {}
            vrf_name = vrf
            if (vrf_name or "").lower() == "default":
                prefs = (
                    ((((defroute.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
                     .get(vrf_name, {}) or {}).get("address_family", {}) or {}
                ).get("", {}).get("prefixes", {}) or {}
            else:
                prefs = (
                    ((((defroute.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
                     .get(vrf_name, {}) or {}).get("address_family", {}) or {}
                ).get("vpnv4 unicast", {}).get("prefixes", {}) or {}
            has_default = "0.0.0.0/0" in prefs
            ld = getattr(b, "lispdbroute", None) or {}
            eid = (ld.get("eid") if isinstance(ld, dict) else getattr(ld, "eid", None)) or "—"
            remote_locs = getattr(b, "remote_iid_locators", None) or []
            match = next((e for e in remote_locs if (e.get("rloc_ip") or "").strip() == rloc), None)
            prio = match.get("priority") if match else "—"
            return (
                f"• VRF: {vrf or '—'}\n"
                f"• Border Loopback RLOC: {rloc or '—'}\n"
                f"• BGP Default Route (0.0.0.0/0) Learned: {'Yes' if has_default else 'No'}\n"
                f"• LISP Database EID Entry: {eid}\n"
                f"• Default-ETR Locator Priority: {prio}"
            )

        if func_name == "validate_local_route_bgp_origin":
            local_route = getattr(b, "local_route", None) or {}
            vrf_name = vrf or "—"
            af_block = (
                ((((local_route.get("instance", {}) or {}).get("default", {}) or {}).get("vrf", {}) or {})
                 .get(vrf, {}) or {}).get("address_family", {}) or {}
            )
            ORIGIN_LEGEND = {"i": "IGP (i)", "e": "EGP (e)", "?": "Incomplete (?)"}
            entries = []
            matched_prefix = None
            best_origin_label = None
            best_nexthop = None
            for af_name, af_data in (af_block or {}).items():
                prefixes = (af_data.get("prefixes", {}) or {}) if isinstance(af_data, dict) else {}
                for pfx, pfx_data in prefixes.items():
                    matched_prefix = matched_prefix or pfx
                    idx_map = (pfx_data.get("index", {}) or {}) if isinstance(pfx_data, dict) else {}
                    for idx_id, idx in idx_map.items():
                        if not isinstance(idx, dict):
                            continue
                        status = str(idx.get("status_codes") or "")
                        origin = (idx.get("origin_codes") or "").strip()
                        origin_label = ORIGIN_LEGEND.get(origin, origin or "—")
                        nh = idx.get("next_hop") or "—"
                        is_best = ">" in status
                        marker = "[best] " if is_best else ""
                        entries.append(
                            f"    – Path {idx_id}: {marker}Origin Type: {origin_label}, Next-Hop: {nh}"
                        )
                        if is_best and best_origin_label is None:
                            best_origin_label = origin_label
                            best_nexthop = nh
            if not entries:
                return (
                    f"• VRF: {vrf_name}\n"
                    f"• Locally Originated Prefix: (none found in BGP RIB)"
                )
            best_line = (
                f"• Best Path Origin: {best_origin_label} (next-hop {best_nexthop})\n"
                if best_origin_label else
                "• Best Path Origin: (no best path was selected)\n"
            )
            return (
                f"• VRF: {vrf_name}\n"
                f"• Locally Originated Prefix: {matched_prefix or '—'}\n"
                + best_line
                + f"• BGP Paths ({len(entries)}):\n" + "\n".join(entries)
            )

        if func_name == "validate_overlapping_summaries":
            if btype not in {"isanywhere", "isinternal"}:
                return (
                    f"• Border Type: {btype_human}\n"
                    f"• Overlapping-Summary Check: Not Applicable (only Anywhere and Internal borders)."
                )
            lisp_local = getattr(b, "lispfwdinglocaleid", None) or {}
            prefixes = lisp_local.get("prefixes") or []
            return (
                f"• Local LISP EID Prefixes Evaluated ({len(prefixes)}): "
                f"{', '.join(map(str, prefixes)) or '(none)'}\n"
                f"• Result: No overlapping summary prefixes were detected."
            )

        if func_name == "validate_interface_counters":
            intfs = getattr(b, "interfacestats", None) or []
            lines = []
            for i in intfs:
                d = vars(i) if hasattr(i, "__dict__") else (i or {})
                lines.append(
                    f"• {d.get('interface') or '?'}\n"
                    f"    – Input Queue Drops: {d.get('iqdrops', 0)}\n"
                    f"    – Output Drops: {d.get('outputdrops', 0)}\n"
                    f"    – CRC Errors: {d.get('crcerrors', 0)}\n"
                    f"    – Giants: {d.get('giants', 0)}\n"
                    f"    – Runts: {d.get('runts', 0)}"
                )
            return "\n".join(lines) if lines else "• No interface counters were collected."

        if func_name == "log_cts_enforcement_status":
            cts_list = getattr(b, "ctsinfo", None) or []
            if not cts_list:
                return "• CTS information was not collected for this border."
            dstip = getattr(b, "dstip", None)
            lines = [f"• Destination Evaluated: {dstip or '—'}"]
            for c in cts_list:
                ge = getattr(c, "globalenforcement", None)
                ve = getattr(c, "vlanenforcement", None)
                pe = getattr(c, "ctsportenabled", None)
                cvrf = getattr(c, "vrf", None)
                sgt = getattr(c, "cefsgt", None)
                lines.append(f"• VRF: {cvrf}")
                lines.append(f"    – Global Enforcement: {_yn(ge)}")
                lines.append(f"    – VLAN Enforcement: {_yn(ve)}")
                lines.append(f"    – Port Enforcement: {_yn(pe)}")
                lines.append(f"    – Destination SGT: {sgt}")
            return "\n".join(lines)
    except Exception:
        return ""
    return ""



BORDER_VALIDATION_STEPS = [
    # (display_name, function_name, extra_args)
    # extra_args: tuple of strings, each one of {"hostname", "service"}.
    ("Anycast Gateway Recursion", "validate_anycast_gateway_recursion", ()),
    ("PETR Settings", "validate_petr_settings", ("hostname",)),
    ("Control Plane Logic", "validate_control_plane_logic", ("service",)),
    ("VRF Configuration", "validate_vrf_configuration", ()),
    ("BGP Summary", "validate_bgp_summary", ()),
    ("BGP Neighbors", "validate_bgp_neighbors", ()),
    ("BGP Neighbor Policies", "validate_bgp_neighbor_policies", ("hostname",)),
    ("Advertised Local Prefix", "validate_advertised_local_prefix", ()),
    ("Source Recursion", "validate_source_recursion", ("hostname", "service")),
    ("Destination Not LISP", "validate_destination_not_lisp", ("hostname",)),
    ("Ping Results", "validate_ping_results", ("hostname",)),
    ("Route Import", "validate_route_import", ("hostname",)),
    ("Default Route / Default ETR", "validate_default_route_and_default_etr", ("hostname",)),
    ("Local Route BGP Origin", "validate_local_route_bgp_origin", ("hostname",)),
    ("Overlapping Summaries", "validate_overlapping_summaries", ("hostname",)),
    ("Interface Counters", "validate_interface_counters", ("hostname",)),
    ("CTS Enforcement", "log_cts_enforcement_status", ("hostname",)),
]


class BorderValidateStep(Check):
    """Per-border, per-validation — runs one sub-validation from iptransit on a
    single border. Splitting the legacy individual_border_validations into
    bite-size Checks so each one reports independently.
    """

    def __init__(self, idx: int, border_id: str, mgmt: str,
                 display_name: str, func_name: str, extra_args: tuple):
        self.idx = idx
        self.target_node_id = border_id
        self.mgmt = mgmt
        self.func_name = func_name
        self.extra_args = extra_args
        self.name = f"{display_name} [{mgmt}]"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        bobjs = ctx.state.get("border_objects") or []
        bobj = bobjs[self.idx] if self.idx < len(bobjs) else None
        if not (service and bobj):
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — no hydrated border object for '{self.mgmt}'.",
            )
        # When _fetch_single_border_data found no upstream BGP path for the
        # VRF on this border, the destination-anchored attrs were never
        # populated. SKIP the validators that would either crash or compare
        # against empty data — keep the source-side, BGP-summary, ACL, and
        # counter validators running, since they're meaningful regardless.
        _DEST_ANCHORED = {
            "validate_destination_not_lisp",
            "validate_ping_results",
            "validate_route_import",
            "validate_overlapping_summaries",
        }
        if getattr(bobj, "no_bgp_upstream", False) and self.func_name in _DEST_ANCHORED:
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — '{self.mgmt}' has no upstream BGP route in this VRF "
                f"(neither a specific entry for the destination nor a default), "
                f"so destination-anchored validation has nothing to check.",
            )
        try:
            from traffic_flows import iptransit
            fn = getattr(iptransit, self.func_name)
            hostname = getattr(
                getattr(bobj, "profiled_device", None), "hostname", None,
            ) or self.mgmt
            args = [bobj, 0]
            for kind in self.extra_args:
                if kind == "hostname":
                    args.append(hostname)
                elif kind == "service":
                    args.append(service)
            fn(*args)
        except BaseException as e:
            return _legacy_fail(e, f"{self.name}")
        body = _describe_border_validation(self.func_name, bobj, hostname) or "Validation passed."
        return CheckResult(CheckStatus.OK, body)


class BorderAclCheck(Check):
    """Per-border — validate egress ACLs on this border for the DHCP relay path."""

    def __init__(self, idx: int, border_id: str, mgmt: str):
        self.idx = idx
        self.target_node_id = border_id
        self.mgmt = mgmt
        self.name = f"Border ACL validation [{mgmt}]"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        bobjs = ctx.state.get("border_objects") or []
        bobj = bobjs[self.idx] if self.idx < len(bobjs) else None
        if not (service and bobj):
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — no hydrated border object for '{self.mgmt}'.",
            )
        try:
            from traffic_flows.dhcp_troubleshooting import validate_border_acls
            validate_border_acls([bobj], service, 0)
        except BaseException as e:
            return _legacy_fail(e, f"Border ACL validation [{self.mgmt}]")
        return CheckResult(
            CheckStatus.OK,
            f"No egress ACLs on '{self.mgmt}' that would drop the DHCP relay path.",
        )


class MultiBorderValidation(Check):
    """Fabric-wide — runs multi_border_validation across all hydrated borders."""

    name = "Multi-border validation (overlap, transit consistency)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        bobjs = [b for b in (ctx.state.get("border_objects") or []) if b is not None]
        if not (service and bobjs):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no hydrated border objects available.",
            )
        try:
            from traffic_flows.iptransit import multi_border_validation
            multi_border_validation(bobjs, 0, service)
        except BaseException as e:
            return _legacy_fail(e, "Multi-border validation")
        return CheckResult(
            CheckStatus.OK,
            f"Multi-border validation complete across {len(bobjs)} border(s).",
        )


def _norm_hostname(s):
    """Strip the FQDN suffix so 'border1.sdawest.com' matches 'border1'."""
    if not s:
        return ""
    return str(s).strip().lower().split(".", 1)[0]


class BorderInterconnect(Check):
    """Discover CDP adjacencies BETWEEN borders and draw inter-border edges.

    Runs after all per-border collection so each border has been profiled and
    we know the real CDP hostname. Queries `show cdp neighbors detail` on each
    reachable border, matches each neighbor's device_id against the other
    borders' hostnames, and emits one edge per matched pair.
    """

    name = "Border interconnect (CDP)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        bobjs = ctx.state.get("border_objects") or []
        l3_borders = ctx.state.get("l3_borders_raw") or []
        if not (service and bobjs):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no hydrated border objects available.",
            )

        # Build idx → (border_id, radkit_name, match_name, mgmtip).
        # radkit_name is what we hand to RSA (must match service.inventory);
        # match_name is what neighbors advertise via CDP (CatC hostname is
        # usually the closest, falling back to the configured hostname).
        info_by_idx = {}
        hostname_to_idx = {}
        for idx, bobj in enumerate(bobjs):
            if bobj is None:
                continue
            profiled = getattr(bobj, "profiled_device", None)
            radkit_name = (
                getattr(profiled, "hostname", None)
                or getattr(bobj, "hostname", None)
            )
            match_name = (
                getattr(profiled, "catc_hostname", None)
                or radkit_name
            )
            mgmtip = (
                getattr(profiled, "mgmtip", None)
                or (l3_borders[idx].get("managementIpAddress") if idx < len(l3_borders) else None)
            )
            border_id = f"border-{idx+1}"
            info_by_idx[idx] = {
                "border_id": border_id,
                "radkit_name": radkit_name,
                "match_name": match_name,
                "mgmtip": mgmtip,
            }
            for cand in (match_name, radkit_name):
                norm = _norm_hostname(cand)
                if norm:
                    hostname_to_idx[norm] = idx

        # Edge-side targets: "xtr" represents the user-supplied/original Edge,
        # "xtr-roamed" represents the discovered Edge after a wireless roam.
        # Map their hostnames so a Border's CDP neighbor that resolves to an
        # Edge gets a border↔edge link drawn even if the Edge's own
        # UnderlayCdpDiscovery never traversed that border's port.
        edge_host_to_id = {}
        cur_xtr_host = ctx.state.get("xtr_hostname")
        orig_xtr_host = ctx.state.get("original_xtr_hostname")
        if orig_xtr_host:
            # Roam case: original anchor is "xtr", roamed Edge is "xtr-roamed".
            edge_host_to_id[_norm_hostname(orig_xtr_host)] = "xtr"
            if cur_xtr_host:
                edge_host_to_id[_norm_hostname(cur_xtr_host)] = "xtr-roamed"
        elif cur_xtr_host:
            edge_host_to_id[_norm_hostname(cur_xtr_host)] = "xtr"
        edge_host_to_id.pop("", None)

        if len(info_by_idx) < 2 and not edge_host_to_id:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — fewer than two reachable borders; no peering to map.",
            )

        from radkit_cli import get_single_output_genie
        edges = []
        seen_pairs = set()
        bullet_lines = []

        for idx, info in info_by_idx.items():
            src_hostname = info["radkit_name"]
            label_name = info["match_name"] or src_hostname
            if not src_hostname:
                continue
            try:
                cdp = get_single_output_genie(
                    src_hostname, "show cdp neighbors detail", service
                )
            except BaseException as e:
                # radkit_cli sys.exit()s on KeyError when the hostname isn't
                # in service.inventory. Catch BaseException so one missing
                # inventory entry doesn't kill the whole interconnect check.
                bullet_lines.append(
                    f"• {label_name}: CDP query failed ({type(e).__name__}: {e})"
                )
                continue
            if not cdp or "index" not in cdp:
                bullet_lines.append(f"• {label_name}: no CDP neighbors parsed")
                continue
            for nidx, entry in (cdp.get("index") or {}).items():
                neighbor = entry.get("device_id") or ""
                norm_neighbor = _norm_hostname(neighbor)
                if not norm_neighbor:
                    continue
                local = entry.get("local_interface") or ""
                remote = entry.get("port_id") or ""
                # Border ↔ Border match
                peer_idx = hostname_to_idx.get(norm_neighbor)
                if peer_idx is not None and peer_idx != idx:
                    pair_key = ("b", tuple(sorted([idx, peer_idx])))
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    peer_info = info_by_idx[peer_idx]
                    edges.append({
                        "source": info["border_id"],
                        "target": peer_info["border_id"],
                        "label": f"{local} ↔ {remote}" if (local or remote) else "CDP",
                        "id_prefix": "border-cdp",
                    })
                    bullet_lines.append(
                        f"• {label_name} {local} ↔ {peer_info['match_name'] or peer_info['radkit_name']} {remote}"
                    )
                    continue
                # Border ↔ Edge match (covers wireless-roam edge-2 case where
                # the border's CDP neighbor is an Edge node whose own underlay
                # discovery didn't traverse this port).
                edge_id = edge_host_to_id.get(norm_neighbor)
                if edge_id:
                    pair_key = ("e", info["border_id"], edge_id)
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)
                    edges.append({
                        "source": info["border_id"],
                        "target": edge_id,
                        "label": f"{local} ↔ {remote}" if (local or remote) else "CDP",
                        "id_prefix": "border-cdp",
                    })
                    bullet_lines.append(
                        f"• {label_name} {local} ↔ {neighbor} {remote}"
                    )

        if not edges:
            body = (
                "No CDP adjacencies between borders detected "
                f"({len(info_by_idx)} borders queried)."
            )
            return CheckResult(CheckStatus.OK, body)

        body = (
            f"{len(edges)} inter-border CDP link(s) found:\n"
            + "\n".join(bullet_lines)
        )
        return CheckResult(CheckStatus.OK, body, data={"add_edges": edges})

