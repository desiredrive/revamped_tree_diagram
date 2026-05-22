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
    is slower than border listing because each CP gets a CLI/RADKIT roundtrip,
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
        match_key = _norm(catc_hostname)
        if match_key:
            for u in (ctx.state.get("underlay_nodes") or []):
                if _norm(u.get("cdp_device_id")) == match_key:
                    merge_into = u.get("id")
                    break

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
        # RADKIT inventory name.
        display_name = catc_hostname or hostname
        # Tag preserved across the relabel so the Border role stays visible on
        # nodes that were merged with a CDP next-hop.
        tags = ["Border"]
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
        return CheckResult(
            CheckStatus.OK,
            body,
            data=result_data,
        )


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
        return CheckResult(CheckStatus.OK, "Validation passed.")


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

