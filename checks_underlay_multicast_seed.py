"""Standalone-scenario seed + destination-profile checks for the underlay
multicast scenario.

These two checks adapt the new ``underlay_multicast`` scenario form into the
``umcast_*`` / ``umcast_dst_*`` state contract that the FHR/LHR/Corr/SG chains
already consume. They run once at the start of the standalone scenario after
the common source-XTR profiling checks; the existing chains then run unchanged.
"""

from checks import Check, CheckResult, CheckStatus, RunContext


class UmcastSeed(Check):
    """Seed ``umcast_*`` (and optionally ``umcast_dst_*``) state from payload.

    Reads (payload):
        umcast_source_ip   (required)  source/FHR XTR mgmt IP.
        umcast_l2vni_iid   (required)  L2VNI instance ID.
        umcast_vlan        (required)  VLAN ID associated with the L2VNI.
        umcast_dest_ip     (optional)  destination/LHR XTR mgmt IP.
        umcast_vrf         (optional)  underlay VRF (defaults to None=global).
        umcast_group       (optional)  broadcast-underlay group override.
    """

    name = "Underlay Mcast: seed scenario state"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        p = ctx.payload
        src_ip = (p.get("umcast_source_ip") or "").strip()
        iid    = p.get("umcast_l2vni_iid")
        vlan   = p.get("umcast_vlan")
        dst_ip = (p.get("umcast_dest_ip") or "").strip() or None
        vrf    = p.get("umcast_vrf") or None
        group  = (p.get("umcast_group") or "").strip() or None
        catc   = ctx.state.get("catc_name") or p.get("catc_name")

        missing = []
        if not src_ip: missing.append("umcast_source_ip")
        if not iid:    missing.append("umcast_l2vni_iid")
        if not vlan:   missing.append("umcast_vlan")
        if missing:
            return CheckResult(
                CheckStatus.FAIL,
                "Missing required form fields: " + ", ".join(missing),
            )

        # FHR side: UmcastDeviceProfile uses this key as mgmt IP (legacy naming).
        ctx.state["umcast_source_hostname"] = src_ip
        ctx.state["umcast_l2vni_iid"]       = iid
        ctx.state["umcast_vlan"]            = vlan
        ctx.state["umcast_vrf"]             = vrf
        ctx.state["umcast_node_id"]         = "xtr"
        ctx.state["umcast_catc_name"]       = catc
        if group:
            ctx.state["umcast_broadcast_group"] = group

        # LHR side: only seeded when destination supplied.
        if dst_ip:
            ctx.state["umcast_dst_hostname"] = dst_ip
            ctx.state["umcast_dst_l2vni_iid"] = iid
            ctx.state["umcast_dst_vlan"]      = vlan
            ctx.state["umcast_dst_vrf"]       = vrf
            ctx.state["umcast_dst_node_id"]   = "dxtr"
            ctx.state["umcast_dst_catc_name"] = catc
            if group:
                ctx.state["umcast_dst_broadcast_group"] = group

        body_lines = [
            f"• Source XTR (FHR) mgmt IP: {src_ip}",
            f"• L2VNI IID: {iid}",
            f"• VLAN: {vlan}",
            f"• VRF: {vrf or '(global)'}",
            f"• CatC: {catc or '(none)'}",
            f"• Destination XTR (LHR) mgmt IP: {dst_ip or '(not provided — FHR-only)'}",
        ]
        if group:
            body_lines.append(f"• Broadcast group override: {group}")
        return CheckResult(CheckStatus.OK, "\n".join(body_lines))


class UmcastDstXtrProfile(Check):
    """Profile the destination XTR (when provided) and emit the dxtr node."""

    name = "Underlay Mcast: destination XTR profiling"
    target_node_id = "xtr"  # anchor on xtr; the dxtr node is added via add_nodes

    def run(self, ctx: RunContext) -> CheckResult:
        dst_ip = ctx.state.get("umcast_dst_hostname")
        if not dst_ip:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: no destination XTR provided (FHR-only run).",
            )
        catc = ctx.state.get("catc_name") or ctx.state.get("umcast_dst_catc_name")
        try:
            from device_profiler import Device
            dstxtr = Device(dst_ip, catc, 0)
            dstxtr.profile_device(ctx.service)
        except BaseException as e:
            msg = str(e) if str(e) else e.__class__.__name__
            return CheckResult(
                CheckStatus.FAIL,
                f"{self.name} raised {e.__class__.__name__}: {msg}",
            )
        # Hand the profiled Device to UmcastDeviceProfile (LHR) so it skips
        # re-profiling.
        ctx.state["umcast_dst_existing_device"] = dstxtr

        label_lines = [getattr(dstxtr, "hostname", "dxtr")]
        loopback = getattr(dstxtr, "loopback", None)
        if loopback:
            label_lines.append(loopback)
        platform = getattr(dstxtr, "platform", None)
        if platform:
            label_lines.append(platform)
        node = {
            "id": "dxtr",
            "role": "xtr",
            "label": "\n".join(label_lines),
            "ip": getattr(dstxtr, "mgmtip", None),
            "hostname": getattr(dstxtr, "hostname", None),
        }
        body = (
            f"• Hostname: {getattr(dstxtr, 'hostname', None)}\n"
            f"• Mgmt IP: {getattr(dstxtr, 'mgmtip', None)}\n"
            f"• Loopback: {loopback}\n"
            f"• Platform: {platform}\n"
            f"• Software: {getattr(dstxtr, 'version', None)}\n"
            f"• Site: {getattr(dstxtr, 'fabric_site_hierarchy', None)}\n"
            f"• Is Fabric: {getattr(dstxtr, 'isfabric', None)}"
        )
        return CheckResult(CheckStatus.OK, body, data={"add_nodes": [node]})
