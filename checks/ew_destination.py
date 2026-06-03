"""East-West Phase C: destination XTR resolution, profiling, map-cache, dest endpoint.

Mirrors the opening of forwardinglogic.l2_inter_xtr_ew (lines 256-296 +
host_onboarding_validation for the destination). Skipped on intra-XTR runs
unless the check still makes sense locally (dest endpoint onboarding does).
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.ew_shared import (
    _legacy_fail,
    _need,
    _skip_if_l3,
    _skip_if_intra,
    _build_src_xtr_shim,
    _endpoint_node_spec,
    _fmt_kv,
)


def _classify_l2vni_arp_mode(hostname, iid, service):
    """Inspect the L2VNI flooding config and return (mode, detail, broadcast_group, cfg).

    mode: "Unicast (LISP signal-based)", "Flooding (broadcast-underlay)", or "Unknown".
    detail: multi-line text with the relevant flags.
    broadcast_group: IP string from `broadcast-underlay <ip>`, or None.
    cfg: the L2LISPConfiguration object (for callers that want more state), or None.
    """
    try:
        from routingmodules.lisp import L2LISPConfiguration
        cfg = L2LISPConfiguration(iid, hostname)
        cfg.l2flooding_configuration(service)
    except BaseException as e:
        return ("Unknown", f"  (could not read L2VNI config on {hostname}: {e})", None, None)
    flood_arp = bool(getattr(cfg, "floodarpnd", False))
    bcast = getattr(cfg, "broadcastunderlay", None)
    if flood_arp:
        mode = "Flooding (broadcast-underlay)"
        diag = (
            "ARP is resolved via underlay flooding — 'flood arp-nd' is configured\n"
            "for this L2VNI.\n"
            "Queuing underlay-multicast validations on both Edge nodes."
        )
    else:
        mode = "Unicast (LISP signal-based)"
        diag = (
            "ARP resolution uses LISP signaling (unicast). The map-cache miss\n"
            "means ARP for the destination MAC has not yet resolved.\n"
            "Suggested next steps:\n"
            "  1. Re-run east-west with source and destination swapped (and the\n"
            "     destination XTR as the new source) to confirm the destination\n"
            "     endpoint is properly onboarded.\n"
            "  2. If onboarding looks fine, packet-capture on the source Edge to\n"
            "     confirm traffic toward the destination MAC is actually arriving."
        )
    return (mode, diag, bcast, cfg)


class EwDestXtrLookup(Check):
    """Resolve the destination XTR's management IP from its RLOC via Catalyst Center."""

    name = "Destination XTR lookup (CatC)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_dst_rloc")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        dstrloc = ctx.state["ew_dst_rloc"]
        try:
            from catalystcenterapi import catcapi
            dev = catcapi.get_device_from_lo0(dstrloc, srcxtr.dnac, ctx.service)
            if not dev:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"Catalyst Center returned no device for Loopback0 {dstrloc}.",
                )
            uuid = dev[0]["deviceUUID"]
            mgmtip = catcapi.get_network_device_byuuid(uuid, srcxtr.dnac, ctx.service)
        except BaseException as e:
            return _legacy_fail(e, "Destination XTR lookup")
        if not mgmtip:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not resolve management IP for destination RLOC {dstrloc}.",
            )
        ctx.state["ew_dst_xtr_mgmtip"] = mgmtip
        ctx.state["ew_dst_xtr_uuid"] = uuid
        return CheckResult(
            CheckStatus.OK,
            f"• Destination RLOC: {dstrloc}\n• Destination XTR mgmt IP: {mgmtip}",
        )


class EwDestXtrProfiling(Check):
    """Profile the destination XTR (Device.profile_device) and add dxtr node."""

    name = "Destination XTR profiling"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_dst_xtr_mgmtip")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        try:
            from device_profiler import Device
            dstxtr = Device(ctx.state["ew_dst_xtr_mgmtip"], srcxtr.dnac, 0)
            dstxtr.profile_device(ctx.service)
        except BaseException as e:
            return _legacy_fail(e, "Destination XTR profiling")
        ctx.state["ew_dstxtr"] = dstxtr
        ctx.state["ew_dstxtr_hostname"] = getattr(dstxtr, "hostname", None)

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
        body = _fmt_kv([
            ("Hostname", getattr(dstxtr, "hostname", None)),
            ("Mgmt IP", getattr(dstxtr, "mgmtip", None)),
            ("Loopback", getattr(dstxtr, "loopback", None)),
            ("Platform", getattr(dstxtr, "platform", None)),
            ("Software", getattr(dstxtr, "version", None)),
            ("Site", getattr(dstxtr, "fabric_site_hierarchy", None)),
            ("Is Fabric", getattr(dstxtr, "isfabric", None)),
            ("PubSub", getattr(dstxtr, "ispubsub", None)),
        ])
        return CheckResult(CheckStatus.OK, body, data={"add_nodes": [node]})


class EwFabricSiteComparison(Check):
    """Compare source and destination fabric-site hierarchies."""

    name = "Fabric-site comparison"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_dstxtr")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        dstxtr = ctx.state["ew_dstxtr"]
        srcsite = srcxtr.fabric_site_hierarchy
        dstsite = getattr(dstxtr, "fabric_site_hierarchy", None)
        src_fid = getattr(srcxtr, "fabric_id", None)
        dst_fid = getattr(dstxtr, "fabric_id", None)
        # Compare resolved fabric_ids — siteNameHierarchy alone misleads when
        # source and destination sit at different child sites (e.g. Floor 14
        # vs Floor 17) that roll up to the same fabric-enabled parent.
        if src_fid and dst_fid:
            same = src_fid == dst_fid
        else:
            same = srcsite == dstsite
        ctx.state["ew_is_intra_site"] = same
        body = (
            f"• Source site: {srcsite}\n"
            f"• Destination site: {dstsite}\n"
            f"• Source fabric-id: {src_fid}\n"
            f"• Destination fabric-id: {dst_fid}\n"
            f"• {'Same fabric site (intra-site L2 east-west).' if same else 'Different fabric sites (inter-site).'}"
        )
        return CheckResult(CheckStatus.OK if same else CheckStatus.WARN, body)


class EwRemoteMapCache(Check):
    """Validate the L2 LISP map-cache for the destination MAC on the source XTR."""

    name = "Remote L2 map-cache"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_l2lispsrc", "ew_dst_rloc", "ew_dst_mac")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        l2 = ctx.state["ew_l2lispsrc"]
        iid = getattr(l2, "l2lispiid", None)
        try:
            from traffic_flows.l2_lisp_interxtr import l2lisp_map_cache_validation
            mc = l2lisp_map_cache_validation(
                l2,
                ctx.state["ew_dst_rloc"],
                srcxtr.hostname,
                ctx.state["ew_dst_mac"],
                ctx.service, 0,
            )
        except BaseException as e:
            arp_mode, arp_detail, bcast_group, l2cfg = _classify_l2vni_arp_mode(
                srcxtr.hostname, iid, ctx.service
            )
            body = (
                f"L2 LISP map-cache lookup for {ctx.state.get('ew_dst_mac')} "
                f"on {srcxtr.hostname} returned no entry.\n"
                f"\n"
                f"• Destination MAC: {ctx.state.get('ew_dst_mac')}\n"
                f"• L2 VNI / IID:    {iid}\n"
                f"• Queried Edge:    {srcxtr.hostname}\n"
                f"• L2VNI ARP mode:  {arp_mode}\n"
                f"\n"
                f"{arp_detail}"
            )
            ctx.state["ew_l2mapcache"] = None
            ctx.state["ew_l2mapcache_miss"] = True
            ctx.state["ew_l2vni_arp_mode"] = arp_mode
            data = {}
            if arp_mode.startswith("Flooding"):
                src_ep = ctx.state.get("ew_sourceep")
                dst_ep = ctx.state.get("ew_destep")
                # Per-side VLAN: in SDA the L2VNI is global but the local VLAN
                # mapping can differ. Use src endpoint's VLAN for FHR and dst
                # endpoint's VLAN for LHR; fall back to the other side / payload.
                src_vlan = (
                    getattr(src_ep, "sourcevlan", None)
                    or ctx.payload.get("vlan_id")
                    or ctx.state.get("ew_src_vlan")
                    or getattr(dst_ep, "sourcevlan", None)
                    or ctx.payload.get("vlan")
                )
                dst_vlan = (
                    getattr(dst_ep, "sourcevlan", None)
                    or ctx.state.get("ew_dst_vlan")
                    or src_vlan
                )
                ctx.state["umcast_source_hostname"] = (
                    getattr(srcxtr, "mgmtip", None) or srcxtr.hostname
                )
                ctx.state["umcast_l2vni_iid"] = iid
                ctx.state["umcast_vlan"] = src_vlan
                ctx.state["umcast_broadcast_group"] = bcast_group
                ctx.state["umcast_vrf"] = None
                ctx.state["umcast_node_id"] = "xtr"
                ctx.state["umcast_catc_name"] = ctx.payload.get("catc_name")
                ctx.state["umcast_l2cfg"] = l2cfg
                # Reuse the FHR shim as profiled_device so we don't re-profile
                # via RSA (which fails when the hostname isn't in the inventory).
                ctx.state["umcast_existing_device"] = srcxtr
                try:
                    from checks.underlay_multicast import build_underlay_multicast_chain
                    queued = list(build_underlay_multicast_chain("fhr"))
                    # LHR side: only when we have a distinct destination XTR.
                    dstxtr = ctx.state.get("ew_dstxtr")
                    if dstxtr and not ctx.state.get("ew_is_intra_xtr"):
                        ctx.state["umcast_dst_hostname"] = (
                            getattr(dstxtr, "mgmtip", None)
                            or getattr(dstxtr, "hostname", None)
                        )
                        ctx.state["umcast_dst_l2vni_iid"] = iid
                        ctx.state["umcast_dst_vlan"] = dst_vlan
                        ctx.state["umcast_dst_broadcast_group"] = bcast_group
                        ctx.state["umcast_dst_vrf"] = None
                        ctx.state["umcast_dst_node_id"] = "dxtr"
                        ctx.state["umcast_dst_catc_name"] = ctx.payload.get("catc_name")
                        ctx.state["umcast_dst_existing_device"] = dstxtr
                        queued.extend(build_underlay_multicast_chain("lhr"))
                        try:
                            from checks.underlay_multicast_correlation import (
                                build_underlay_multicast_correlation_chain,
                            )
                            queued.extend(build_underlay_multicast_correlation_chain())
                        except Exception:
                            pass
                        try:
                            from checks.underlay_multicast_rp import (
                                build_underlay_multicast_rp_chain,
                            )
                            queued.extend(build_underlay_multicast_rp_chain())
                        except Exception:
                            pass
                        try:
                            from checks.underlay_multicast_sg import (
                                build_underlay_multicast_sg_chain,
                            )
                            queued.extend(build_underlay_multicast_sg_chain())
                        except Exception:
                            pass
                        try:
                            from checks.underlay_multicast_path import (
                                build_underlay_multicast_path_chain,
                            )
                            queued.extend(build_underlay_multicast_path_chain())
                        except Exception:
                            pass
                    data["queue_checks"] = queued
                except Exception:
                    pass
            return CheckResult(CheckStatus.WARN, body, data=data)
        ctx.state["ew_l2mapcache"] = mc
        body = _fmt_kv([
            ("EID (MAC)", getattr(mc, "eid", None)),
            ("L2 VNI / IID", getattr(mc, "iid", None)),
            ("Remote RLOC", getattr(mc, "rloc", None)),
            ("RLOC state", getattr(mc, "rlocstate", None)),
            ("Priority", getattr(mc, "priority", None)),
            ("Weight", getattr(mc, "weight", None)),
            ("Queried device", getattr(mc, "queriedev", None)),
        ])
        return CheckResult(CheckStatus.OK, body)


class EwDestEndpointOnboarding(Check):
    """Profile the destination endpoint on the destination (or source on intra) XTR."""

    name = "Destination endpoint onboarding"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        destip = ctx.payload.get("destination_ip")
        if not destip:
            return CheckResult(CheckStatus.FAIL, "destination_ip missing.")
        # On intra-XTR, dstxtr == srcxtr.
        if ctx.state.get("ew_is_intra_xtr"):
            xtr = _build_src_xtr_shim(ctx)
            connect_to = "xtr"
        else:
            miss = _need(ctx, "ew_dstxtr")
            if miss:
                return miss
            xtr = ctx.state["ew_dstxtr"]
            connect_to = "dxtr"
        try:
            from hostonboarding import EndpointInfo
            dstep = EndpointInfo(destip)
            dstep.host_onboarding_validation(xtr, ctx.service, 0)
        except BaseException as e:
            return _legacy_fail(e, "Destination endpoint onboarding")
        ctx.state["ew_destep"] = dstep
        node = _endpoint_node_spec(
            "dst-endpoint", dstep, connect_to=connect_to, label_prefix="DST"
        )
        body = _fmt_kv([
            ("IP", getattr(dstep, "sourceip", None)),
            ("MAC", getattr(dstep, "sourcemac", None)),
            ("Port", getattr(dstep, "sourceport", None)),
            ("VLAN", getattr(dstep, "sourcevlan", None)),
            ("VRF", getattr(dstep, "sourcevrf", None)),
            ("SISF state", getattr(dstep, "ipdtstate", None)),
            ("On XTR", getattr(xtr, "hostname", None)),
        ])
        # Detect destination wireless via access-tunnel learning. If the dest
        # endpoint's port is an access-tunnel, queue the destination-side
        # wireless validation chain (WLC discovery + endpoint state + access-
        # tunnel + fabric-edge MAC + roaming). On intra-XTR runs we skip — the
        # source-side wireless chain (WirelessFabricEdgeMac etc.) already
        # covers the same MAC on the same Edge.
        result_data = {"add_nodes": [node]}
        from checks.ew_wireless import is_access_tunnel_port, build_ew_dest_wireless_chain
        if (
            not ctx.state.get("ew_is_intra_xtr")
            and is_access_tunnel_port(getattr(dstep, "sourceport", None))
        ):
            ctx.state["ew_dst_is_wireless"] = True
            result_data["queue_checks"] = build_ew_dest_wireless_chain()
            body += "\n\n→ Destination port is an access-tunnel — queuing dest-side fabric wireless validations."
        return CheckResult(CheckStatus.OK, body, data=result_data)


class EwDestSisf(Check):
    """Endpoint-centric SISF / device-tracking on the destination XTR.

    Mirrors EwSourceSisf (checks_ew_flow.py) — uses the EndpointInfo populated
    by EwDestEndpointOnboarding (which already pulled the SISF row for the
    destination endpoint IP). Inter-XTR only; on intra-XTR the source-side
    SISF check already covers the endpoint.
    """

    name = "SISF / Device-Tracking (destination endpoint)"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        dstxtr = ctx.state.get("ew_dstxtr")
        dstep = ctx.state.get("ew_destep")
        if not (dstxtr and dstep):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — destination XTR / endpoint not available.",
            )
        from checks.ew_flow import _render_endpoint_sisf
        return _render_endpoint_sisf(
            dstep, getattr(dstxtr, "hostname", None), ctx.service, side="destination"
        )


class EwDestAuthenticationSession(Check):
    """Authentication-session validation on the destination edge port.

    Mirrors AuthenticationSessionCheck (checks_profile.py) but runs against
    the destination XTR + the destination endpoint's learned port. Inter-XTR
    only — on intra-XTR the source-side AuthenticationSessionCheck already
    covers the same port.
    """

    name = "Authentication Session (destination)"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        if (skip := _skip_if_intra(ctx)): return skip
        miss = _need(ctx, "ew_dstxtr", "ew_destep")
        if miss:
            return miss
        dstxtr = ctx.state["ew_dstxtr"]
        dstep = ctx.state["ew_destep"]
        hostname = getattr(dstxtr, "hostname", None)
        port = getattr(dstep, "sourceport", None)
        if not (hostname and port):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — destination hostname or learned port unavailable.",
            )
        try:
            from securitymodules.authenticationsession import authen_session_for_interface
            auth_details = authen_session_for_interface(hostname, port, ctx.service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"authen_session_for_interface raised {type(e).__name__}: {e}",
            )
        ctx.state["ew_dst_authensessiondetails"] = auth_details
        from checks.profile import _format_authen_session
        body = _format_authen_session(auth_details, hostname, port)
        return CheckResult(CheckStatus.OK, body)
