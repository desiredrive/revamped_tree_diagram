"""DHCP-specific Check objects.

DHCP pool/parameters identification, snooping/relay/SVI validation,
client statistics, local policies (PACL/VACL/RACL), and final DHCP
server compatibility. The profile, LISP, underlay, and border checks
that used to live here have moved to checks_profile / checks_lisp /
checks_underlay / checks_border.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.shared import _legacy_fail, _build_edge_shim
from radkit_cli import get_catc_api, get_any_single_output, get_single_output_genie


class PoolIdentification(Check):
    """DHCP — identify the IP pool bound to the endpoint's VLAN.

    Mirrors dhcp_troubleshooting.py:1978-2020. Two CatC API calls:
      1. /sda/layer2VirtualNetworks?fabricId=…&vlanId=…  → vlanName
      2. /business/sda/virtualnetwork/ippool?siteNameHierarchy=…
         &virtualNetworkName=…&ipPoolName=…                → pool details

    L2-only pools FAIL the run because the downstream DHCP traffic-flow checks
    rely on an Anycast Gateway being present (CLI exit_program at line 2008).
    """

    name = "Pool Identification"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        fabric_id = ctx.state.get("fabric_id")
        site_hierarchy = ctx.state.get("fabric_site_hierarchy")
        vlan = ctx.payload.get("vlan")
        vrf = ctx.payload.get("vrf")
        is_infravn = ctx.state.get("is_infravn")

        if not (service and dnac and fabric_id and site_hierarchy and vlan):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — pool identification requires service / catc_name / "
                "fabric_id / fabric_site_hierarchy / vlan.",
            )

        l2vn_api = (
            f"/dna/intent/api/v1/sda/layer2VirtualNetworks"
            f"?fabricId={fabric_id}&vlanId={vlan}"
        )
        try:
            l2vn_raw = get_catc_api(dnac, l2vn_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"CatC layer2VirtualNetworks call failed: {type(e).__name__}: {e}",
            )

        l2vn_resp = (l2vn_raw or {}).get("response") or []
        if not l2vn_resp:
            return CheckResult(
                CheckStatus.FAIL,
                f"No layer2VirtualNetwork entry for VLAN {vlan} under fabric {fabric_id}. "
                f"Confirm the VLAN is provisioned in this fabric site.",
            )

        vlan_name = l2vn_resp[0].get("vlanName")
        if not vlan_name:
            return CheckResult(
                CheckStatus.FAIL,
                f"layer2VirtualNetworks response has no vlanName for VLAN {vlan}.",
            )

        vn_name = "INFRA_VN" if is_infravn else vrf
        pool_api = (
            f"/dna/intent/api/v1/business/sda/virtualnetwork/ippool"
            f"?siteNameHierarchy={site_hierarchy}"
            f"&virtualNetworkName={vn_name}"
            f"&ipPoolName={vlan_name}"
        )
        try:
            pool_data = get_catc_api(dnac, pool_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"CatC virtualnetwork/ippool call failed: {type(e).__name__}: {e}",
            )

        if not pool_data:
            return CheckResult(
                CheckStatus.FAIL,
                f"No pool details returned for VN '{vn_name}', pool '{vlan_name}'.",
            )

        # DNAC signals an invalid VN / pool with a dict that looks like:
        #   {"status": "failed", "description": "This Virtual Network does not exist..."}
        # Treat that as a hard FAIL so a typo in the VRF field stops the chain
        # right here instead of cascading into nonsense downstream checks.
        if isinstance(pool_data, dict) and str(pool_data.get("status", "")).lower() == "failed":
            desc = pool_data.get("description") or "Unknown reason."
            hint = ""
            if vn_name and vn_name.lower() != "default" and "default".startswith(vn_name.lower()[:3]):
                hint = f" Did you mean 'default'?"
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center rejected the VN/pool lookup for VN '{vn_name}', pool "
                f"'{vlan_name}': {desc}{hint}",
            )

        ctx.state["pool_info"] = pool_data
        ctx.state["pool_vlan_name"] = vlan_name

        if pool_data.get("isLayer2OnlyPool") is True:
            return CheckResult(
                CheckStatus.FAIL,
                "Pool is Layer-2 only — DHCP traffic-flow validation requires an "
                "Anycast Gateway. The rest of the chain cannot proceed against this pool.",
                data={"pool": vlan_name, "vn": vn_name, "isLayer2OnlyPool": True},
            )

        ippoolname = pool_data.get("vlanName", pool_data.get("ipPoolName", "Unknown"))
        pooltype = pool_data.get("poolType", pool_data.get("trafficType", "DATA"))
        vlan_id_api = pool_data.get("vlanId", "Unknown")

        return CheckResult(
            CheckStatus.OK,
            f"IP pool '{ippoolname}' (VN '{vn_name}', VLAN {vlan_id_api}) — type '{pooltype}', "
            f"Anycast Gateway.",
            data={
                "pool": ippoolname,
                "vn": vn_name,
                "vlan": vlan_id_api,
                "pool_type": pooltype,
            },
        )


class DhcpParameters(Check):
    """DHCP — collect global DHCP/snooping/relay/SVI parameters on the XTR.

    Collection only. Each sub-validation that dhcp_parameters_validation() runs
    in the CLI is now its own Check below, so the UI shows them one-by-one.
    """

    name = "DHCP Parameters"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        vlan = ctx.payload.get("vlan")
        port = ctx.state.get("xtr_port")

        if not (service and hostname and vlan and port):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname / vlan / xtr_port).",
            )

        try:
            from switchingmodules.dhcp import DHCPDevice
            info = DHCPDevice(hostname)
            info.service_dhcp(service)
            info.dhcpsnooping(service)
            info.dhcpsnoopingacl(service)
            info.dhcpsnoopingstats(service)
            info.dhcpsnoopingbindings(vlan, service)
            info.dhcprelayconfiguration(service)
            info.svi_configuration(vlan, service)
            info.svi_running_config(vlan, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"DHCP parameter collection failed on {hostname}: {type(e).__name__}: {e}",
            )

        ctx.state["dhcpparameters_info"] = info
        return CheckResult(
            CheckStatus.OK,
            f"Collected DHCP service / snooping / relay / SVI parameters on {hostname} "
            f"for VLAN {vlan} / interface {port}.",
        )


class _DhcpGroup(Check):
    """Base for the 3 DHCP grouped validation Checks.

    Each subclass implements `rules(info, vlan, port)` returning a list of
    (label, ok_bool, message) tuples. The group as a whole FAILs on the first
    rule with ok=False (message becomes the headline); on full pass the message
    is a compact "<n>/<n> rules passed" with per-rule lines in the body for the
    UI panel.
    """

    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("dhcpparameters_info")
        vlan = ctx.payload.get("vlan")
        port = ctx.state.get("xtr_port")
        if not info or not vlan or not port:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — dhcpparameters_info / vlan / xtr_port not available.",
            )
        try:
            rules = self.rules(info, vlan, port)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"{self.name} raised {type(e).__name__}: {e}",
            )

        lines = []
        first_fail = None
        for label, ok, msg in rules:
            mark = "✓" if ok else "✗"
            lines.append(f"{mark} {label}: {msg}")
            if not ok and first_fail is None:
                first_fail = (label, msg)

        body = "\n".join(lines)
        if first_fail is not None:
            return CheckResult(
                CheckStatus.FAIL,
                f"{first_fail[0]} — {first_fail[1]}\n\n{body}",
            )
        return CheckResult(
            CheckStatus.OK,
            f"{len(rules)}/{len(rules)} rules passed\n\n{body}",
        )

    def rules(self, info, vlan, port):
        raise NotImplementedError


class DhcpSnoopingValidation(_DhcpGroup):
    """Group: service dhcp + DHCP snooping global/VLAN/operational/option82/trust/ACL/stats."""

    name = "DHCP Service and DHCP Snooping"

    def rules(self, info, vlan, port):
        from traffic_flows.dhcp_troubleshooting import expand_port
        dev = info.device
        results = []

        results.append((
            "Service DHCP",
            info.servicedhcp is not False,
            f"enabled on '{dev}'" if info.servicedhcp is not False
            else f"disabled on '{dev}' — configure \"service dhcp\".",
        ))
        results.append((
            "Snooping Global",
            info.dhcpsnoop_global_enabled is not False,
            f"globally enabled on '{dev}'" if info.dhcpsnoop_global_enabled is not False
            else f"globally disabled on '{dev}' — configure \"ip dhcp snooping\".",
        ))
        in_cfg = int(vlan) in (info.dhcpsnoop_configured_vlans or [])
        results.append((
            "Snooping on VLAN",
            in_cfg,
            f"enabled for VLAN {vlan} on '{dev}'" if in_cfg
            else f"disabled for VLAN {vlan} — configure \"ip dhcp snooping vlan {vlan}\".",
        ))
        in_op = int(vlan) in (info.dhcpsnoop_operational_vlans or [])
        results.append((
            "Snooping Operational",
            in_op,
            f"operational for VLAN {vlan} on '{dev}'" if in_op
            else f"configured but not operational for VLAN {vlan} on '{dev}' — "
                 f"VLAN may be unconfigured/shut or have no STP-forwarding ports.",
        ))
        proxy_on = int(vlan) in (info.dhcpsnoop_operational_vlans_proxy or [])
        results.append((
            "Snooping Proxy-Bridge",
            True,
            f"enabled for VLAN {vlan} on '{dev}'" if proxy_on
            else f"disabled for VLAN {vlan} on '{dev}' (typical — required only for Bridge-Mode VMs / multi-IP).",
        ))
        results.append((
            "Option 82 Insertion",
            info.option82_insertion is not False,
            f"enabled on '{dev}'" if info.option82_insertion is not False
            else f"disabled on '{dev}' — configure \"ip dhcp snooping information option\".",
        ))
        expanded = expand_port(port)
        trusted = (info.trust_interfaces or [])
        results.append((
            "Interface Trust",
            expanded not in trusted,
            f"{port} is not snooping-trusted on '{dev}' (expected)" if expanded not in trusted
            else f"{port} is snooping-trusted on '{dev}' — may block Option 82 insertion. "
                 f"Remove with \"no ip dhcp snooping trust\".",
        ))
        results.append((
            "Snooping ACL",
            True,
            f"none configured on '{dev}'" if info.dhcpsnoopacl is None
            else f"ACL '{info.dhcpsnoopacl}' present on '{dev}' — review the MAC ACL manually "
                 f"(no automated validation).",
        ))
        stats = getattr(info, "packets_dropped_because", None) or {}
        offenders = {r: c for r, c in stats.items() if c and c > 0}
        if offenders:
            details = ", ".join(f"{r}={c}" for r, c in offenders.items())
            results.append((
                "Snooping Drops",
                True,
                f"non-zero counters on '{dev}': {details}. Counters are historic — confirm via "
                f"'show ip dhcp snooping statistic details' that they aren't actively incrementing.",
            ))
        else:
            results.append(("Snooping Drops", True, f"all counters zero on '{dev}'."))

        return results


class DhcpRelayValidation(_DhcpGroup):
    """Group: global DHCP relay information option / vpn / trust-all."""

    name = "DHCP Relay"

    def rules(self, info, vlan, port):
        dev = info.device
        results = []
        results.append((
            "Relay Information Option",
            info.dhcprelayinformationoption is True,
            f"configured on '{dev}'" if info.dhcprelayinformationoption is True
            else f"not configured on '{dev}' — may prevent Option 82 preservation. "
                 f"Configure \"ip dhcp relay information option\".",
        ))
        results.append((
            "Relay Information Option VPN",
            info.dhcprelayinformationoptionvpn is not True,
            f"not set on '{dev}' (expected)" if info.dhcprelayinformationoptionvpn is not True
            else f"set on '{dev}' — conflicts with LISP-based Option 82. "
                 f"Remove \"ip dhcp relay information option vpn\".",
        ))
        results.append((
            "Relay Trust-All",
            info.dhcprelayinformationtrustall is not True,
            f"not set on '{dev}' (expected)" if info.dhcprelayinformationtrustall is not True
            else f"set on '{dev}' — prevents Option 82 insertion on any interface. "
                 f"Remove \"ip dhcp relay information option trust-all\".",
        ))
        return results


class SviValidation(_DhcpGroup):
    """Group: SVI operational / primary IP / CEF / helper / helper-VRF / source-interface / same-subnet."""

    name = "Switch Virtual Interface (SVI)"

    def rules(self, info, vlan, port):
        from ipaddress import ip_network, ip_address
        dev = info.device
        results = []

        oper_ok = (info.svienabled is not False) and (info.svioperational == 'up')
        results.append((
            "SVI Operational",
            oper_ok,
            f"VLAN {vlan} SVI up on '{dev}'" if oper_ok
            else f"VLAN {vlan} SVI not operationally enabled on '{dev}' — may be admin-shut "
                 f"or have no STP-forwarding ports.",
        ))
        results.append((
            "SVI Primary IP",
            info.prefix is not None,
            f"{info.prefix}/{info.mask} on '{dev}'" if info.prefix is not None
            else f"no primary IP on VLAN {vlan} SVI of '{dev}'.",
        ))
        results.append((
            "SVI CEF",
            info.cef_state is True,
            f"enabled on '{dev}'" if info.cef_state is True
            else f"disabled on VLAN {vlan} SVI of '{dev}' — configure \"ip route-cache same-interface\".",
        ))
        has_helpers = bool(info.helper_address) and len(info.helper_address) > 0
        results.append((
            "Helper-Address Present",
            has_helpers,
            f"{info.helper_address} on '{dev}'" if has_helpers
            else f"no helper-address on VLAN {vlan} SVI — required for Anycast Gateway DHCP.",
        ))
        svivrf = info.svivrf
        bad = [h for h in (info.helper_addresses or []) if h.get('vrf') != svivrf]
        results.append((
            "Helper-Address VRF",
            not bad,
            f"all helpers in SVI VRF '{svivrf}'" if not bad
            else f"helper {bad[0]['dhcpserverip']} in VRF '{bad[0]['vrf']}' instead of "
                 f"SVI VRF '{svivrf}' on '{dev}'.",
        ))
        si_ok = True
        si_msg = "no conflicting source-interface/vpn-id config."
        expected_vlan = "Vlan" + str(vlan)
        for cmd in (info.ip_dhcp_commands or []):
            if "vpn-id" in cmd:
                si_ok = False
                si_msg = (f"VPN-ID option set on VLAN {vlan} SVI — conflicts with LISP-based "
                          f"Option 82. Remove \"ip dhcp relay information option vpn-id\".")
                break
            if "source-interface" in cmd and expected_vlan not in cmd:
                si_ok = False
                si_msg = (f"non-standard relay source-interface ({cmd!r}). Not supported in "
                          f"SD-Access fabrics. Remove \"ip dhcp relay source-interface\".")
                break
        results.append(("SVI Relay Source/VPN-ID", si_ok, si_msg))

        same_subnet_ok = True
        same_subnet_msg = "no helper-address overlaps the SVI subnet."
        if info.prefix and info.mask and info.helper_addresses:
            try:
                svi_net = ip_network(f"{info.prefix}/{info.mask}", strict=False)
                for helper in info.helper_addresses:
                    ip = helper.get('dhcpserverip')
                    if ip and ip_address(ip) in svi_net:
                        same_subnet_ok = False
                        same_subnet_msg = (f"helper '{ip}' is in the same subnet as the SVI ({svi_net}) "
                                           f"on '{dev}'. Same-subnet DHCP servers are not supported in "
                                           f"SD-Access; they must sit inside the fabric under an L2-Only Pool.")
                        break
            except ValueError as e:
                same_subnet_ok = False
                same_subnet_msg = f"could not parse SVI subnet on '{dev}': {e}"
        results.append(("SVI Same-Subnet Helper", same_subnet_ok, same_subnet_msg))

        return results



class SviInterfaceCounters(Check):
    """DHCP — inspect input-queue drops and error counters on the Edge SVI.

    The SVI is the anycast gateway interface that receives the client's DHCP
    Discover before relay. Non-zero input-queue drops or interface errors
    indicate punt-path congestion or a bad cable/optics that will silently
    swallow DHCP packets even when relay/snooping configuration is perfect.
    """

    name = "SVI Interface Counters"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        info = ctx.state.get("dhcpparameters_info")
        svi = getattr(info, "svi", None) if info else None
        if not (service and hostname and svi):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires service / xtr_hostname / SVI name.",
            )
        try:
            from switchingmodules.interfaces import Interfaces
            intf = Interfaces(svi, hostname)
            intf.show_interface(service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Failed to collect counters for {svi} on {hostname}: {type(e).__name__}: {e}",
            )

        iqdrops = int(getattr(intf, "iiqdrops", 0) or 0)
        outputdrops = int(getattr(intf, "outputdrops", 0) or 0)
        crc = int(getattr(intf, "crcerrors", 0) or 0)
        giants = int(getattr(intf, "giants", 0) or 0)
        runts = int(getattr(intf, "runts", 0) or 0)

        body = (
            f"• Interface: {svi} on {hostname}\n"
            f"    – Input Queue Drops: {iqdrops}\n"
            f"    – Output Drops: {outputdrops}\n"
            f"    – CRC Errors: {crc}\n"
            f"    – Giants: {giants}\n"
            f"    – Runts: {runts}"
        )

        problems = []
        if iqdrops > 0:
            problems.append(f"input queue drops={iqdrops}")
        if outputdrops > 0:
            problems.append(f"output drops={outputdrops}")
        if crc > 0:
            problems.append(f"CRC errors={crc}")
        if giants > 0:
            problems.append(f"giants={giants}")
        if runts > 0:
            problems.append(f"runts={runts}")

        if problems:
            return CheckResult(
                CheckStatus.WARN,
                f"Non-zero counters on {svi}: {', '.join(problems)}. "
                f"Input-queue drops on the anycast gateway SVI commonly cause "
                f"silent DHCP Discover loss before relay.\n\n{body}",
            )
        return CheckResult(
            CheckStatus.OK,
            f"All input queue, output drop and error counters on {svi} are zero.\n\n{body}",
        )


class DhcpSnoopingClientStats(Check):
    """DHCP — collect per-client DHCP snooping stats and infer DORA state.

    Mirrors dhcp_troubleshooting.edge_node.dhcpsnoopingclientstats() (line 110-117).
    Returns the DORA state, which downstream `validate_dhcp_server_compatibility`
    consumes to flag mid-handshake stalls.
    """

    name = "DHCP Snooping Clients Statistics"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        mac = ctx.payload.get("mac")
        dhcp_info = ctx.state.get("dhcpparameters_info")
        if not (service and hostname and mac and dhcp_info):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires service / xtr_hostname / mac / dhcpparameters_info.",
            )
        anycastgw = getattr(dhcp_info, "prefix", None)
        helpers = getattr(dhcp_info, "helper_address", None) or []

        try:
            from switchingmodules.dhcp import DHCPDevice
            stats = DHCPDevice(hostname)
            _, dora_state = stats.dhcpsnoopclientstat(mac, anycastgw, helpers, service, 0)
        except BaseException as e:
            return _legacy_fail(e, "dhcpsnoopclientstat")

        ctx.state["dora_state"] = dora_state
        return CheckResult(
            CheckStatus.OK,
            f"DORA state inferred from DHCP snooping client stats: {dora_state}.",
            data={"dora_state": str(dora_state)},
        )


class LocalPolicies(Check):
    """DHCP — RACL / VACL / PACL evaluation in the DHCP path.

    Mirrors dhcp_troubleshooting.edge_node.raclvaclpacl() (line 120-124) +
    the acl_hit_procedure loop at line 2056-2057.
    """

    name = "Local Policies (Port ACL, VLAN ACL, Route ACL)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        vlan = ctx.payload.get("vlan")
        port = ctx.state.get("xtr_port")
        dhcp_info = ctx.state.get("dhcpparameters_info")

        if not (service and hostname and vlan and port and dhcp_info):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires dhcpparameters_info / xtr_port / vlan.",
            )

        try:
            from traffic_flows.dhcp_troubleshooting import local_policies, acl_hit_procedure
            acls, vacls = local_policies(dhcp_info, hostname, vlan, port, service, 0)
        except BaseException as e:
            return _legacy_fail(e, "local_policies")

        shim = _build_edge_shim(ctx)
        try:
            for acl in (acls or []):
                acl_hit_procedure(shim, acl, service, 0)
        except BaseException as e:
            return _legacy_fail(e, "acl_hit_procedure")

        ctx.state["edgeacls"] = acls or []
        ctx.state["edgevacls"] = vacls or []

        # Split RACLs from PACLs for display. local_policies() commingles them:
        # inbound/outbound from dhcpparameters_info are RACLs; the rest came from
        # AccessList.aclbyinterface() on the physical/port-channel port (PACLs).
        racl_candidates = [
            getattr(dhcp_info, "inboundacl", None),
            getattr(dhcp_info, "outboundacl", None),
        ]
        racls = [a for a in racl_candidates if a]
        pacls = [a for a in (acls or []) if a not in racls]

        def _fmt(items):
            return ", ".join(items) if items else "none"

        body = (
            f"• Port ACL: {_fmt(pacls)}\n"
            f"• VLAN ACL: {_fmt(vacls or [])}\n"
            f"• Route ACL: {_fmt(racls)}"
        )
        return CheckResult(
            CheckStatus.OK,
            body,
            data={
                "pacl_count": len(pacls),
                "vacl_count": len(vacls or []),
                "racl_count": len(racls),
            },
        )



class DhcpServerCompatibility(Check):
    """Fabric-wide — DHCP server Option-82 compatibility check using DORA state."""

    name = "DHCP server compatibility (Option 82 / DORA)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        border_objects = ctx.state.get("border_objects")
        dora_state = ctx.state.get("dora_state")
        if not (service and border_objects):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires border_objects from BorderProfile.",
            )
        try:
            from traffic_flows.dhcp_troubleshooting import validate_dhcp_server_compatibility
            validate_dhcp_server_compatibility(border_objects, dora_state, 0)
        except BaseException as e:
            return _legacy_fail(e, "DHCP server compatibility")
        reach = any(getattr(b, "ping_reachable", False) for b in border_objects)
        return CheckResult(
            CheckStatus.OK,
            f"DHCP server compatibility check complete. DORA state: {dora_state or 'unknown'}; "
            f"at least one border reachable: {reach}.",
        )

