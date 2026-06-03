"""Profile / role / topology-discovery checks.

These checks resolve the Catalyst Center name, profile the XTR network and
fabric device records, determine the XTR's fabric role, look up the fabric
site, and gather neighbor / authentication / SGT context. They run before
the LISP, underlay, and border checks and populate ctx.state with the
fields those later checks depend on.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.shared import _legacy_fail
from radkit_cli import get_catc_api, get_any_single_output, get_single_output_genie


def _format_authen_session(auth_details, hostname: str, port: str) -> str:
    """Render the rich per-session detail captured by authen_session_for_interface."""
    lines = [f"Authentication session validated on {hostname} {port}."]

    acro = getattr(auth_details, "acrosessions", None)
    if acro:
        lines.append("")
        lines.append("AcroSession (Access Tunnel — wireless AP-side):")
        for s in acro:
            vlan = s.get("vlan")
            mac = s.get("mac_address")
            sid = s.get("session_id")
            authd = "YES" if s.get("authorized") else "NO"
            lines.append(f"  • VLAN {vlan}  MAC {mac}  Authorized: {authd}  Session-ID: {sid}")
        return "\n".join(lines)

    intf_data = getattr(auth_details, "authsessionintf", None) or {}
    interfaces = intf_data.get("interfaces") or {}
    if interfaces:
        lines.append("")
        for intf, blob in interfaces.items():
            for mac, e in (blob.get("mac_address") or {}).items():
                lines.append(f"Session: {mac} on {intf}")
                status = e.get("status")
                authorized = "YES" if (status or "").lower().startswith("auth") else (
                    "NO" if status else "?"
                )
                lines.append(f"  • Authorized:    {authorized}  ({status or 'unknown'})")
                user = e.get("user_name")
                lines.append(f"  • Username:      {user if user and user != 'Unknown' else '(none)'}")
                lines.append(f"  • Domain:        {e.get('domain') or '(none)'}")
                iifid = (
                    e.get("iif_id")
                    or e.get("iifid")
                    or e.get("iif-id")
                    or e.get("client_iif_id")
                )
                if iifid:
                    lines.append(f"  • Client IIF-ID: {iifid}")
                methods = e.get("method_status") or {}
                if methods:
                    parts = [f"{m}={ms.get('state')}" for m, ms in methods.items()]
                    lines.append(f"  • Method:        {', '.join(parts)}")
                else:
                    lines.append("  • Method:        (none)")
                # Session / re-auth timeouts surface as either timeout fields or
                # under session_timeout. Genie key spelling varies by IOS-XE
                # release; check several before falling through.
                stimeout = (
                    e.get("session_timeout")
                    or e.get("timeout")
                    or e.get("server_timeout")
                )
                if isinstance(stimeout, dict):
                    parts = []
                    for k in ("type", "timeout", "remaining"):
                        if stimeout.get(k):
                            parts.append(f"{k}={stimeout[k]}")
                    stimeout = ", ".join(parts) if parts else None
                lines.append(f"  • Session Timeout: {stimeout or '(not set)'}")
                server_policies = e.get("server_policies") or {}
                if server_policies:
                    lines.append("  • Server Policies:")
                    for _, sp in server_policies.items():
                        nm = sp.get("name") or "?"
                        pol = sp.get("policies") or sp.get("value") or ""
                        lines.append(f"      - {nm}: {pol}")
                else:
                    lines.append("  • Server Policies: (none)")
                ipv4 = e.get("ipv4_address")
                if ipv4 and ipv4 != "Unknown":
                    lines.append(f"  • IPv4:          {ipv4}")
                dt = e.get("device_type")
                if dt and dt != "Unknown":
                    lines.append(f"  • Device-Type:   {dt}")
                dn = e.get("device_name")
                if dn and dn != "Unknown":
                    lines.append(f"  • Device-Name:   {dn}")
                hm = e.get("oper_host_mode")
                if hm and hm != "Unknown":
                    lines.append(f"  • Host Mode:     {hm}")
                cd = e.get("oper_control_dir")
                if cd and cd != "Unknown":
                    lines.append(f"  • Control Dir:   {cd}")
                cp = e.get("current_policy")
                if cp and cp != "Unknown":
                    lines.append(f"  • Policy:        {cp}")
                local = e.get("local_policies") or {}
                vlan_grp = local.get("vlan_group", {}).get("vlan") if isinstance(local.get("vlan_group"), dict) else None
                if vlan_grp:
                    lines.append(f"  • Local VLAN:    {vlan_grp}")
                csid = e.get("common_session_id")
                if csid and csid != "Unknown":
                    lines.append(f"  • Common SID:    {csid}")

    dot1x = getattr(auth_details, "dot1xinterfaceparameter", None) or {}
    params = dot1x.get("parameters") or {}
    if params:
        lines.append("")
        lines.append("Dot1x interface parameters:")
        for k in ("PAE", "HostMode", "ControlDirection", "QuietPeriod", "ServerTimeout",
                  "SuppTimeout", "ReAuthMax", "MaxReq", "TxPeriod"):
            if k in params:
                lines.append(f"  • {k}: {params[k]}")
        for k, v in params.items():
            if k not in {"PAE", "HostMode", "ControlDirection", "QuietPeriod", "ServerTimeout",
                         "SuppTimeout", "ReAuthMax", "MaxReq", "TxPeriod"}:
                lines.append(f"  • {k}: {v}")

    if len(lines) == 1:
        # No parsed sessions / dot1x. Distinguish wireless tunnels (Ac0…) —
        # where per-client auth lives on the WLC, not the edge — from a real
        # "no session on this port" outcome on a wired access port.
        is_wireless_tunnel = (port or "").lower().startswith(("ac", "accesstunnel"))
        if is_wireless_tunnel:
            lines.append("")
            lines.append("Fabric-Enabled Wireless tunnel — no per-client session on the")
            lines.append("edge tunnel interface is expected. Per-client authentication is")
            lines.append("anchored on the WLC; refer to the WLC client validation results.")
            return "\n".join(lines)

        # Wired access port with no parsed session: surface only the meaningful
        # populated fields, formatted cleanly. Skip noisy structural fields
        # like templateinterface and raw genie blobs.
        SKIP_ATTRS = {
            "hostname", "templateinterface", "authsessionintf",
            "dot1xinterfaceparameter", "acrosessions",
        }
        raw_attrs = [
            a for a in dir(auth_details)
            if not a.startswith("_")
            and not callable(getattr(auth_details, a, None))
            and a not in SKIP_ATTRS
        ]
        populated = []
        for a in raw_attrs:
            v = getattr(auth_details, a, None)
            if v in (None, "", {}, []):
                continue
            populated.append((a, v))

        lines.append("")
        lines.append(f"No active authentication session on {port}.")
        if populated:
            lines.append("")
            lines.append("Additional attributes reported:")
            for a, v in populated:
                snippet = repr(v) if not isinstance(v, str) else v
                if len(snippet) > 200:
                    snippet = snippet[:200] + "…"
                lines.append(f"  • {a}: {snippet}")
    return "\n".join(lines)


class ResolveCatcName(Check):
    """Phase 1 / Check 5 — Resolve the Catalyst Center hostname.

    Mirrors the radkit_cli.get_catc_name() call that dhcp_troubleshooting
    performs before any Catalyst Center API request. The form lets the user
    override the auto-detected name (needed when RSA Standalone Server is
    in use); if they leave it blank, we fall back to scanning the RSA
    inventory for a device with device_type CENTER (or DNAC for older builds).
    """

    name = "Resolve Catalyst Center name"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.FAIL, "No RSA service in run context.")

        form_value = (ctx.payload.get("catc_name") or "").strip()
        if form_value:
            try:
                inv = service.inventory.filter("name", "^{}$".format(form_value))
                if not list(inv.keys()):
                    return CheckResult(
                        CheckStatus.FAIL,
                        f"Catalyst Center '{form_value}' is not in RSA inventory.",
                    )
            except Exception as e:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"RSA inventory lookup failed: {type(e).__name__}: {e}",
                )
            ctx.state["catc_name"] = form_value
            return CheckResult(
                CheckStatus.OK,
                f"Using Catalyst Center '{form_value}' (form-supplied).",
                data={"catc_name": form_value},
            )

        try:
            inv = service.inventory.filter("device_type", "CENTER")
            names = list(inv.keys())
            if not names:
                inv = service.inventory.filter("device_type", "DNAC")
                names = list(inv.keys())
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"RSA inventory lookup failed: {type(e).__name__}: {e}",
            )

        if not names:
            return CheckResult(
                CheckStatus.FAIL,
                "No Catalyst Center (device_type CENTER/DNAC) found in RSA inventory. "
                "Supply the Catalyst Center name in the form if RSA Standalone is in use.",
            )

        catc_name = names[0]
        ctx.state["catc_name"] = catc_name
        return CheckResult(
            CheckStatus.OK,
            f"Catalyst Center auto-detected: '{catc_name}'.",
            data={"catc_name": catc_name},
        )


class ProfileXtrNetworkDevice(Check):
    """Phase 1 / Check 6 — network-device API: softwareVersion, serial, uuid, platform, reachability.

    Mirrors device_profiler.profile_device():234-270, the first half of the
    CatC profile call. Extracts the fields downstream checks need (instanceUuid
    is required for every later /interface/network-device/{uuid} call). The
    original sys.exit()s on missing fields or empty response are converted to
    CheckResult(FAIL, ...) so the chain halts cleanly.
    """

    name = "Profile XTR (network-device API)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.SKIP, "RSA service missing in run context.")
        dnac = ctx.state.get("catc_name")
        mgmtip = ctx.state.get("xtr_mgmtip")
        if not dnac:
            return CheckResult(CheckStatus.SKIP, "Catalyst Center name not resolved by an earlier check.")
        if not mgmtip:
            return CheckResult(CheckStatus.SKIP, "XTR management IP not resolved by an earlier check.")

        api = f"/dna/intent/api/v1/network-device/ip-address/{mgmtip}"
        try:
            raw = get_catc_api(dnac, api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center API call failed: {type(e).__name__}: {e} (API: {api})",
            )
        if raw is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center returned no response for {api}.",
            )
        response = raw.get("response") if isinstance(raw, dict) else None
        if not response:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center could not find network device {mgmtip} (API: {api}).",
            )

        try:
            version = response["softwareVersion"]
            serial = response["serialNumber"]
            uuid = response["instanceUuid"]
            platform = response["platformId"]
            reach = response["reachabilityStatus"]
        except KeyError as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Network-device API response missing field {e} (API: {api}).",
            )

        ctx.state["xtr_catc_hostname"] = response.get("hostname")
        ctx.state["xtr_version"] = version
        ctx.state["xtr_serial"] = serial
        ctx.state["xtr_uuid"] = uuid
        ctx.state["xtr_platform"] = platform
        ctx.state["xtr_reachability"] = reach

        if reach == "Unreachable":
            return CheckResult(
                CheckStatus.WARN,
                f"{platform} (IOS-XE {version}, serial {serial}) is marked Unreachable by Catalyst Center. "
                f"Downstream RLOC/LISP checks will be skipped.",
                data={
                    "platform": platform,
                    "version": version,
                    "serial": serial,
                    "uuid": uuid,
                    "reachability": reach,
                },
            )

        return CheckResult(
            CheckStatus.OK,
            (
                f"• Platform: {platform}\n"
                f"• IOS-XE: {version}\n"
                f"• Serial: {serial}\n"
                f"• Reachability: {reach}"
            ),
            data={
                "platform": platform,
                "version": version,
                "serial": serial,
                "uuid": uuid,
                "reachability": reach,
            },
        )


class ProfileXtrFabricDevice(Check):
    """Phase 1 / Check 7 — fabric-device API: roles + siteNameHierarchy.

    Mirrors device_profiler.profile_device():248-292. When the device is not a
    fabric member (status == 'failed' or no siteNameHierarchy), falls back to
    the device-detail API to recover the location string so later checks know
    the site even for Intermediate/Fusion routers.
    """

    name = "Profile XTR (fabric-device API)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        mgmtip = ctx.state.get("xtr_mgmtip")
        uuid = ctx.state.get("xtr_uuid")
        if not (service and dnac and mgmtip and uuid):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — an earlier check did not populate the required state "
                "(service / catc_name / xtr_mgmtip / xtr_uuid).",
            )

        api = f"/dna/intent/api/v1/business/sda/device?deviceManagementIpAddress={mgmtip}"
        try:
            raw = get_catc_api(dnac, api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center API call failed: {type(e).__name__}: {e} (API: {api})",
            )
        if not isinstance(raw, dict):
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center returned no/unparseable response for {api}.",
            )

        site_hierarchy = None
        roles = []
        is_fabric = True

        if raw.get("status") == "failed" or "siteNameHierarchy" not in raw:
            is_fabric = False
            detail_api = f"/dna/intent/api/v1/device-detail?searchBy={uuid}&identifier=uuid"
            try:
                detail_raw = get_catc_api(dnac, detail_api, service)
            except Exception as e:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"device-detail API failed: {type(e).__name__}: {e}",
                )
            detail = (detail_raw or {}).get("response") or {}
            site_hierarchy = detail.get("location")
            if not site_hierarchy:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"Device {mgmtip} is not a fabric device and device-detail returned no location.",
                )
        else:
            site_hierarchy = raw.get("siteNameHierarchy")
            roles = raw.get("roles") or []

        ctx.state["xtr_is_fabric"] = is_fabric
        ctx.state["xtr_roles"] = roles
        ctx.state["xtr_site_hierarchy"] = site_hierarchy

        if not is_fabric:
            return CheckResult(
                CheckStatus.WARN,
                f"Device {mgmtip} is not a fabric device (possibly Intermediate/Fusion). "
                f"Location: {site_hierarchy}. RLOC/LISP checks will be skipped.",
                data={"is_fabric": False, "site_hierarchy": site_hierarchy},
            )

        return CheckResult(
            CheckStatus.OK,
            (
                f"• Fabric roles: {', '.join(roles) if roles else '(none)'}\n"
                f"• Site: {site_hierarchy}"
            ),
            data={"is_fabric": True, "roles": roles, "site_hierarchy": site_hierarchy},
        )


class XtrRoleClassification(Check):
    """XTR role classification — sets edge / iborder / l2handoff state flags.

    Mirrors device_profiler.profile_device():353-365 + the LISP route-import
    branch at :341-350. Downstream DHCP checks (MAC learning, forwarding) gate
    on these flags so they must be in state before Group A runs.

    - edge:      'Edge Node' is in xtr_roles
    - iborder:   'Border Node' role AND at least one IID has route-import
                 configured (lisp_route_import.ridb_state)
    - l2handoff: layer2Handoffs count >= 1 on this device in this fabric
    """

    name = "XTR Role Classification"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        dnac = ctx.state.get("catc_name")
        hostname = ctx.state.get("xtr_hostname")
        uuid = ctx.state.get("xtr_uuid")
        fabric_id = ctx.state.get("fabric_id")
        roles = ctx.state.get("xtr_roles") or []
        is_fabric = ctx.state.get("xtr_is_fabric")

        if not is_fabric:
            ctx.state["edge"] = False
            ctx.state["iborder"] = False
            ctx.state["l2handoff"] = False
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — device is not a fabric member; no role flags to set.",
            )

        if not (service and dnac and hostname and uuid and fabric_id):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / catc_name / "
                "xtr_hostname / xtr_uuid / fabric_id).",
            )

        edge = any("Edge Node" in r for r in roles)

        iborder = False
        if any("Border Node" in r for r in roles):
            try:
                from routingmodules.lisp import lisp_route_import
                rdbstate = lisp_route_import("*", hostname).ridb_state(service)
            except Exception as e:
                return CheckResult(
                    CheckStatus.FAIL,
                    f"LISP route-import probe failed: {type(e).__name__}: {e}",
                )
            if rdbstate:
                iborder = any(
                    (entry or {}).get("configured") is True
                    for entry in rdbstate.values()
                )

        l2handoff_api = (
            f"/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs/count"
            f"?fabricId={fabric_id}&networkDeviceId={uuid}"
        )
        try:
            l2_raw = get_catc_api(dnac, l2handoff_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"layer2Handoffs/count API failed: {type(e).__name__}: {e}",
            )
        l2_response = (l2_raw or {}).get("response") if isinstance(l2_raw, dict) else None
        count = (l2_response or {}).get("count", 0) if isinstance(l2_response, dict) else 0
        l2handoff = count >= 1

        ctx.state["edge"] = edge
        ctx.state["iborder"] = iborder
        ctx.state["l2handoff"] = l2handoff

        labels = []
        if edge:      labels.append("edge")
        if iborder:   labels.append("iborder")
        if l2handoff: labels.append(f"l2handoff (count={count})")
        summary = ", ".join(labels) if labels else "no XTR roles matched"

        tags = []
        if edge:      tags.append("Edge")
        if iborder:   tags.append("iBorder")
        if l2handoff: tags.append("L2Handoff")

        return CheckResult(
            CheckStatus.OK,
            f"XTR classification: {summary}.",
            data={
                "edge": edge,
                "iborder": iborder,
                "l2handoff": l2handoff,
                "l2handoff_count": count,
                "node_tags": tags,
            },
        )


class FabricSiteLookup(Check):
    """Phase 1 / Check 8 — fabricSites API: pubsub flag + fabric_id + site_id + site_hierarchy.

    Mirrors device_profiler.fabric_sites():147-187. Uses the v1 site API and
    cross-references against fabricSites to find the entry whose siteId is in
    the device's site hierarchy. Skips cleanly when the device is not fabric.
    """

    name = "Fabric Site Lookup"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.state.get("xtr_is_fabric", False):
            return CheckResult(
                CheckStatus.SKIP,
                "Device is not a fabric member; fabric site lookup not applicable.",
            )

        service = ctx.service
        dnac = ctx.state.get("catc_name")
        site_hierarchy = ctx.state.get("xtr_site_hierarchy")
        if not (service and dnac and site_hierarchy):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — an earlier check did not populate the required state "
                "(service / catc_name / xtr_site_hierarchy).",
            )

        site_api = f"/dna/intent/api/v1/site?name={site_hierarchy}"
        fabricsite_api = "/dna/intent/api/v1/sda/fabricSites"
        try:
            site_raw = get_catc_api(dnac, site_api, service)
            fabric_raw = get_catc_api(dnac, fabricsite_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center API call failed: {type(e).__name__}: {e}",
            )
        if not isinstance(site_raw, dict) or not isinstance(fabric_raw, dict):
            return CheckResult(CheckStatus.FAIL, "Catalyst Center returned unparseable response for site lookup.")
        site_response = site_raw.get("response") or []
        fabric_response = fabric_raw.get("response") or []
        if not isinstance(site_response, list) or not site_response:
            return CheckResult(
                CheckStatus.FAIL,
                f"Site '{site_hierarchy}' not found in Catalyst Center (API: {site_api}).",
            )
        first_site = site_response[0] if isinstance(site_response[0], dict) else {}
        group_hierarchy = first_site.get("siteHierarchy", "")

        fabric_id = site_id = None
        is_pubsub = False
        for entry in fabric_response:
            if not isinstance(entry, dict):
                continue
            if entry.get("siteId") and entry["siteId"] in group_hierarchy:
                is_pubsub = entry.get("isPubSubEnabled", False)
                fabric_id = entry.get("id")
                site_id = entry.get("siteId")
                break

        if fabric_id is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"No fabricSites entry matches site hierarchy '{site_hierarchy}'. "
                f"Review the latest API retrieved in Catalyst Center in the GPS_SDA Collection ({fabricsite_api}).",
            )

        final_api = f"/dna/intent/api/v1/site?siteId={site_id}"
        try:
            final_raw = get_catc_api(dnac, final_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Catalyst Center API call failed: {type(e).__name__}: {e} (API: {final_api})",
            )
        final_resp = (final_raw or {}).get("response") or {}
        final_hierarchy = final_resp.get("siteNameHierarchy", site_hierarchy)

        ctx.state["is_pubsub"] = is_pubsub
        ctx.state["fabric_id"] = fabric_id
        ctx.state["fabric_site_id"] = site_id
        ctx.state["fabric_site_hierarchy"] = final_hierarchy

        return CheckResult(
            CheckStatus.OK,
            (
                f"• Fabric site: {final_hierarchy}\n"
                f"• Pubsub: {is_pubsub}\n"
                f"• Fabric ID: {fabric_id}"
            ),
            data={
                "is_pubsub": is_pubsub,
                "fabric_id": fabric_id,
                "fabric_site_id": site_id,
                "fabric_site_hierarchy": final_hierarchy,
            },
        )



class FewRedirectReal(Check):
    """Phase 1 / Check 13 — Real Fabric-Enabled Wireless redirect.

    Replaces the FewRedirect stub. When is_few=True, calls
    wirelessflows.wirelessclientonboarding() with the resolved fabric_site_id,
    catc_name, and endpoint MAC. The function returns the hostname of the XTR
    actually hosting the wireless endpoint's AP; we override
    ctx.state['xtr_hostname'] and relabel the topology node accordingly.

    NOTE: wirelessclientonboarding() runs many validations internally and uses
    sys.exit() on error — we catch BaseException (covers SystemExit) so the
    chain fails cleanly rather than killing the worker.
    """

    name = "Fabric Enabled Wireless"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return CheckResult(
                CheckStatus.SKIP,
                "Not Required — endpoint is not Fabric-Enabled Wireless.",
            )

        fabric_site_id = ctx.state.get("fabric_site_id")
        catc_name = ctx.state.get("catc_name")
        mac = ctx.payload.get("mac")
        service = ctx.service
        if not (fabric_site_id and catc_name and mac and service):
            return CheckResult(
                CheckStatus.SKIP,
                "Error — required state missing (fabric_site_id / catc_name / mac / service).",
            )

        try:
            from traffic_flows.wirelessflows import wirelessclientonboarding
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Error — could not import wirelessclientonboarding: {type(e).__name__}: {e}",
            )

        # Pre-flight: confirm at least one WLC is registered to this fabric.
        # wirelessclientonboarding() crashes with IndexError on empty inventory.
        wlc_api = (
            f"/dna/intent/api/v1/sda/fabricDevices?fabricId={fabric_site_id}"
            f"&deviceRoles=WIRELESS_CONTROLLER_NODE"
        )
        try:
            wlc_raw = get_catc_api(catc_name, wlc_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Error — WLC lookup failed: {type(e).__name__}: {e} (API: {wlc_api})",
            )
        wlc_response = (wlc_raw or {}).get("response") if isinstance(wlc_raw, dict) else None
        if not wlc_response:
            return CheckResult(
                CheckStatus.FAIL,
                f"Error — no Wireless LAN Controller is registered to fabric_id {fabric_site_id}. "
                f"Cannot identify the XTR hosting this wireless endpoint. "
                f"Add a WLC to the fabric site in Catalyst Center, or set "
                f"'Fabric Enabled Wireless' to OFF if the endpoint is wired.",
            )

        try:
            _step, new_xtr = wirelessclientonboarding(0, fabric_site_id, catc_name, mac, service)
        except BaseException as e:
            return _legacy_fail(e, "wirelessclientonboarding")

        if not new_xtr:
            return CheckResult(
                CheckStatus.FAIL,
                "Error — wirelessclientonboarding returned no XTR hostname.",
            )

        prior = ctx.state.get("xtr_hostname")
        ctx.state["xtr_hostname"] = new_xtr
        return CheckResult(
            CheckStatus.OK,
            f"Required — real XTR for wireless endpoint: {new_xtr} (was {prior}).",
            data={"hostname": new_xtr, "node_relabel": new_xtr},
        )


class MacLearning(Check):
    """DHCP — verify the endpoint MAC is learned on the XTR for the given VLAN.

    Mirrors dhcp_troubleshooting.edge_node.maclearning() +
    dhcp_mac_address_validation(). Runs only on fabric edges or L2 handoffs
    (CLI gate at dhcp_troubleshooting.py:1924-1927).

    Resolution outcomes (preserving CLI semantics):
      - port == None  -> FAIL (MAC not in table)
      - port == "Drop"-> FAIL (drop state)
      - port startswith "Ac" -> OK + flags fewendpoint=True (AccessTunnel; FEW
        features bypassed for the rest of the chain)
      - "Tu" or "L2L" in port -> FAIL (endpoint is remote, known via LISP)
      - otherwise -> OK with the learned port
    """

    name = "MAC Learning"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        mac = ctx.payload.get("mac")
        vlan = ctx.payload.get("vlan")

        if not (service and hostname and mac and vlan):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname / mac / vlan).",
            )

        is_fabric = ctx.state.get("xtr_is_fabric")
        edge = ctx.state.get("edge")
        l2handoff = ctx.state.get("l2handoff")
        if not (is_fabric and (edge or l2handoff)):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — MAC learning only runs on fabric Edge or L2-handoff devices.",
            )

        try:
            from switchingmodules.maclearning import mac_learning
            info = mac_learning(hostname)
            info.mac_learning_mac(mac, vlan, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"mac_learning_mac raised {type(e).__name__}: {e}",
            )

        port = getattr(info, "port", None)
        m_type = getattr(info, "type", None)
        fewendpoint = False

        if port is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"MAC {mac} not found in the mac-address-table for VLAN {vlan} on {hostname}.",
            )
        if port == "Drop":
            return CheckResult(
                CheckStatus.FAIL,
                f"MAC {mac} on VLAN {vlan} is in DROP state on {hostname}.",
            )
        if isinstance(port, str) and (("Tu" in port) or ("L2L" in port)):
            return CheckResult(
                CheckStatus.FAIL,
                f"MAC {mac} on VLAN {vlan} learned on {port} of {hostname} — endpoint is "
                f"remote (known via LISP). Specify the correct device or update the endpoint's location.",
            )

        if isinstance(port, str) and port.startswith("Ac"):
            fewendpoint = True
            msg = (
                f"MAC {mac} on VLAN {vlan} learned on {port} (AccessTunnel) of {hostname}."
            )
        else:
            msg = (
                f"MAC {mac} on VLAN {vlan} learned on {port} of {hostname}. "
                f"Confirm this is the expected port for this endpoint."
            )

        ctx.state["xtr_port"] = port
        ctx.state["xtr_mac_type"] = m_type
        ctx.state["fewendpoint"] = fewendpoint
        ctx.state["mac_learning_info"] = info  # for downstream Checks (auth-session, cdp)

        return CheckResult(
            CheckStatus.OK,
            msg,
            data={"port": port, "type": m_type, "fewendpoint": fewendpoint},
        )


class CdpNeighborCheck(Check):
    """DHCP — CDP discovery on the learned XTR port.

    Mirrors the CDP block at dhcp_troubleshooting.py:1944-1964:
      1. CDPinfo.cdpneighborinterface on the learned port.
      2. AP detection: any neighbor advertising Cisco + Router + Trans-Bridge
         flags is_ap=True (consumed by AuthenticationSession).

    Stashes cdpneighborhost + is_ap in ctx.state so the next Check can run
    auth-session validation on top of the CDP context.
    """

    name = "Cisco Discovery Protocol (CDP)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        info = ctx.state.get("mac_learning_info")
        port = ctx.state.get("xtr_port")

        if not (service and hostname and info and port):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — CDP probe requires a learned MAC port from the previous Check.",
            )

        try:
            from switchingmodules.cdp import CDPinfo
            cdpneighbor = CDPinfo(hostname)
            cdpneighbor.cdpneighborinterface(port, service)
            neighbors = getattr(cdpneighbor, "cdpneighbors", []) or []
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"CDP probe failed on {hostname} {port}: {type(e).__name__}: {e}",
            )

        is_ap = False
        for neighbor in neighbors:
            platform = (neighbor.get("platform") or "").lower()
            capabilities = neighbor.get("capabilities", "") or ""
            if "cisco" in platform and "Router" in capabilities and "Trans-Bridge" in capabilities:
                is_ap = True
                break

        ctx.state["is_ap"] = is_ap
        ctx.state["cdpneighborhost"] = neighbors

        # Build a bulleted breakdown of CDP neighbors for the panel.
        if not neighbors:
            body = "• No CDP neighbors learned on this port."
        else:
            lines = []
            for n in neighbors:
                dev = n.get("device_id") or n.get("deviceId") or "(unknown)"
                plat = n.get("platform") or "(unknown)"
                caps = n.get("capabilities") or "-"
                lines.append(f"• {dev} — platform: {plat}, capabilities: {caps}")
            if is_ap:
                lines.append("• Access Point detected via CDP capabilities.")
            body = "\n".join(lines)

        return CheckResult(
            CheckStatus.OK,
            f"CDP on {hostname} {port}:\n{body}",
            data={"is_ap": is_ap, "cdp_neighbors": len(neighbors)},
        )


class AuthenticationSessionCheck(Check):
    """DHCP — authentication-session validation on the XTR port.

    Mirrors the auth-session block at dhcp_troubleshooting.py:1965-1976:
      1. authen_session_for_interface(hostname, port, service) — handles
         AccessTunnel ACRO sessions vs. normal interface template lookup.
      2. Delegate to validate_authentication_sessions() which performs the
         full chain: template/closed-mode/order, live session state, MAB,
         CDP phone detection, PAE, host mode, WOL, VLAN/SGT/dACL.

    validate_authentication_sessions() uses sys.exit() on hard fails; we catch
    BaseException so the chain surfaces them as Check FAILs instead of killing
    the worker. Discrete sub-validations stream into collection_logfile.txt
    via the legacy logging helpers.
    """

    name = "Authentication Session"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        from types import SimpleNamespace
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        info = ctx.state.get("mac_learning_info")
        port = ctx.state.get("xtr_port")

        if not (service and hostname and info and port):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — auth-session requires a learned MAC port from the previous Check.",
            )

        neighbors = ctx.state.get("cdpneighborhost") or []
        is_ap = bool(ctx.state.get("is_ap"))

        try:
            from securitymodules.authenticationsession import authen_session_for_interface
            auth_details = authen_session_for_interface(hostname, port, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"authen_session_for_interface raised {type(e).__name__}: {e}",
            )

        from device_profiler import Device  # noqa: F401 -- referenced indirectly
        shim = SimpleNamespace(
            hostname=hostname,
            mac_learning_info=info,
            authensessiondetails=auth_details,
            cdpneighborhost=neighbors,
            is_ap=is_ap,
            profiled_device=SimpleNamespace(hostname=hostname),
        )

        try:
            from traffic_flows.dhcp_troubleshooting import validate_authentication_sessions
            validate_authentication_sessions(shim, 0, service)
        except BaseException as e:
            return _legacy_fail(e, "validate_authentication_sessions")

        ctx.state["authensessiondetails"] = auth_details

        body = _format_authen_session(auth_details, hostname, port)

        return CheckResult(
            CheckStatus.OK,
            body,
            data={"is_ap": is_ap},
        )


class LocalSgt(Check):
    """DHCP — derive the endpoint's local SGT from the XTR's CEF table.

    Mirrors dhcp_troubleshooting.edge_node.localsgt() (line 71-75) which calls
    local_sgt_determination(loopback, hostname, service). Internally this
    builds an IPCef on the XTR's Loopback0 and pulls the SGT tag the switch
    has bound to that source.

    Side effect (the reason this Check is the trigger for the endpoint
    visualization): once SGT is known, MAC + VLAN + SGT are all available,
    so we emit `add_endpoint` so the frontend can draw the computer node.
    """

    name = "Network Device (XTR) SGT"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        hostname = ctx.state.get("xtr_hostname")
        loopback = ctx.state.get("xtr_loopback")
        mac = ctx.payload.get("mac")
        vlan = ctx.payload.get("vlan")

        # EW / underlay-multicast chains don't run CpLoopback/RlocDefinition,
        # so xtr_loopback may not be set. Resolve it lazily from CatC if we
        # have the uuid + service. Cache for any later check that needs it.
        if not loopback and service and ctx.state.get("xtr_uuid") and ctx.state.get("catc_name"):
            from checks.lisp import _query_loopback0
            ip, mask, err = _query_loopback0(ctx)
            if ip:
                loopback = ip
                ctx.state["xtr_loopback"] = ip
                if mask:
                    ctx.state["xtr_loopback_mask"] = mask

        if not (service and hostname and loopback):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — local SGT requires xtr_hostname + xtr_loopback + service.",
            )

        try:
            from traffic_flows.dhcp_troubleshooting import local_sgt_determination
            lsgt = local_sgt_determination(loopback, hostname, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"local_sgt_determination raised {type(e).__name__}: {e}",
            )

        ctx.state["localsgt"] = lsgt

        data = {"localsgt": lsgt}
        # Emit the endpoint visualization once MAC/VLAN/SGT are all known.
        # In FEW (wireless) runs, the wireless phase already drew the endpoint
        # parented to the AP with the wireless edge style — don't redraw it
        # parented to XTR here.
        if mac and vlan and not ctx.payload.get("is_few"):
            ep = ctx.state.get("ew_sourceep")
            endpoint_ip = (
                getattr(ep, "sourceip", None)
                or ctx.payload.get("endpoint_ip")
                or ctx.payload.get("client_ip")
            )
            data["add_endpoint"] = {
                "ip": endpoint_ip,
                "mac": mac,
                "vlan": vlan,
                "sgt": lsgt,
                "port": ctx.state.get("xtr_port"),
                "parent_node_id": "xtr",
            }

        return CheckResult(
            CheckStatus.OK,
            f"Local SGT for {loopback} on {hostname} resolved to {lsgt}.",
            data=data,
        )


