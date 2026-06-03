"""Fabric-Enabled Wireless precheck phase.

Runs BEFORE the wired DHCP/LISP/Underlay chain when the endpoint is wireless
(is_few=True). Each check wraps one phase of the legacy
traffic_flows.wirelessflows.wirelessclientonboarding() pipeline so the UI can
surface per-phase status badges and panel content rather than collapsing
everything into a single result.

The legacy helpers call sys.exit() on hard failures; every wrapper catches
BaseException and routes through _legacy_fail so the worker thread keeps
running and the user sees the error on the right node.

State produced by the phase (consumed by downstream wired checks):
  - xtr_hostname:  overridden by WirelessFabricEdgeRedirect to the real Edge
                   hosting the AP, so CpLoopback / RlocDefinition / DHCP /
                   underlay all run against the resolved Edge.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.shared import _legacy_fail
from radkit_cli import get_catc_api


def _skip_wired(name: str) -> CheckResult:
    return CheckResult(
        CheckStatus.SKIP,
        "Skipped — endpoint is wired (Fabric-Enabled Wireless not requested).",
    )


def _skip_missing(**checks) -> CheckResult:
    """Return SKIP listing only the keys whose value is falsy.

    Pass keyword pairs of (display_name=value). Falsy values are reported as
    missing; the rest are omitted so the message accurately reflects which
    upstream check did not run / did not populate state.
    """
    missing = [name for name, value in checks.items() if not value]
    if not missing:
        # Defensive: caller misused the helper. Surface as WARN so it's noticed.
        return CheckResult(
            CheckStatus.WARN,
            "Skip helper invoked with no missing values — check predicate logic.",
        )
    return CheckResult(
        CheckStatus.SKIP,
        "Skipped — required state missing: " + ", ".join(missing) + ".",
    )


class WirelessWlcDiscovery(Check):
    """Phase 1 — discover the Fabric WLC(s), pick the one hosting the endpoint,
    then validate its platform / HA / fabric state.

    Some fabric sites have multiple WLCs (HA pair across distinct devices, or
    SSO+N+1). CatC returns all of them; only the one that actually has the
    endpoint as a wireless client should drive the rest of the chain. We
    therefore enumerate each registered WLC, run endpoint_info() against it,
    and pick the one whose client database returns this MAC.
    """

    name = "Wireless — WLC Discovery"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        service = ctx.service
        catc = ctx.state.get("catc_name")
        # CatC /sda/fabricDevices expects the fabricSites entry's `id` (stored
        # as ctx.state["fabric_id"]), NOT the siteId (fabric_site_id). Passing
        # siteId silently returns an empty response on some CatC releases.
        fabric_id = ctx.state.get("fabric_id")
        mac = ctx.payload.get("mac")
        if not (service and catc and fabric_id and mac):
            return _skip_missing(
                service=service, catc_name=catc,
                fabric_id=fabric_id, mac=mac,
            )

        wlc_api = (
            f"/dna/intent/api/v1/sda/fabricDevices?fabricId={fabric_id}"
            f"&deviceRoles=WIRELESS_CONTROLLER_NODE"
        )
        try:
            wlc_raw = get_catc_api(catc, wlc_api, service)
        except Exception as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"WLC lookup failed: {type(e).__name__}: {e} (API: {wlc_api})",
            )
        wlc_response = (wlc_raw or {}).get("response") if isinstance(wlc_raw, dict) else None
        if not wlc_response:
            return CheckResult(
                CheckStatus.FAIL,
                f"No Wireless LAN Controller is registered to fabric_id {fabric_id}. "
                f"Add a WLC to the fabric site in Catalyst Center, or turn the "
                f"'Fabric Enabled Wireless' slider OFF if the endpoint is wired.",
            )

        from catalystcenterapi.catcapi import get_network_device_byuuid
        from radkit_cli import get_hostname_from_mgmtip
        from wirelessmodules.wirelesscore import (
            WirelessControllerInfo, WirelessEndpointMac,
        )

        # Step 1: resolve each WLC's hostname/mgmt IP via CatC.
        candidates = []  # list of (hostname, mgmt_ip)
        resolution_errors = []
        for entry in wlc_response:
            uuid = entry.get("networkDeviceId")
            if not uuid:
                continue
            try:
                mgmt_ip = get_network_device_byuuid(uuid, catc, service)
                hostname = get_hostname_from_mgmtip(mgmt_ip, service) if mgmt_ip else None
            except Exception as e:
                resolution_errors.append(f"{uuid}: {type(e).__name__}: {e}")
                continue
            if hostname:
                candidates.append((hostname, mgmt_ip))

        if not candidates:
            return CheckResult(
                CheckStatus.FAIL,
                "Found WLC entries in CatC but could not resolve any to a RSA "
                "hostname.\n" + ("\n".join(resolution_errors) if resolution_errors else ""),
            )

        # Step 2: probe each WLC for this endpoint MAC. The one whose client
        # database returns the MAC is the controller actually serving the
        # endpoint — pick it for the rest of the chain.
        probe_results = []  # list of dicts for the panel body
        chosen = None       # (hostname, mgmt_ip, endpoint_obj)
        for hostname, mgmt_ip in candidates:
            endpoint = WirelessEndpointMac(hostname, mac)
            try:
                endpoint.endpoint_info(service)
            except BaseException as e:
                probe_results.append({
                    "hostname": hostname, "mgmt_ip": mgmt_ip,
                    "found": False,
                    "note": f"endpoint_info raised {type(e).__name__}: {e}",
                })
                continue
            info = getattr(endpoint, "endpointinfo", None) or {}
            client_mac = (info.get("client", {}) or {}).get("mac_address")
            found = bool(client_mac)
            probe_results.append({
                "hostname": hostname, "mgmt_ip": mgmt_ip,
                "found": found,
                "note": "client present" if found else "client absent",
            })
            if found and chosen is None:
                chosen = (hostname, mgmt_ip, endpoint)

        if chosen is None:
            lines = [
                f"• {r['hostname']} ({r['mgmt_ip']}): {r['note']}"
                for r in probe_results
            ]
            return CheckResult(
                CheckStatus.FAIL,
                f"Wireless endpoint {mac} was not found on any Fabric WLC for this site. "
                f"Queried controllers:\n" + "\n".join(lines) + "\n"
                f"Remediation: confirm the endpoint is currently associated, then re-run.",
            )

        chosen_hostname, chosen_mgmt_ip, chosen_endpoint = chosen

        # Step 3: collect full WLC profile + run the platform/HA/fabric validation.
        try:
            wlc_attrs = WirelessControllerInfo(chosen_hostname)
            wlc_attrs.initial_commands(service)
            from traffic_flows.wirelessflows import wlcInfoValidation
            cps, vnids, _ = wlcInfoValidation(wlc_attrs, 0)
        except BaseException as e:
            return _legacy_fail(e, "WirelessControllerInfo/wlcInfoValidation")

        # Cache everything WirelessEndpointProfile + later checks need so we
        # don't re-query the WLC.
        ctx.state["wireless_wlc"] = wlc_attrs
        ctx.state["wireless_wlc_hostname"] = chosen_hostname
        ctx.state["wireless_wlc_ewlc"] = bool(getattr(wlc_attrs, "ewlc", False))
        ctx.state["wireless_cps_seed"] = cps
        ctx.state["wireless_vnids"] = vnids
        ctx.state["wireless_endpoint"] = chosen_endpoint

        try:
            platform = wlc_attrs.platform_information.get("platform")
            version = wlc_attrs.platform_information.get("version")
        except Exception:
            platform = version = None

        if len(candidates) > 1:
            probe_lines = "\n".join(
                f"  - {r['hostname']} ({r['mgmt_ip']}): {r['note']}"
                for r in probe_results
            )
            header = (
                f"Multiple WLCs registered to this fabric site ({len(candidates)}); "
                f"selected the one hosting endpoint {mac}.\n"
                f"Probe results:\n{probe_lines}\n"
            )
        else:
            header = ""

        body = header + (
            f"• Selected WLC: {chosen_hostname}\n"
            f"• Platform: {platform} (IOS-XE {version})\n"
            f"• Embedded WLC: {ctx.state['wireless_wlc_ewlc']}\n"
            f"• Control planes: {len(cps)}\n"
            f"• INFRA-VN L2 VNIDs: {len(vnids)}"
        )

        return CheckResult(
            CheckStatus.OK,
            body,
            data={
                "add_nodes": [{
                    "id": "wlc",
                    "role": "wlc",
                    "label": chosen_hostname,
                    "ip": chosen_mgmt_ip,
                    "floating": True,
                }],
            },
        )


class WirelessEndpointProfile(Check):
    """Phase 2 — surface the wireless-client identity collected during discovery.

    WirelessWlcDiscovery already ran endpoint_info() against the chosen WLC
    (that's how it picked the right one when multiple WLCs exist). This check
    stashes the endpoint info dict for the focused presenter checks that
    follow (SSID, Radio, Mobility, Session, Fabric, Stats), and renders the
    Identity section as its own body.
    """

    name = "Wireless — Endpoint Identity"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        endpoint = ctx.state.get("wireless_endpoint")
        mac = ctx.payload.get("mac")
        if not (endpoint and mac):
            return _skip_missing(wireless_endpoint=endpoint, mac=mac)

        info = getattr(endpoint, "endpointinfo", None) or {}
        client = info.get("client", {}) or {}
        ap = info.get("ap", {}) or {}
        wlan = info.get("wlan", {}) or {}
        fabric = info.get("fabric", {}) or {}
        stats = info.get("statistics", {}) or {}

        eid = client.get("mac_address") or mac
        vnid = fabric.get("vnid")
        sgt = fabric.get("sgt")
        rloc = fabric.get("rloc")
        ap_name = ap.get("name")
        ssid = wlan.get("ssid") or wlan.get("wlan_profile_name")
        rssi = stats.get("rssi_dbm") or stats.get("rssi_raw")
        snr = stats.get("snr_db") or stats.get("snr_raw")

        ctx.state["wireless_endpoint_info"] = info
        ctx.state["wireless_eid"] = eid
        ctx.state["wireless_vnid"] = vnid
        ctx.state["wireless_sgt"] = sgt
        ctx.state["wireless_endpoint_rloc"] = rloc
        ctx.state["wireless_ap_name"] = ap_name
        ctx.state["wireless_ssid"] = ssid
        ctx.state["wireless_rssi"] = rssi
        ctx.state["wireless_snr"] = snr
        ctx.state["wireless_ipv4"] = client.get("ipv4_address")

        ipv6 = client.get("ipv6_addresses") or []
        ipv6_str = ", ".join(ipv6) if ipv6 else "—"

        body = (
            f"• MAC: {_v(eid)}   ({_v(client.get('mac_type'))})\n"
            f"• Username: {_v(client.get('username'))}\n"
            f"• IPv4: {_v(client.get('ipv4_address'))}\n"
            f"• IPv6: {ipv6_str}\n"
            f"• Client state / active: {_v(client.get('state'))} / {_v(client.get('active_state'))}\n"
            f"• Policy-manager state: {_v(client.get('policy_manager_state'))}\n"
            f"• Connected for: {_v(client.get('connected_for_seconds'))} s\n"
            f"• Session timeout: {_v(client.get('session_timeout_sec'))} s (remaining {_v(client.get('session_timeout_remaining_sec'))} s)"
        )
        # Endpoint topology placement is deferred to phase 3, where the AP
        # node is created — the endpoint hangs off the AP (the actual airlink
        # peer), not the WLC.
        return CheckResult(CheckStatus.OK, body)


def _skip_no_endpoint_data(ctx):
    return (
        not ctx.payload.get("is_few")
        or ctx.state.get("wireless_endpoint_info") is None
    )


class WirelessEndpointSsid(Check):
    """Presenter — WLAN/SSID context (WLAN id, profile, auth, VLAN, NAT)."""

    name = "Wireless — Endpoint SSID"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_endpoint_data(ctx):
            return _skip_wired(self.name)
        info = ctx.state["wireless_endpoint_info"]
        client = info.get("client", {}) or {}
        wlan = info.get("wlan", {}) or {}
        ssid = wlan.get("ssid") or wlan.get("wlan_profile_name")
        body = (
            f"• SSID: {_v(ssid)}   WLAN id: {_v(wlan.get('wlan_id'))}\n"
            f"• WLAN profile: {_v(wlan.get('wlan_profile_name'))}\n"
            f"• Policy profile: {_v(wlan.get('policy_profile'))}\n"
            f"• Flex profile:   {_v(wlan.get('flex_profile'))}\n"
            f"• Auth algorithm: {_v(client.get('authentication_algorithm'))}\n"
            f"• EAP type: {_v(client.get('eap_type'))}\n"
            f"• Encryption cipher: {_v(client.get('encryption_cipher'))}\n"
            f"• 802.11w (PMF): {_v(client.get('pmf_80211w'))}\n"
            f"• VLAN (name): {_v(client.get('vlan_name'))}\n"
            f"• Central NAT: {_v(client.get('central_nat'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessEndpointRadio(Check):
    """Presenter — Radio/RF: AP/BSSID, protocol, channel, rate, RSSI/SNR, WMM."""

    name = "Wireless — Endpoint Radio / RF"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_endpoint_data(ctx):
            return _skip_wired(self.name)
        info = ctx.state["wireless_endpoint_info"]
        client = info.get("client", {}) or {}
        ap = info.get("ap", {}) or {}
        stats = info.get("statistics", {}) or {}
        rssi = stats.get("rssi_dbm") or stats.get("rssi_raw")
        snr = stats.get("snr_db") or stats.get("snr_raw")
        body = (
            f"• AP: {_v(ap.get('name'))}   ({_v(ap.get('mac_address'))})\n"
            f"• BSSID: {_v(ap.get('bssid'))}   slot: {_v(ap.get('slot'))}\n"
            f"• Protocol: {_v(client.get('protocol'))}   channel: {_v(client.get('channel'))}\n"
            f"• Current rate: {_v(client.get('current_rate'))}\n"
            f"• RSSI: {_v(rssi)} dBm   SNR: {_v(snr)} dB\n"
            f"• WMM: {_v(client.get('wmm_support'))}   U-APSD: {_v(client.get('uapsd_support'))}   Power-save: {_v(client.get('power_save'))}\n"
            f"• Fastlane: {_v(client.get('fastlane_support'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessEndpointMobility(Check):
    """Presenter — mobility role, roam type, move count, last move timestamp."""

    name = "Wireless — Endpoint Mobility"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_endpoint_data(ctx):
            return _skip_wired(self.name)
        mobility = ctx.state["wireless_endpoint_info"].get("mobility", {}) or {}
        body = (
            f"• Role: {_v(mobility.get('role'))}   roam type: {_v(mobility.get('roam_type'))}\n"
            f"• Move count: {_v(mobility.get('move_count'))}\n"
            f"• Last move (UTC): {_v(mobility.get('complete_timestamp_utc'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessEndpointSessionManager(Check):
    """Presenter — Session Manager: PoA, IIF-ID, session IDs, AAA-resultant policies."""

    name = "Wireless — Endpoint Session Manager"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_endpoint_data(ctx):
            return _skip_wired(self.name)
        session_mgr = ctx.state["wireless_endpoint_info"].get("session_manager", {}) or {}
        resultant = session_mgr.get("resultant_policies", {}) or {}
        body = (
            f"• Point of attachment: {_v(session_mgr.get('point_of_attachment'))}\n"
            f"• IIF-ID: {_v(session_mgr.get('iif_id'))}\n"
            f"• Authorized: {_v(session_mgr.get('authorized'))}\n"
            f"• Common session ID: {_v(session_mgr.get('common_session_id'))}\n"
            f"• Acct session ID: {_v(session_mgr.get('acct_session_id'))}\n"
            f"• Resultant policies pushed by AAA: {len(resultant)} keys"
        )
        if resultant:
            body += "\n    " + "\n    ".join(
                f"– {k}: {v}" for k, v in list(resultant.items())[:20]
            )
        return CheckResult(CheckStatus.OK, body)


class WirelessEndpointFabric(Check):
    """Presenter — fabric status / VNID / SGT / RLOC / CP (as reported by WLC)."""

    name = "Wireless — Endpoint Fabric (per WLC)"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_endpoint_data(ctx):
            return _skip_wired(self.name)
        fabric = ctx.state["wireless_endpoint_info"].get("fabric", {}) or {}
        body = (
            f"• Fabric status: {_v(fabric.get('status'))}\n"
            f"• VNID: {_v(fabric.get('vnid'))}   SGT: {_v(fabric.get('sgt'))}\n"
            f"• Reported RLOC: {_v(fabric.get('rloc'))}\n"
            f"• Control plane: {_v(fabric.get('control_plane_name'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessEndpointStats(Check):
    """Presenter — endpoint traffic counters (bytes / packets RX/TX)."""

    name = "Wireless — Endpoint Traffic Statistics"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_endpoint_data(ctx):
            return _skip_wired(self.name)
        stats = ctx.state["wireless_endpoint_info"].get("statistics", {}) or {}
        body = (
            f"• Bytes RX/TX: {_v(stats.get('bytes_received_from_client_raw'))} / {_v(stats.get('bytes_sent_to_client_raw'))}\n"
            f"• Packets RX/TX: {_v(stats.get('packets_received_from_client_raw'))} / {_v(stats.get('packets_sent_to_client_raw'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessWlcEndpointValidation(Check):
    """Phase 3 — run the WLC's full endpoint/AP/WLAN/policy-profile validation.

    Wraps wlcEndpointValidation(). This is the heavyweight phase that pulls AP
    config, WLAN, policy profile, flex profile, site tag and raises on the
    many exit_program() conditions inside.

    Body shows the AP Platform section only — Tags/Profiles, WLAN, Policy
    Profile, Flex Profile and Site Tag are split into focused presenter
    checks that run immediately after this one and read ctx.state.
    """

    name = "Wireless — AP Platform"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        service = ctx.service
        wlc_hostname = ctx.state.get("wireless_wlc_hostname")
        endpoint = ctx.state.get("wireless_endpoint")
        wlc_attrs = ctx.state.get("wireless_wlc")
        if not (service and wlc_hostname and endpoint and wlc_attrs):
            return _skip_missing(
                service=service, wireless_wlc_hostname=wlc_hostname,
                wireless_endpoint=endpoint, wireless_wlc=wlc_attrs,
            )

        try:
            from traffic_flows.wirelessflows import wlcEndpointValidation
            ap_config, wlan_set, _ = wlcEndpointValidation(
                0, wlc_hostname, endpoint, bool(getattr(wlc_attrs, "ewlc", False)), service
            )
        except BaseException as e:
            return _legacy_fail(e, "wlcEndpointValidation")

        ctx.state["wireless_ap_config"] = ap_config
        ctx.state["wireless_wlan_set"] = wlan_set

        ap_name = ctx.state.get("wireless_ap_name") or "AP"
        ap_entry = (ap_config.get("ap_name") or {}).get(ap_name) or {}
        ctx.state["wireless_ap_ip"] = ap_entry.get("ip_address")

        ap_ip = ap_entry.get("ip_address")
        ap_mask = ap_entry.get("ip_netmask")
        ap_mode = ap_entry.get("ap_mode")
        ap_model = ap_entry.get("ap_model")
        ap_version = ap_entry.get("ios_version")
        ap_uptime = ap_entry.get("ap_up_time")
        ap_capwap = ap_entry.get("ap_capwap_up_time")
        ap_radio_mac = ap_entry.get("cisco_ap_identifier")

        body = (
            f"• AP: {_v(ap_name)}   model: {_v(ap_model)}   mode: {_v(ap_mode)}\n"
            f"• Image: {_v(ap_version)}\n"
            f"• Radio MAC: {_v(ap_radio_mac)}\n"
            f"• Mgmt IP: {_v(ap_ip)}/{_v(ap_mask)}\n"
            f"• Uptime: {_v(ap_uptime)}   CAPWAP uptime: {_v(ap_capwap)}"
        )

        return CheckResult(
            CheckStatus.OK,
            body,
            data={
                "add_nodes": [{
                    "id": "ap",
                    "role": "access-point",
                    "label": ap_name,
                    "ip": ap_ip,
                    "floating": True,
                }],
            },
        )


def _v(x, dash="—"):
    return dash if x in (None, "", []) else x


def _ap_entry(ctx):
    ap_config = ctx.state.get("wireless_ap_config") or {}
    ap_name = ctx.state.get("wireless_ap_name") or "AP"
    return (ap_config.get("ap_name") or {}).get(ap_name) or {}


def _wlan_obj(ctx):
    wlan_set = ctx.state.get("wireless_wlan_set")
    return getattr(wlan_set, "wlanprofile", {}) or {}


def _policy_profile(ctx):
    wlan_set = ctx.state.get("wireless_wlan_set")
    return (getattr(wlan_set, "policyprofile", {}) or {}).get("policy_profile", {}) or {}


def _flex_obj(ctx):
    wlan_set = ctx.state.get("wireless_wlan_set")
    return (getattr(wlan_set, "flexprofile", {}) or {}).get("flex_profile", {}) or {}


def _stag_obj(ctx):
    wlan_set = ctx.state.get("wireless_wlan_set")
    return (getattr(wlan_set, "stag", {}) or {}).get("site_tag", {}) or {}


def _skip_no_wlc_data(ctx):
    return (
        not ctx.payload.get("is_few")
        or ctx.state.get("wireless_ap_config") is None
        or ctx.state.get("wireless_wlan_set") is None
    )


class WirelessApTags(Check):
    """Presenter — AP tag/profile bindings collected in WirelessWlcEndpointValidation."""

    name = "Wireless — AP Tags / Profiles"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_wlc_data(ctx):
            return _skip_wired(self.name)
        ap = _ap_entry(ctx)
        body = (
            f"• Policy tag: {_v(ap.get('policy_tag_name'))}\n"
            f"• Site tag:   {_v(ap.get('site_tag_name'))}\n"
            f"• RF tag:     {_v(ap.get('rf_tag_name'))}\n"
            f"• Flex profile:    {_v(ap.get('flex_profile'))}\n"
            f"• AP-join profile: {_v(ap.get('ap_join_profile'))}\n"
            f"• Fabric status: {_v(ap.get('fabric_status'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessWlanProfile(Check):
    """Presenter — WLAN profile + 802.11 security/fast-transition."""

    name = "Wireless — WLAN Profile"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_wlc_data(ctx):
            return _skip_wired(self.name)
        wlan_obj = _wlan_obj(ctx)
        wlan_blk = wlan_obj.get("wlan", {}) or {}
        ft = wlan_obj.get("fast_transition", {}) or {}
        security = (wlan_obj.get("security", {}) or {}).get("global", {}) or {}
        body = (
            f"• id: {_v(wlan_blk.get('id'))}   name: {_v(wlan_blk.get('profile_name'))}   SSID: {_v(wlan_blk.get('ssid'))}\n"
            f"• Status: {_v(wlan_blk.get('status'))}\n"
            f"• 802.11 Auth: {_v(security.get('802.11 Authentication'))}\n"
            f"• WMM: {_v(wlan_blk.get('wmm'))}   OKC: {_v(wlan_blk.get('okc'))}   FT: {_v(ft.get('support'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessPolicyProfile(Check):
    """Presenter — Policy Profile (VLAN, switching, ACL/QoS, fabric/AAA invariants)."""

    name = "Wireless — Policy Profile"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_wlc_data(ctx):
            return _skip_wired(self.name)
        pp = _policy_profile(ctx)
        sections = pp.get("sections", {}) or {}
        switching = sections.get("WLAN Switching Policy", {}) or {}
        acl = sections.get("WLAN ACL", {}) or {}
        qos_ssid = sections.get("QOS per SSID", {}) or {}
        qos_client = sections.get("QOS per Client", {}) or {}
        fabric_sec = sections.get("Fabric Profile", {}) or {}
        aaa = sections.get("AAA Policy Params", {}) or {}
        dhcp_sec = sections.get("DHCP", {}) or {}
        atf = sections.get("Airtime-fairness Profile", {}) or {}
        wlan_mobility = sections.get("WLAN Mobility", {}) or {}
        body = (
            f"• Name: {_v(pp.get('name'))}\n"
            f"• VLAN: {_v(pp.get('vlan'))}   WMI VLAN: {_v(pp.get('wireless_management_interface_vlan'))}\n"
            f"• Passive client: {_v(pp.get('passive_client'))}   Static-IP mobility: {_v(pp.get('staticip_mobility'))}\n"
            f"• Flex central switching: {_v(switching.get('Flex Central Switching'))}\n"
            f"• Flex central DHCP:      {_v(switching.get('Flex Central DHCP'))}\n"
            f"• Flex central auth:      {_v(switching.get('Flex Central Authentication'))}\n"
            f"• ACL IPv4: {_v(acl.get('IPv4 ACL'))}   ACL IPv6: {_v(acl.get('IPv6 ACL'))}\n"
            f"• Preauth URL filter:  {_v(acl.get('Preauth urlfilter list'))}\n"
            f"• Postauth URL filter: {_v(acl.get('Postauth urlfilter list'))}\n"
            f"• QoS/SSID  in: {_v(qos_ssid.get('Ingress Service Name'))}   out: {_v(qos_ssid.get('Egress Service Name'))}\n"
            f"• QoS/Client in: {_v(qos_client.get('Ingress Service Name'))}   out: {_v(qos_client.get('Egress Service Name'))}\n"
            f"• Fabric profile attached: {_v(fabric_sec.get('Profile Name'))}\n"
            f"• AAA Override: {_v(aaa.get('AAA Override'))}   NAC: {_v(aaa.get('NAC'))} ({_v(aaa.get('NAC Type'))})\n"
            f"• IP-MAC binding: {_v(atf.get('IP mac-binding'))}\n"
            f"• DHCP required:  {_v(dhcp_sec.get('required'))}\n"
            f"• WLAN mobility anchor: {_v(wlan_mobility.get('Anchor'))}\n"
            "\nAll mandatory SDA/FEW invariants validated (VLAN, fabric profile attached, "
            "central-switching DISABLED, central-DHCP DISABLED, central-auth ENABLED, "
            "no static-IP mobility, no mobility anchor, MAB/Web ACL present in Flex)."
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessFlexProfile(Check):
    """Presenter — Flex profile (native VLAN, policy ACLs)."""

    name = "Wireless — Flex Profile"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_wlc_data(ctx):
            return _skip_wired(self.name)
        flex_obj = _flex_obj(ctx)
        flex_acls = flex_obj.get("policy_acl", []) or flex_obj.get("policy_acls", []) or []
        acls_render = ", ".join(
            str(a.get("acl_name", a)) if isinstance(a, dict) else str(a)
            for a in flex_acls[:6]
        ) or "—"
        body = (
            f"• Name: {_v(flex_obj.get('name'))}\n"
            f"• Native VLAN id: {_v(flex_obj.get('native_vlan_id'))}\n"
            f"• Policy ACLs ({len(flex_acls)}): {acls_render}"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessSiteTag(Check):
    """Presenter — Site Tag (local-site, fabric AP DHCP broadcast, multicast group)."""

    name = "Wireless — Site Tag"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if _skip_no_wlc_data(ctx):
            return _skip_wired(self.name)
        stag = _stag_obj(ctx)
        body = (
            f"• Name: {_v(stag.get('name'))}\n"
            f"• Local site: {_v(stag.get('local_site'))}\n"
            f"• Fabric AP DHCP broadcast: {_v(stag.get('fabric_ap_dhcp_broadcast'))}\n"
            f"• Fabric multicast group:   {_v(stag.get('fabric_multicast_group_ipv4'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessCpSession(Check):
    """Phase 4 — verify LISP sessions between the WLC and every fabric CP.

    Wraps fabricEnabledWirelessSession(). Stores the resolved control-plane
    list and per-CP info objects for the next checks.
    """

    name = "Wireless — Control-Plane Sessions"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        service = ctx.service
        wlc_attrs = ctx.state.get("wireless_wlc")
        endpoint = ctx.state.get("wireless_endpoint")
        catc = ctx.state.get("catc_name")
        if not (service and wlc_attrs and endpoint and catc):
            return _skip_missing(
                service=service, wireless_wlc=wlc_attrs,
                wireless_endpoint=endpoint, catc_name=catc,
            )

        try:
            from traffic_flows.lispsessiontroubleshooting import fabricEnabledWirelessSession
            _, control_planes, cp_info = fabricEnabledWirelessSession(
                wlc_attrs, None, 0, catc, endpoint, service
            )
        except BaseException as e:
            return _legacy_fail(e, "fabricEnabledWirelessSession")

        ctx.state["wireless_control_planes"] = control_planes
        ctx.state["wireless_cp_info"] = cp_info

        lines = [
            f"• {(cp.get('ip') or '?')} — status: {(cp.get('status') or '?')}"
            for cp in (control_planes or [])
        ]
        body = "\n".join(lines) if lines else "No control planes returned."

        return CheckResult(CheckStatus.OK, body)


class WirelessCpEidQuery(Check):
    """Phase 5 — query every up control plane for the endpoint EID.

    Wraps wlcCpQuery(). Stores the baseline ETR set the next check uses to
    locate the real fabric Edge.
    """

    name = "Wireless — CP EID Registration"
    target_node_id = "wlc"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        service = ctx.service
        eid = ctx.state.get("wireless_eid")
        vnid = ctx.state.get("wireless_vnid")
        control_planes = ctx.state.get("wireless_control_planes")
        cp_info = ctx.state.get("wireless_cp_info")
        if not (service and eid and vnid and control_planes and cp_info):
            return _skip_missing(
                service=service, wireless_eid=eid, wireless_vnid=vnid,
                wireless_control_planes=control_planes, wireless_cp_info=cp_info,
            )

        try:
            from traffic_flows.wirelessflows import wlcCpQuery
            _, baseline_etrs = wlcCpQuery(0, eid, vnid, control_planes, cp_info, service)
        except BaseException as e:
            return _legacy_fail(e, "wlcCpQuery")

        if not baseline_etrs:
            return CheckResult(
                CheckStatus.FAIL,
                f"No ETRs returned by any control plane for EID {eid} VNID {vnid}.",
            )

        ctx.state["wireless_baseline_etrs"] = baseline_etrs

        return CheckResult(
            CheckStatus.OK,
            f"• EID {eid} (VNID {vnid}) registered by ETRs: {sorted(baseline_etrs)}",
        )


class WirelessFabricEdgeResolve(Check):
    """Phase 6a — resolve the real fabric Edge hosting the AP.

    Runs the heavy LISP-side work (fabric_edge_etr_validation against the
    baseline ETR). Stashes the resolved Edge identity in ctx.state for the
    Redirect + AccessTunnel checks that follow.
    """

    name = "Wireless — Resolve Fabric Edge"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        service = ctx.service
        catc = ctx.state.get("catc_name")
        baseline_etrs = ctx.state.get("wireless_baseline_etrs")
        eid = ctx.state.get("wireless_eid")
        vnid = ctx.state.get("wireless_vnid")
        control_planes = ctx.state.get("wireless_control_planes")
        if not (service and catc and baseline_etrs and eid and vnid and control_planes):
            return _skip_missing(
                service=service, catc_name=catc,
                wireless_baseline_etrs=baseline_etrs,
                wireless_eid=eid, wireless_vnid=vnid,
                wireless_control_planes=control_planes,
            )

        etr = next(iter(baseline_etrs))
        mapservers = [
            {"map_server": (cp.get("ip") or "").strip().lower(), "ack": "Up"}
            for cp in control_planes
        ]

        try:
            from traffic_flows.wirelessflows import fabric_edge_etr_validation
            _, sourcextr = fabric_edge_etr_validation(
                0, etr, eid, vnid, catc, service, mapservers
            )
        except BaseException as e:
            return _legacy_fail(e, "fabric_edge_etr_validation")

        new_xtr = getattr(sourcextr, "hostname", None)
        if not new_xtr:
            return CheckResult(
                CheckStatus.FAIL,
                "fabric_edge_etr_validation returned no XTR hostname.",
            )

        prior = ctx.state.get("xtr_hostname")
        roamed = bool(
            prior
            and prior.split(".")[0].lower() != new_xtr.split(".")[0].lower()
        )

        # Stash for Redirect + AccessTunnel checks.
        ctx.state["wireless_sourcextr"] = sourcextr
        ctx.state["wireless_resolved_xtr"] = new_xtr
        ctx.state["wireless_prior_xtr"] = prior
        ctx.state["wireless_roamed"] = roamed

        if roamed:
            body = (
                f"Real fabric Edge: {new_xtr}\n"
                f"Endpoint roamed — user supplied: {prior}"
            )
        else:
            body = f"Real fabric Edge for wireless endpoint: {new_xtr}."
        return CheckResult(CheckStatus.OK, body)


class WirelessFabricEdgeRedirect(Check):
    """Phase 6b — apply the redirect.

    Mutates xtr_* state to point at the resolved Edge, emits topology changes
    (relabel for no-roam, new xtr-roamed node + remap for roam), and queues
    OriginalEdgeUnderlayDiscovery on roam so the original Edge still gets its
    underlay/CDP wiring.
    """

    name = "Wireless — Apply XTR Redirect"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        sourcextr = ctx.state.get("wireless_sourcextr")
        new_xtr = ctx.state.get("wireless_resolved_xtr")
        if not (sourcextr and new_xtr):
            return _skip_missing(
                wireless_sourcextr=sourcextr,
                wireless_resolved_xtr=new_xtr,
            )

        prior = ctx.state.get("wireless_prior_xtr")
        roamed = bool(ctx.state.get("wireless_roamed"))

        if prior:
            ctx.state["original_xtr_hostname"] = prior
            ctx.state["original_xtr_mgmtip"] = ctx.state.get("xtr_mgmtip")
            ctx.state["original_xtr_node_id"] = "xtr"
        ctx.state["xtr_hostname"] = new_xtr
        if getattr(sourcextr, "loopback", None):
            ctx.state["xtr_loopback"] = sourcextr.loopback
        if getattr(sourcextr, "mgmtip", None):
            ctx.state["xtr_mgmtip"] = sourcextr.mgmtip
        # Also redirect CatC UUID so downstream UUID-keyed CatC calls hit the
        # resolved Edge — prevents spurious mismatches between hostname-keyed
        # and UUID-keyed lookups (e.g. PITR vs Loopback0).
        new_uuid = getattr(sourcextr, "deviceuuid", None) or getattr(sourcextr, "uuid", None)
        if new_uuid:
            ctx.state["xtr_uuid"] = new_uuid

        if not roamed:
            return CheckResult(
                CheckStatus.OK,
                f"No roam — XTR remains {new_xtr}.",
                data={"hostname": new_xtr, "node_relabel": new_xtr},
            )

        new_id = "xtr-roamed"
        remap = ctx.state.setdefault("node_remap", {})
        remap["xtr"] = new_id

        from checks.underlay import OriginalEdgeUnderlayDiscovery
        return CheckResult(
            CheckStatus.OK,
            f"Wireless endpoint roamed: {prior} → {new_xtr}. Remaining wired "
            f"validations will run against {new_xtr}.",
            data={
                "hostname": new_xtr,
                "add_nodes": [{
                    "id": new_id,
                    "role": "xtr",
                    "label": new_xtr,
                    "ip": getattr(sourcextr, "loopback", None)
                          or getattr(sourcextr, "mgmtip", None),
                    "connect_to": "xtr",
                    "edge_label": "ROAMED",
                }],
                "queue_checks": [OriginalEdgeUnderlayDiscovery()],
            },
        )


class WirelessAccessTunnel(Check):
    """Phase 6c — wire AP + endpoint to the resolved Edge.

    Looks up the AP↔Edge access tunnel on the resolved Edge, builds the
    wireless edge label (SSID/RSSI/SNR), and emits the AP node + endpoint
    into the topology.
    """

    name = "Wireless — Access Tunnel (AP↔Edge)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        new_xtr = ctx.state.get("wireless_resolved_xtr")
        eid = ctx.state.get("wireless_eid")
        if not (new_xtr and eid):
            return _skip_missing(
                wireless_resolved_xtr=new_xtr,
                wireless_eid=eid,
            )

        # Resolve current xtr node id (post-remap) for connect_to.
        remap = ctx.state.get("node_remap") or {}
        xtr_node_id = remap.get("xtr", "xtr")

        ap_ip = ctx.state.get("wireless_ap_ip")
        tunnel_name = None
        phyport = None
        if ap_ip:
            try:
                from wirelessmodules.accesstunnels import AccessTunnel
                at = AccessTunnel(new_xtr)
                at.accesstunnelbyip(ap_ip, ctx.service)
                tunnel_name = getattr(at, "accesstunnelname", None)
                phy = getattr(at, "accesstunnelphyport", None) or []
                phyport = phy[0] if phy else None
                ctx.state["wireless_access_tunnel"] = tunnel_name
                ctx.state["wireless_ap_phyport"] = phyport
            except BaseException:
                pass

        tunnel_label_parts = []
        if tunnel_name:
            tunnel_label_parts.append(tunnel_name.replace("AccessTunnel", "Ac"))
        if phyport:
            tunnel_label_parts.append(phyport)
        tunnel_edge_label = "  •  ".join(tunnel_label_parts) if tunnel_label_parts else "Access Tunnel"

        rssi = ctx.state.get("wireless_rssi")
        snr = ctx.state.get("wireless_snr")
        ssid = ctx.state.get("wireless_ssid")

        def _num(v):
            if v is None:
                return None
            s = str(v).strip()
            for suf in ("dBm", "dbm", "dB", "db"):
                if s.lower().endswith(suf.lower()):
                    s = s[:-len(suf)].strip()
            return s
        rssi_n = _num(rssi)
        snr_n = _num(snr)

        wparts = []
        if ssid:
            wparts.append(f"SSID {ssid}")
        if rssi_n:
            wparts.append(f"RSSI {rssi_n} dBm")
        if snr_n:
            wparts.append(f"SNR {snr_n} dB")
        wireless_edge_label = "\n".join(wparts) if wparts else ""

        def _rssi_band(v):
            try:
                v = int(str(v).split()[0])
            except Exception:
                return None
            if v >= -67: return "good"
            if v <= -75: return "bad"
            return "normal"

        def _snr_band(v):
            try:
                v = int(str(v).split()[0])
            except Exception:
                return None
            if v >= 25: return "good"
            if v < 15:  return "bad"
            return "normal"

        bands = [b for b in (_rssi_band(rssi), _snr_band(snr)) if b]
        rf_band = "bad" if "bad" in bands else ("normal" if "normal" in bands else ("good" if bands else None))

        endpoint_spec = {
            "mac": eid,
            "ip": ctx.state.get("wireless_ipv4"),
            "parent_node_id": "ap",
            "port": ssid,
            "rssi": rssi,
            "snr": snr,
            "wireless": True,
            "edge_label": wireless_edge_label,
            "rf_band": rf_band,
            "vlan": ctx.state.get("wireless_vnid"),
            "sgt": ctx.state.get("wireless_sgt"),
        }

        body_lines = [f"AP↔Edge tunnel: {tunnel_name or 'unknown'}"]
        if phyport:
            body_lines.append(f"Physical port: {phyport}")
        if ssid:
            body_lines.append(f"SSID: {ssid}")
        if rssi_n:
            body_lines.append(f"RSSI: {rssi_n} dBm")
        if snr_n:
            body_lines.append(f"SNR: {snr_n} dB")

        return CheckResult(
            CheckStatus.OK,
            "\n".join(body_lines),
            data={
                "add_nodes": [{
                    "id": "ap",
                    "connect_to": xtr_node_id,
                    "edge_label": tunnel_edge_label,
                }],
                "add_endpoint": endpoint_spec,
            },
        )


class WirelessFabricEdgeMac(Check):
    """Phase 7 — validate the wireless MAC on the resolved Edge.

    Wraps fabric_edge_mac_validation(): L2LISP DB entry, access-tunnel,
    SISF entry, MAC table CP_LEARN, etc.
    """

    name = "Wireless — Fabric Edge MAC Validation"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        service = ctx.service
        mac = ctx.state.get("wireless_eid")
        vnid = ctx.state.get("wireless_vnid")
        rloc = ctx.state.get("wireless_endpoint_rloc")
        sourcextr = ctx.state.get("wireless_sourcextr")
        if not (service and mac and vnid and sourcextr):
            return _skip_missing(
                service=service, wireless_eid=mac,
                wireless_vnid=vnid, wireless_sourcextr=sourcextr,
            )

        try:
            from traffic_flows.wirelessflows import (
                fabric_edge_mac_validation,
                WirelessRoamWarning,
            )
            fabric_edge_mac_validation(0, mac, vnid, rloc, sourcextr, service)
        except WirelessRoamWarning as w:
            # Device-tracking / LISP-DB came back empty on this Edge in a way
            # that's explainable by the wireless client having roamed off it.
            # Surface as WARN so the chain keeps going and the badge reflects
            # "expected, not a real failure".
            return CheckResult(CheckStatus.WARN, str(w))
        except BaseException as e:
            return _legacy_fail(e, "fabric_edge_mac_validation")

        body = (
            f"MAC {mac} in VNID {vnid} validated on {sourcextr.hostname}.\n"
            f"Sub-checks performed:\n"
            f"  • L2LISP database — local entry present for the MAC\n"
            f"  • Access-tunnel — MAC reachable via access-tunnel adjacency\n"
            f"  • SISF — device-tracking row present for the endpoint\n"
            f"  • MAC address-table — CP_LEARN entry confirms control-plane learning"
        )
        return CheckResult(CheckStatus.OK, body)


class WirelessRoamingHistory(Check):
    """Phase 8 — pull recent fabric roaming events (up to 5)."""

    name = "Wireless — Roaming History"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        service = ctx.service
        wlc_hostname = ctx.state.get("wireless_wlc_hostname")
        mac = ctx.state.get("wireless_eid")
        if not (service and wlc_hostname and mac):
            return _skip_missing(
                service=service, wireless_wlc_hostname=wlc_hostname,
                wireless_eid=mac,
            )

        try:
            from wirelessmodules.wirelesscore import WirelessEndpointMac
            hist = WirelessEndpointMac(wlc_hostname, mac)
            hist.fabric_roamming(service)
        except BaseException as e:
            return _legacy_fail(e, "WirelessEndpointMac.fabric_roamming")

        events = (getattr(hist, "roaminghistory", {}) or {}).get("events") or []
        if not events:
            return CheckResult(CheckStatus.OK, "No recent fabric roaming events recorded.")

        lines = []
        for i, e in enumerate(events[:5], start=1):
            lines.append(
                f"• Event {i}: AP {e.get('ap_mac')}, XTR {e.get('xtr_ip')}, "
                f"VNID {e.get('vnid')}, SGT {e.get('sgt')}, "
                f"assoc {e.get('assoc_time')}, entry {e.get('entry_time')}"
            )
        return CheckResult(CheckStatus.OK, "\n".join(lines))


class WirelessL2LispStats(Check):
    """Phase 9 — collect L2LISP error counters on the resolved Edge."""

    name = "Wireless — L2LISP Statistics"
    target_node_id = "xtr"

    _IGNORE = ("update client rbm failed", "idb not found")

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.payload.get("is_few"):
            return _skip_wired(self.name)

        service = ctx.service
        sourcextr = ctx.state.get("wireless_sourcextr")
        if not (service and sourcextr):
            return _skip_missing(service=service, wireless_sourcextr=sourcextr)

        try:
            from routingmodules.lisp import L2LISPStatistics
            stats = L2LISPStatistics(sourcextr.hostname)
            stats.l2lispstatistics(service)
        except BaseException as e:
            return _legacy_fail(e, "L2LISPStatistics.l2lispstatistics")

        errors = ((getattr(stats, "l2lispstats", {}) or {}).get("errors") or {})
        warn_errors = {
            k: v for k, v in errors.items()
            if v and not any(s in k.lower() for s in self._IGNORE)
        }

        if warn_errors:
            return CheckResult(
                CheckStatus.WARN,
                "L2LISP error counters non-zero:\n"
                + "\n".join(f"• {k}: {v}" for k, v in warn_errors.items()),
            )
        return CheckResult(
            CheckStatus.OK,
            f"L2LISP error counters are clean on {sourcextr.hostname}.",
        )



