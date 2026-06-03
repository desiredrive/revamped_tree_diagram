"""East-West — destination-endpoint wireless validations.

Triggered from `EwDestEndpointOnboarding` when the destination endpoint is
learned via an access-tunnel port (i.e. it's a wireless client on the
destination Fabric Edge). Mirrors the endpoint-state subset of the source-side
wireless chain but operates on the destination XTR / destination MAC and a
parallel `wireless_dst_*` state namespace.

Anchored on node id `dxtr` (added by EwDestXtrProfiling).
"""

from checks import Check, CheckResult, CheckStatus, RunContext


def is_access_tunnel_port(port: str) -> bool:
    """True if `port` looks like an Access-Tunnel interface name.

    Genie reports these as 'Ac0', 'AccessTunnel0', etc.
    """
    if not port:
        return False
    p = str(port).strip().lower()
    return p.startswith("ac") and ("tunnel" in p or p.startswith("ac"))


def _v(x):
    return "—" if x in (None, "", []) else x


def _skip_no_dst_endpoint(name: str) -> CheckResult:
    return CheckResult(
        CheckStatus.SKIP,
        f"{name}: no destination wireless endpoint info captured.",
    )


class EwDestWirelessWlcDiscovery(Check):
    """Find the WLC serving the destination endpoint MAC.

    Destination XTR's fabric_id is used to enumerate registered WLCs from CatC,
    then each candidate is probed for the dest endpoint MAC; the controller
    that returns the MAC drives the rest of the dest wireless chain.
    """

    name = "Wireless (dest) — WLC Discovery"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        from radkit_cli import get_catc_api
        from catalystcenterapi.catcapi import get_network_device_byuuid
        from radkit_cli import get_hostname_from_mgmtip
        from wirelessmodules.wirelesscore import (
            WirelessControllerInfo, WirelessEndpointMac,
        )
        from checks_ew_shared import _legacy_fail

        service = ctx.service
        catc = ctx.state.get("catc_name")
        dstxtr = ctx.state.get("ew_dstxtr")
        dstep = ctx.state.get("ew_destep")
        if not (service and catc and dstxtr and dstep):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — service / catc / ew_dstxtr / ew_destep missing.",
            )

        mac = getattr(dstep, "sourcemac", None)
        fabric_id = getattr(dstxtr, "fabric_id", None)
        if not (mac and fabric_id):
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — destination MAC ({mac}) or fabric_id ({fabric_id}) missing.",
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
                f"WLC lookup failed: {type(e).__name__}: {e}",
            )
        wlc_response = (wlc_raw or {}).get("response") if isinstance(wlc_raw, dict) else None
        if not wlc_response:
            return CheckResult(
                CheckStatus.FAIL,
                f"No WLC registered to destination fabric_id {fabric_id}.",
            )

        candidates = []
        for entry in wlc_response:
            uuid = entry.get("networkDeviceId")
            if not uuid:
                continue
            try:
                mgmt_ip = get_network_device_byuuid(uuid, catc, service)
                hostname = get_hostname_from_mgmtip(mgmt_ip, service) if mgmt_ip else None
            except Exception:
                continue
            if hostname:
                candidates.append((hostname, mgmt_ip))

        if not candidates:
            return CheckResult(
                CheckStatus.FAIL,
                "WLC entries returned by CatC could not be resolved to RSA hostnames.",
            )

        chosen = None
        probes = []
        for hostname, mgmt_ip in candidates:
            endpoint = WirelessEndpointMac(hostname, mac)
            try:
                endpoint.endpoint_info(service)
            except BaseException as e:
                probes.append(f"  - {hostname} ({mgmt_ip}): {type(e).__name__}: {e}")
                continue
            info = getattr(endpoint, "endpointinfo", None) or {}
            client_mac = (info.get("client", {}) or {}).get("mac_address")
            if client_mac:
                chosen = (hostname, mgmt_ip, endpoint)
                probes.append(f"  - {hostname} ({mgmt_ip}): client present")
                break
            probes.append(f"  - {hostname} ({mgmt_ip}): client absent")

        if chosen is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"Destination wireless MAC {mac} not present on any fabric WLC.\n"
                + "\n".join(probes),
            )

        chosen_hostname, chosen_mgmt_ip, chosen_endpoint = chosen
        try:
            wlc_attrs = WirelessControllerInfo(chosen_hostname)
            wlc_attrs.initial_commands(service)
        except BaseException as e:
            return _legacy_fail(e, "Dest WirelessControllerInfo")

        ctx.state["wireless_dst_wlc"] = wlc_attrs
        ctx.state["wireless_dst_wlc_hostname"] = chosen_hostname
        ctx.state["wireless_dst_endpoint"] = chosen_endpoint
        ctx.state["wireless_dst_endpoint_info"] = (
            getattr(chosen_endpoint, "endpointinfo", None) or {}
        )

        try:
            platform = wlc_attrs.platform_information.get("platform")
            version = wlc_attrs.platform_information.get("version")
        except Exception:
            platform = version = None

        body = (
            f"• Selected WLC: {chosen_hostname} ({chosen_mgmt_ip})\n"
            f"• Platform: {platform} (IOS-XE {version})\n"
            f"• Embedded WLC: {bool(getattr(wlc_attrs, 'ewlc', False))}\n"
            f"• Probes:\n" + "\n".join(probes)
        )
        return CheckResult(CheckStatus.OK, body)


class EwDestWirelessEndpointProfile(Check):
    """Identity slice of the dest WLC endpoint info (MAC, user, IP, state)."""

    name = "Wireless (dest) — Endpoint Identity"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("wireless_dst_endpoint_info")
        if not info:
            return _skip_no_dst_endpoint(self.name)
        client = info.get("client", {}) or {}
        ipv6 = client.get("ipv6_addresses") or []
        body = (
            f"• MAC: {_v(client.get('mac_address'))}   ({_v(client.get('mac_type'))})\n"
            f"• Username: {_v(client.get('username'))}\n"
            f"• IPv4: {_v(client.get('ipv4_address'))}\n"
            f"• IPv6: {', '.join(ipv6) if ipv6 else '—'}\n"
            f"• Client state / active: {_v(client.get('state'))} / {_v(client.get('active_state'))}\n"
            f"• Policy-manager state: {_v(client.get('policy_manager_state'))}\n"
            f"• Connected for: {_v(client.get('connected_for_seconds'))} s\n"
            f"• Session timeout: {_v(client.get('session_timeout_sec'))} s "
            f"(remaining {_v(client.get('session_timeout_remaining_sec'))} s)"
        )
        return CheckResult(CheckStatus.OK, body)


class EwDestWirelessEndpointSsid(Check):
    name = "Wireless (dest) — Endpoint SSID"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("wireless_dst_endpoint_info")
        if not info:
            return _skip_no_dst_endpoint(self.name)
        wlan = info.get("wlan", {}) or {}
        body = (
            f"• SSID: {_v(wlan.get('ssid') or wlan.get('wlan_profile_name'))}\n"
            f"• WLAN profile: {_v(wlan.get('wlan_profile_name'))}\n"
            f"• Policy profile: {_v(wlan.get('policy_profile'))}\n"
            f"• WLAN ID: {_v(wlan.get('wlan_id'))}\n"
            f"• L2 auth: {_v(wlan.get('l2_auth') or wlan.get('layer_2_security'))}\n"
            f"• L3 auth: {_v(wlan.get('l3_auth') or wlan.get('layer_3_security'))}\n"
            f"• VLAN: {_v(wlan.get('vlan'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class EwDestWirelessEndpointMobility(Check):
    name = "Wireless (dest) — Endpoint Mobility"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("wireless_dst_endpoint_info")
        if not info:
            return _skip_no_dst_endpoint(self.name)
        m = info.get("mobility", {}) or {}
        body = (
            f"• Mobility role: {_v(m.get('role'))}\n"
            f"• Move count: {_v(m.get('move_count'))}\n"
            f"• Anchor IP: {_v(m.get('anchor_ip'))}\n"
            f"• Foreign IP: {_v(m.get('foreign_ip'))}\n"
            f"• Client roam type: {_v(m.get('roam_type'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class EwDestWirelessEndpointSession(Check):
    name = "Wireless (dest) — Session Manager"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("wireless_dst_endpoint_info")
        if not info:
            return _skip_no_dst_endpoint(self.name)
        s = info.get("session_manager", {}) or {}
        body = (
            f"• Auth status: {_v(s.get('auth_status') or s.get('status'))}\n"
            f"• Method: {_v(s.get('method'))}\n"
            f"• Domain: {_v(s.get('domain'))}\n"
            f"• Server policies: {_v(s.get('server_policies'))}\n"
            f"• Session ID: {_v(s.get('session_id') or s.get('common_session_id'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class EwDestWirelessEndpointFabric(Check):
    name = "Wireless (dest) — Fabric State"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("wireless_dst_endpoint_info")
        if not info:
            return _skip_no_dst_endpoint(self.name)
        f = info.get("fabric", {}) or {}
        body = (
            f"• VNID: {_v(f.get('vnid'))}\n"
            f"• SGT: {_v(f.get('sgt'))}\n"
            f"• RLOC: {_v(f.get('rloc'))}\n"
            f"• Fabric status: {_v(f.get('status'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class EwDestWirelessEndpointStats(Check):
    name = "Wireless (dest) — Endpoint Stats"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("wireless_dst_endpoint_info")
        if not info:
            return _skip_no_dst_endpoint(self.name)
        s = info.get("statistics", {}) or {}
        body = (
            f"• RSSI: {_v(s.get('rssi_dbm') or s.get('rssi_raw'))}\n"
            f"• SNR: {_v(s.get('snr_db') or s.get('snr_raw'))}\n"
            f"• Bytes RX/TX: {_v(s.get('bytes_rx'))} / {_v(s.get('bytes_tx'))}\n"
            f"• Packets RX/TX: {_v(s.get('packets_rx'))} / {_v(s.get('packets_tx'))}"
        )
        return CheckResult(CheckStatus.OK, body)


class EwDestWirelessAccessTunnel(Check):
    """Resolve the AP↔dest-Edge access tunnel and emit the dest AP node."""

    name = "Wireless (dest) — Access Tunnel (AP↔Edge)"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("wireless_dst_endpoint_info")
        dstxtr = ctx.state.get("ew_dstxtr")
        if not (info and dstxtr):
            return _skip_no_dst_endpoint(self.name)
        ap = info.get("ap", {}) or {}
        ap_ip = ap.get("ip_address")
        ap_name = ap.get("name")
        dst_hostname = getattr(dstxtr, "hostname", None)
        # WirelessEndpointMac.endpoint_info() only fills ap.name reliably;
        # ap.ip_address comes from the WLC's AP config (show ap config general).
        # Resolve it the same way the source-side WirelessWlcEndpointValidation
        # check does.
        if not ap_ip and ap_name:
            wlc_attrs = ctx.state.get("wireless_dst_wlc")
            endpoint = ctx.state.get("wireless_dst_endpoint")
            wlc_hostname = ctx.state.get("wireless_dst_wlc_hostname")
            if wlc_attrs and endpoint and wlc_hostname:
                try:
                    from traffic_flows.wirelessflows import wlcEndpointValidation
                    ap_config, _wlan_set, _ = wlcEndpointValidation(
                        0, wlc_hostname, endpoint,
                        bool(getattr(wlc_attrs, "ewlc", False)),
                        ctx.service,
                    )
                    ap_entry = (ap_config.get("ap_name") or {}).get(ap_name) or {}
                    ap_ip = ap_entry.get("ip_address")
                    ctx.state["wireless_dst_ap_config"] = ap_config
                except BaseException as e:
                    return CheckResult(
                        CheckStatus.WARN,
                        f"AP IP lookup via wlcEndpointValidation failed on "
                        f"WLC {wlc_hostname} for AP {ap_name}: "
                        f"{type(e).__name__}: {e}",
                    )
        if not (ap_ip and dst_hostname):
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — could not resolve AP IP for AP '{ap_name}' on "
                f"WLC {ctx.state.get('wireless_dst_wlc_hostname')} "
                f"(dest hostname: {dst_hostname}).",
            )
        tunnel_name = None
        phyport = None
        try:
            from wirelessmodules.accesstunnels import AccessTunnel
            at = AccessTunnel(dst_hostname)
            at.accesstunnelbyip(ap_ip, ctx.service)
            tunnel_name = getattr(at, "accesstunnelname", None)
            phy = getattr(at, "accesstunnelphyport", None) or []
            phyport = phy[0] if phy else None
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"Access-tunnel lookup on {dst_hostname} for AP {ap_ip} failed: "
                f"{type(e).__name__}: {e}",
            )

        ctx.state["wireless_dst_access_tunnel"] = tunnel_name
        ctx.state["wireless_dst_ap_phyport"] = phyport
        ctx.state["wireless_dst_ap_ip"] = ap_ip
        ctx.state["wireless_dst_ap_name"] = ap_name

        client = info.get("client", {}) or {}
        wlan = info.get("wlan", {}) or {}
        ssid = wlan.get("ssid") or wlan.get("wlan_profile_name")
        edge_label_parts = []
        if tunnel_name:
            edge_label_parts.append(tunnel_name.replace("AccessTunnel", "Ac"))
        if phyport:
            edge_label_parts.append(phyport)
        tunnel_edge_label = "  •  ".join(edge_label_parts) if edge_label_parts else "Access Tunnel"

        endpoint_spec = {
            "id": "dst-endpoint",
            "mac": client.get("mac_address"),
            "ip": client.get("ipv4_address"),
            "parent_node_id": "dst-ap",
            "port": ssid,
            "wireless": True,
            "vlan": (info.get("fabric") or {}).get("vnid"),
            "sgt": (info.get("fabric") or {}).get("sgt"),
        }
        body_lines = [f"AP↔dest-Edge tunnel: {tunnel_name or 'unknown'}"]
        if phyport:
            body_lines.append(f"Physical port: {phyport}")
        if ap_name:
            body_lines.append(f"AP: {ap_name} ({ap_ip})")
        if ssid:
            body_lines.append(f"SSID: {ssid}")
        return CheckResult(
            CheckStatus.OK,
            "\n".join(body_lines),
            data={
                "add_nodes": [{
                    "id": "dst-ap",
                    "role": "ap",
                    "label": ap_name or "AP",
                    "ip": ap_ip,
                    "connect_to": "dxtr",
                    "edge_label": tunnel_edge_label,
                }],
                "add_endpoint": endpoint_spec,
            },
        )


class EwDestWirelessFabricEdgeMac(Check):
    """L2LISP DB / SISF / MAC-table validation on the destination Edge."""

    name = "Wireless (dest) — Fabric Edge MAC Validation"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        info = ctx.state.get("wireless_dst_endpoint_info")
        dstxtr = ctx.state.get("ew_dstxtr")
        if not (info and dstxtr):
            return _skip_no_dst_endpoint(self.name)
        client = info.get("client", {}) or {}
        fabric = info.get("fabric", {}) or {}
        mac = client.get("mac_address")
        vnid = fabric.get("vnid")
        rloc = fabric.get("rloc")
        if not (mac and vnid):
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — dest MAC ({mac}) or VNID ({vnid}) missing.",
            )
        try:
            from traffic_flows.wirelessflows import (
                fabric_edge_mac_validation, WirelessRoamWarning,
            )
            fabric_edge_mac_validation(0, mac, vnid, rloc, dstxtr, ctx.service)
        except WirelessRoamWarning as w:
            return CheckResult(CheckStatus.WARN, str(w))
        except BaseException as e:
            from checks_ew_shared import _legacy_fail
            return _legacy_fail(e, "fabric_edge_mac_validation (dest)")
        return CheckResult(
            CheckStatus.OK,
            f"MAC {mac} in VNID {vnid} validated on {dstxtr.hostname} "
            f"(L2LISP DB, access-tunnel, SISF, MAC table CP_LEARN).",
        )


class EwDestWirelessRoamingHistory(Check):
    """Recent fabric roaming events for the destination endpoint MAC."""

    name = "Wireless (dest) — Roaming History"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        wlc = ctx.state.get("wireless_dst_wlc_hostname")
        info = ctx.state.get("wireless_dst_endpoint_info") or {}
        mac = (info.get("client") or {}).get("mac_address")
        if not (wlc and mac):
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — dest WLC ({wlc}) or MAC ({mac}) missing.",
            )
        try:
            from wirelessmodules.wirelesscore import WirelessEndpointMac
            hist = WirelessEndpointMac(wlc, mac)
            hist.fabric_roamming(ctx.service)
        except BaseException as e:
            from checks_ew_shared import _legacy_fail
            return _legacy_fail(e, "WirelessEndpointMac.fabric_roamming (dest)")
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


def build_ew_dest_wireless_chain() -> list:
    """Ordered chain to run when the dest endpoint is on an access-tunnel."""
    return [
        EwDestWirelessWlcDiscovery(),
        EwDestWirelessEndpointProfile(),
        EwDestWirelessEndpointSsid(),
        EwDestWirelessEndpointMobility(),
        EwDestWirelessEndpointSession(),
        EwDestWirelessEndpointFabric(),
        EwDestWirelessEndpointStats(),
        EwDestWirelessAccessTunnel(),
        EwDestWirelessFabricEdgeMac(),
        EwDestWirelessRoamingHistory(),
    ]
