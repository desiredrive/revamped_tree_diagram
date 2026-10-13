"""AP Onboarding step 2 — WLC parameters.

Two checks, both standalone: they describe the wireless controllers themselves
and say nothing about any particular AP. The AP's own state on the WLC is a
later step.

`ApWlcDiscovery` finds every WLC registered to the fabric site and resolves it
to a RSA hostname. `ApWlcProfile` then profiles each one -- platform, HA,
management interface, trustpoint and fabric state.

Unlike the DHCP/east-west wireless chain, which probes each candidate for a
client MAC and keeps only the controller serving that client, this profiles
*every* WLC at the site. Without an endpoint to disambiguate there is nothing
to choose between them, and on an HA pair or SSO+N+1 site the health of each
is worth seeing.
"""

from collections.abc import Mapping

from checks.ap_onboarding import _ApCheck
from checks.base import CheckResult, CheckStatus, RunContext


class ApWlcDiscovery(_ApCheck):
    """Find every Fabric WLC registered to this fabric site.

    Same CatC lookup the wireless chain uses, minus the endpoint probe: with no
    client MAC to disambiguate, every controller at the site is kept and
    profiled. Publishes `ap_wlc_candidates` as a list of (hostname, mgmt_ip).
    """

    name = "WLC Discovery"
    target_node_id = "xtr"
    running_note = "Querying Catalyst Center for fabric WLCs…"

    def _stop(self, ctx, reason: str, message: str) -> CheckResult:
        """FAIL here and skip every later AP check with one clear reason.

        Set when the flow genuinely cannot continue -- no WLC could be
        identified or reached. The chain does not break on FAIL, so without
        this every downstream check would fail on its own missing data and bury
        the actual cause under a wall of noise.
        """
        ctx.state["ap_stop"] = reason
        return CheckResult(CheckStatus.FAIL, message)

    def run_ap(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        catc = ctx.state.get("catc_name")
        # As in the wireless chain: /sda/fabricDevices expects the fabricSites
        # entry's `id`, not the siteId. Passing siteId silently returns empty.
        fabric_id = ctx.state.get("fabric_id")
        if not (service and catc and fabric_id):
            missing = [n for n, v in
                       (("service", service), ("catc_name", catc),
                        ("fabric_id", fabric_id)) if not v]
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — missing prerequisite(s): " + ", ".join(missing),
            )

        from radkit_cli import get_catc_api, get_hostname_from_mgmtip
        from catalystcenterapi.catcapi import get_network_device_byuuid
        from catalystcenterapi.wlc_fallback import find_fabric_wlcs

        api = (
            f"/dna/intent/api/v1/sda/fabricDevices?fabricId={fabric_id}"
            f"&deviceRoles=WIRELESS_CONTROLLER_NODE"
        )
        try:
            raw = get_catc_api(catc, api, service)
        except Exception:
            # Not fatal on its own -- the fallback below reaches the same answer
            # through endpoints this defect does not affect.
            raw = None

        response = (raw or {}).get("response") if isinstance(raw, dict) else None

        # (hostname, mgmt_ip) pairs, plus notes explaining anything dropped.
        pairs, errors, source = [], [], "fabricDevices"

        for entry in (response or []):
            uuid = entry.get("networkDeviceId")
            if not uuid:
                continue
            try:
                mgmt_ip = get_network_device_byuuid(uuid, catc, service)
            except Exception as e:
                errors.append(f"{uuid}: {type(e).__name__}: {e}")
                continue
            if mgmt_ip:
                pairs.append((None, mgmt_ip))
            else:
                errors.append(f"{uuid}: no management IP in Catalyst Center")

        if not pairs:
            # /sda/fabricDevices returns empty on some releases even when a
            # fabric WLC is assigned, so an empty primary is not evidence of a
            # missing controller. Rebuild the answer from the unaffected
            # endpoints before concluding anything.
            source = "fallback"
            site = ctx.state.get("xtr_site_hierarchy")
            if not site:
                return self._stop(
                    ctx,
                    "the fabric site hierarchy is unknown, so managed WLCs "
                    "cannot be tied to this site (see Profile XTR).",
                    "Cannot identify the Fabric WLC: /sda/fabricDevices returned "
                    "nothing and the fabric site hierarchy is unknown, so the "
                    "fallback lookup cannot run.",
                )
            found, reason = find_fabric_wlcs(catc, service, site)
            if not found:
                return self._stop(
                    ctx,
                    "no Fabric WLC could be identified (see WLC Discovery).",
                    "No Fabric WLC could be identified.\n\n"
                    f"• /sda/fabricDevices returned nothing (fabric_id {fabric_id}); "
                    "this endpoint has a known defect that returns empty even when "
                    "a WLC is assigned, so it was not trusted on its own.\n"
                    f"• Fallback: {reason}\n\n"
                    "An AP cannot join the wireless fabric without a WLC, so no "
                    "further AP onboarding checks can run.",
                )
            pairs = [(w.get("hostname"), w["mgmt_ip"]) for w in found]

        # Resolve each management IP to a RSA hostname; that is the name every
        # later check issues commands against, so a WLC we cannot address is of
        # no use even though CatC knows about it.
        candidates = []
        for hostname, mgmt_ip in pairs:
            try:
                resolved = get_hostname_from_mgmtip(mgmt_ip, service)
            except Exception as e:
                errors.append(f"{mgmt_ip}: {type(e).__name__}: {e}")
                continue
            if resolved:
                candidates.append((resolved, mgmt_ip))
            else:
                label = f"{hostname} ({mgmt_ip})" if hostname else str(mgmt_ip)
                errors.append(f"{label}: not in the RSA inventory")

        if not candidates:
            detail = "\n".join(errors) if errors else "no detail available"
            return self._stop(
                ctx,
                "no Fabric WLC could be reached through RSA (see WLC Discovery).",
                "Catalyst Center reported Fabric WLC(s), but none resolved to a "
                "device in the RSA inventory, so none can be queried:\n" + detail,
            )

        # Node ids are assigned here, once, so ApWlcProfile can target each
        # controller's own node rather than reporting onto the Edge.
        candidates = [
            (h, ip, ("wlc" if i == 0 else f"wlc{i}"))
            for i, (h, ip) in enumerate(candidates)
        ]
        ctx.state["ap_wlc_candidates"] = candidates

        # Draw each controller now, floating near the top. Fabric state is not
        # known until ApWlcProfile runs, so they start as plain "WLC".
        add_nodes = [{
            "id": node_id,
            "role": "wlc",
            "label": hostname,
            "ip": mgmt_ip,
            "floating": True,
            "tags": ["WLC"],
        } for hostname, mgmt_ip, node_id in candidates]

        lines = [f"• {h} ({ip})" for h, ip, _ in candidates]
        noise = ("\n\nUnresolved:\n" + "\n".join(errors)) if errors else ""
        plural = "" if len(candidates) == 1 else "s"
        via = "" if source == "fabricDevices" else (
            "\n\nFound via the fallback lookup (/network-device + "
            "/business/sda/device): /sda/fabricDevices returned nothing, which "
            "is a known defect on that endpoint rather than a missing WLC.")
        return CheckResult(
            CheckStatus.OK,
            f"{len(candidates)} Fabric WLC{plural} registered to this site:\n"
            + "\n".join(lines) + via + noise,
            data={"add_nodes": add_nodes},
        )




# The INFRA_VN L3 VNID is fixed by SD-Access; an AP onboards in it and nowhere
# else, so anything other than 4097 is a misconfiguration rather than a variant.
INFRA_VN_L3_VNID = 4097


def _infra_vn_l2_vnid(vnid_mapping: dict):
    """The INFRA_VN's L2 VNID, or None. Same selection as _infra_vn_lines."""
    l2 = (vnid_mapping or {}).get("l2_vnid") or {}
    for k, v in l2.items():
        if "INFRA_VN" in (v.get("name") or ""):
            try:
                return int(k)
            except (TypeError, ValueError):
                return k
    return None


def _infra_vn_subnet(vnid_mapping: dict):
    """The INFRA_VN's network as an ip_network, or None.

    Taken from the WLC's own IP Address and Subnet columns rather than from
    the VN name: the name embeds the subnet by Catalyst Center convention,
    not by guarantee.
    """
    l2 = (vnid_mapping or {}).get("l2_vnid") or {}
    for v in l2.values():
        if "INFRA_VN" not in (v.get("name") or ""):
            continue
        addr, mask = v.get("ip_address"), v.get("subnet")
        if not addr or addr == "0.0.0.0" or not mask:
            return None
        try:
            import ipaddress
            return ipaddress.ip_network(f"{addr}/{mask}", strict=False)
        except (ValueError, TypeError):
            return None
    return None


def _infra_vn_lines(vnid_mapping: dict):
    """Render the INFRA_VN VNIDs, or return an error string for a hard stop.

    Returns (error, lines). `error` is non-empty only when the flow must stop:
    the INFRA_VN is absent, or its L3 VNID is not 4097. Identifying the VN by
    name rather than by its L3 VNID is deliberate -- filtering on 4097 up front
    would make "no INFRA_VN at all" and "INFRA_VN with the wrong L3 VNID" look
    identical, and they need different remediation.
    """
    l2 = (vnid_mapping or {}).get("l2_vnid") or {}
    infra = {k: v for k, v in l2.items() if "INFRA_VN" in (v.get("name") or "")}

    if not infra:
        return (
            "No INFRA_VN is defined on the WLC. An AP onboards in the INFRA_VN, "
            "so it cannot join the fabric without one — add the INFRA_VN to this "
            "fabric site in Catalyst Center and re-provision the WLC.",
            [],
        )

    l2_vnid, attrs = next(iter(infra.items()))
    name = attrs.get("name")
    l3_vnid = attrs.get("l3_vnid")

    if not l3_vnid:
        return (
            f"The INFRA_VN ({name}) has an L2 VNID ({l2_vnid}) but no L3 VNID. "
            f"Both must be defined for an AP to onboard — re-provision the "
            f"INFRA_VN on this WLC.",
            [],
        )

    if l3_vnid != INFRA_VN_L3_VNID:
        return (
            f"The INFRA_VN ({name}) reports L3 VNID {l3_vnid}, but the INFRA_VN "
            f"L3 VNID can only be {INFRA_VN_L3_VNID}. This is a misconfiguration "
            f"— correct it in Catalyst Center and re-provision the WLC.",
            [],
        )

    # The network address and mask the WLC already reports for this VNID.
    # The VN
    # name embeds the subnet too (172_19_5_0-INFRA_VN), but that is a display
    # label: parsing it would break on any site whose naming differs. These
    # come from the parser's own fields.
    addr = attrs.get("ip_address")
    mask = attrs.get("subnet")
    subnet = ""
    if addr and addr != "0.0.0.0":
        try:
            import ipaddress
            net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
            subnet = str(net)
        except (ValueError, TypeError):
            subnet = f"{addr}/{mask}" if mask else addr

    lines = [
        "• INFRA VN VNIDs",
        f"    Layer 2: {l2_vnid}, Name: ({name})",
        f"    Layer 3: {l3_vnid}, Name: ({name})",
    ]
    if subnet:
        lines.append(f"    Subnet: {subnet}")
    lines.append(f"    CP Name: \"{attrs.get('control_plane_name')}\"")
    return "", lines


class ApWlcProfile(_ApCheck):
    """Fan out the per-WLC validation checks, one set per discovered controller.

    Does no validation itself -- each queued check owns one aspect and reports
    onto that controller's own topology node.
    """

    name = "WLC Parameters"
    target_node_id = "xtr"
    running_note = "Profiling each Fabric WLC…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        candidates = ctx.state.get("ap_wlc_candidates") or []
        if not candidates:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no WLC was discovered (see WLC Discovery).",
            )
        queued = []
        for hostname, mgmt_ip, node in candidates:
            queued.append(ApWlcCollect(hostname, mgmt_ip, node))
            queued.append(ApWlcPlatform(hostname, node))
            queued.append(ApWlcWmi(hostname, node))
            queued.append(ApWlcTrustpoint(hostname, node))
            queued.append(ApWlcFabricEnabled(hostname, node))
            queued.append(ApWlcControlPlanes(hostname, node))
            queued.append(ApWlcInfraVn(hostname, node))
            queued.append(ApWlcCountry(hostname, mgmt_ip, node))
        # Last: every collection has been attempted by the time this runs.
        queued.append(ApWlcCollectionVerdict())
        plural = "" if len(candidates) == 1 else "s"
        return CheckResult(
            CheckStatus.OK,
            f"Validating {len(candidates)} Fabric WLC{plural}; each controller's "
            "results appear on its own node.",
            data={"queue_checks": queued},
        )


class _PerWlcCheck(_ApCheck):
    """Base for the per-controller checks: carries the hostname and node id.

    Each subclass validates ONE aspect so it gets its own status badge, and so
    one failure does not mask the aspects after it -- the CLI's
    wlcInfoValidation aborts at the first problem, which hides everything
    downstream of it.
    """

    aspect = ""

    def __init__(self, hostname: str, node_id: str):
        self.hostname = hostname
        self.target_node_id = node_id
        self.name = f"WLC {self.aspect} — {hostname}"

    def _info(self, ctx):
        """The WirelessControllerInfo collected once by ApWlcCollect."""
        return (ctx.state.get("ap_wlc_collected") or {}).get(self.hostname)

    def _skip_no_data(self):
        return CheckResult(
            CheckStatus.SKIP,
            "Skipped — controller data was not collected (see WLC Collection).",
        )


class ApWlcCollect(_PerWlcCheck):
    """Run the WLC show commands once; every later check reads what it stored.

    Splitting the validation must not multiply device round-trips, so the five
    commands behind initial_commands() are issued here and once only. The raw
    `show wireless fabric summary` is kept alongside the parsed form because
    Genie drops Multi-Site control-plane rows (see wirelessmodules.multisite_cp).
    """

    aspect = "Collection"
    running_note = "Collecting platform, trustpoint and fabric state…"

    def __init__(self, hostname: str, mgmt_ip: str, node_id: str):
        super().__init__(hostname, node_id)
        self.mgmt_ip = mgmt_ip

    def run_ap(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if not service:
            ctx.state.setdefault("ap_wlc_uncollected", {})[self.hostname] = (
                "no RSA service")
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        from wirelessmodules.wirelesscore import WirelessControllerInfo
        from checks.shared import _legacy_fail

        try:
            info = WirelessControllerInfo(self.hostname)
            info.initial_commands(service)
        except BaseException as e:
            # Recorded rather than merely reported: one unreachable controller
            # is not a dead site (HA / N+1), so the decision to stop belongs to
            # ApWlcCollectionVerdict, which sees every controller's outcome.
            result = _legacy_fail(e, f"WLC {self.hostname} collection")
            ctx.state.setdefault("ap_wlc_uncollected", {})[self.hostname] = (
                f"{type(e).__name__}: {e}")
            return result

        # Raw text for the Multi-Site control-plane read; a failure here is not
        # fatal, the control-plane check reports the degraded parse instead.
        raw_fabric = None
        try:
            from radkit_cli import get_any_single_output
            raw_fabric = get_any_single_output(
                self.hostname, "show wireless fabric summary", service
            )
        except Exception:
            raw_fabric = None

        # Sixth command: certificate validity dates. `Certificate Info:
        # Available` says a certificate is installed, not that it is still
        # valid, and an expired one refuses every AP -- so the dates are worth
        # one extra round-trip. Keyed on the trustpoint name the previous
        # command reported; failure is non-fatal, the trustpoint check says the
        # dates could not be read rather than assuming they are fine.
        certs, cert_error = None, None
        trustpoint = _trustpoint_fields(
            getattr(info, "trustpoint_information", None)).get("trustpoint_name")
        if trustpoint:
            try:
                from radkit_cli import get_single_output_genie
                certs = get_single_output_genie(
                    self.hostname,
                    f"show crypto pki certificates {trustpoint}",
                    service,
                )
            except Exception as e:
                cert_error = f"{type(e).__name__}: {e}"
        else:
            cert_error = "no trustpoint name to query"

        ctx.state.setdefault("ap_wlc_collected", {})[self.hostname] = info
        ctx.state.setdefault("ap_wlc_raw_fabric", {})[self.hostname] = raw_fabric
        ctx.state.setdefault("ap_wlc_certificates", {})[self.hostname] = {
            "parsed": certs, "error": cert_error, "trustpoint": trustpoint,
        }
        ctx.state.setdefault("ap_wlc_profiles", {})[self.hostname] = {
            "mgmt_ip": self.mgmt_ip,
            "ewlc": bool(getattr(info, "ewlc", False)),
        }
        return CheckResult(
            CheckStatus.OK,
            f"Collected controller state from {self.hostname} ({self.mgmt_ip}).",
        )


# `show redundancy` reports a standalone controller with these operational
# modes. Anything else on a box configured for redundancy means the pair is not
# currently protecting anything.
_STANDALONE_RED_MODES = {"non-redundant", "simplex", "none", ""}


def _redundancy_verdict(ha: dict):
    """(degraded, line) for the redundancy row.

    `degraded` is True only when redundancy is *configured* but not operating:
    a genuinely standalone controller is normal, not a fault. Compares the
    configured mode against the operational one rather than inferring from
    hardware mode, because a chassis can be capable of pairing without being
    configured for it.
    """
    hw = (ha or {}).get("hw_mode")
    conf = ((ha or {}).get("conf_red_mode") or "").strip()
    oper = ((ha or {}).get("oper_red_mode") or "").strip()
    line = f"• Redundancy: {hw} operating as {oper or 'unknown'}"

    conf_standalone = conf.lower() in _STANDALONE_RED_MODES
    oper_standalone = oper.lower() in _STANDALONE_RED_MODES
    if conf and not conf_standalone and oper_standalone:
        return True, line + f" (configured for {conf})"
    return False, line


class ApWlcPlatform(_PerWlcCheck):
    """Platform, software version, uptime and redundancy state.

    Descriptive apart from redundancy: a controller configured as an HA pair
    but not currently operating as one still onboards APs, so it warns rather
    than fails -- but it is worth surfacing, since a failover would drop the AP
    sessions this flow is about to verify.
    """

    aspect = "Platform"
    running_note = "Reading platform and redundancy state…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        info = self._info(ctx)
        if info is None:
            return self._skip_no_data()
        plat = getattr(info, "platform_information", None) or {}
        ha = getattr(info, "ha_information", None) or {}
        ewlc = bool(getattr(info, "ewlc", False))
        degraded, red_line = _redundancy_verdict(ha)
        lines = [
            f"• Platform: {plat.get('platform')} (IOS-XE {plat.get('version')})",
            f"• Uptime: {plat.get('uptime')}",
            red_line,
            f"• Embedded WLC: {'yes' if ewlc else 'no'}",
        ]
        if degraded:
            lines.append(
                "\nHigh availability is configured on this controller but it is "
                "not currently operating as a redundant pair. AP onboarding is "
                "unaffected, but a failover would drop AP and client sessions — "
                "check the peer and the redundancy link.")
            return CheckResult(CheckStatus.WARN, "\n".join(lines))
        return CheckResult(CheckStatus.OK, "\n".join(lines))


def _wmi_line(i: dict) -> str:
    """One interface as a single line, for the multi-interface listing."""
    return (f"{i.get('interfacename')} (VLAN {i.get('vlanid')}) "
            f"{i.get('ipaddress')}/{i.get('netmask')}")


class ApWlcWmi(_PerWlcCheck):
    """Wireless management interface must be configured.

    An AP builds its CAPWAP tunnel to the WMI address, so which interface is
    reported matters. Both the CLI (wirelessflows.py) and this check take
    interfaces[0]; lispsessiontroubleshooting.py:1839 instead refuses to use
    the address at all when more than one is present. That refusal is the
    better instinct -- with several interfaces listed there is nothing in this
    output identifying which one serves the fabric -- so a multi-interface
    controller warns and lists them all rather than presenting the first as
    authoritative.
    """

    aspect = "Management Interface"
    running_note = "Checking the wireless management interface…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        info = self._info(ctx)
        if info is None:
            return self._skip_no_data()
        interfaces = (getattr(info, "wmi_information", None) or {}).get("interfaces") or []
        name = interfaces[0].get("interfacename") if interfaces else None
        if not name:
            return CheckResult(
                CheckStatus.FAIL,
                "Wireless Management Interface configuration is missing. "
                "Remediation: use the 'wireless management interface' command "
                "to recover.",
            )

        i = interfaces[0]
        lines = [
            f"• Interface: {name} (VLAN {i.get('vlanid')})",
            f"• Address: {i.get('ipaddress')} / {i.get('netmask')}",
            f"• MAC: {i.get('macaddress')}",
        ]

        if len(interfaces) > 1:
            others = "\n".join(f"    {_wmi_line(x)}" for x in interfaces[1:])
            lines.append(
                f"\nAlso listed:\n{others}\n\n{len(interfaces)} wireless "
                "management interfaces are present, and this output does not say "
                f"which one serves this fabric site. The details above are for "
                f"{name} (the first listed); an AP builds its CAPWAP tunnel to "
                "the management address, so confirm which interface applies "
                "before relying on them.")
            return CheckResult(CheckStatus.WARN, "\n".join(lines))

        return CheckResult(CheckStatus.OK, "\n".join(lines))


def _trustpoint_fields(raw):
    """`show wireless management trustpoint` as a dict, parsed or raw.

    Accepts the Mapping RADKit returns (a GenieParseResult, which is not a
    dict) and the raw output it substitutes when the parse does not apply.
    The command is a flat "Label : value" block, so recovering it is exact --
    no guessing, and no healthy controller reported as unconfigured.
    """
    # RADKit returns a GenieParseResult, which is a Mapping but NOT a dict:
    # `isinstance(x, dict)` is False for it while `.get()` works fine. Testing
    # for dict here reported a perfectly healthy controller as unconfigured.
    if isinstance(raw, Mapping):
        return raw
    if raw is None:
        return {}
    if isinstance(raw, (list, tuple)):
        text = "\n".join(str(line) for line in raw)
    else:
        text = str(raw)

    # "Trustpoint Name  : WLCv_WLC_TP" -> {"trustpoint_name": "WLCv_WLC_TP"}
    labels = {
        "trustpoint name": "trustpoint_name",
        "certificate info": "certificate_info",
        "certificate type": "certificate_type",
        "certificate hash": "certificate_hash",
        "private key info": "private_key_info",
        "fips suitability": "fips_suitability",
    }
    fields = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        key = labels.get(" ".join(label.split()).lower())
        if key and value.strip():
            fields[key] = value.strip()
    return fields


class ApWlcTrustpoint(_PerWlcCheck):
    """Wireless management trustpoint, its certificate, key and validity.

    The CLI checks two things: a trustpoint exists, and its certificate info
    reads "Available". Two more are checked here, both of which fail an AP join
    while leaving those two conditions satisfied:

      * the private key -- returned by the same command and ignored by the CLI.
        Without it the DTLS handshake cannot complete.
      * the validity dates -- "Available" is true of an expired certificate,
        so this is the difference between a certificate being installed and
        being usable.
    """

    aspect = "Trustpoint"
    running_note = "Checking the wireless management trustpoint…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        info = self._info(ctx)
        if info is None:
            return self._skip_no_data()
        # Genie's ShowWirelessManagementTrustPoint keys: trustpoint_name,
        # certificate_info, private_key_info, fips_suitability.
        #
        # RADKit does not always hand back the parsed dict: when the genie parse
        # does not apply it returns the device's raw output instead, as a list
        # of lines. The device is fine and the text is right there, so read it
        # rather than reporting a healthy controller as having no trustpoint.
        tp = _trustpoint_fields(getattr(info, "trustpoint_information", None))
        name = tp.get("trustpoint_name")
        cert = tp.get("certificate_info")
        key = tp.get("private_key_info")

        if not name:
            return CheckResult(
                CheckStatus.FAIL,
                "No wireless management trustpoint found. An AP will not join "
                "the controller without one — configure the wireless management "
                "trustpoint on this WLC.",
            )
        if cert != "Available":
            return CheckResult(
                CheckStatus.FAIL,
                f"Trustpoint {name} is configured but its certificate details "
                f"are unavailable (state: {cert}). Re-install or re-enrol the "
                "certificate on this WLC.",
            )
        if key and key != "Available":
            return CheckResult(
                CheckStatus.FAIL,
                f"Trustpoint {name} has a certificate, but its private key is "
                f"unavailable (state: {key}). The DTLS handshake an AP uses to "
                "join cannot complete without it — regenerate the key and "
                "re-enrol the certificate on this WLC.",
            )

        lines = [
            f"• Trustpoint: {name}",
            f"• Certificate: {cert}",
            f"• Private key: {key or 'not reported'}",
        ]
        if tp.get("certificate_type"):
            lines.append(f"• Type: {tp['certificate_type']}")

        return self._with_validity(ctx, name, lines)

    def _with_validity(self, ctx, name, lines) -> CheckResult:
        """Append the certificate validity verdict to an otherwise-passing check.

        Kept separate so a failure to read the dates degrades to a warning
        rather than masking the trustpoint state that was read successfully.
        """
        from wirelessmodules.wlc_certificate import assess

        entry = (ctx.state.get("ap_wlc_certificates") or {}).get(self.hostname) or {}
        parsed, error = entry.get("parsed"), entry.get("error")

        if not parsed:
            lines.append(
                f"\nCertificate validity could not be checked ({error or 'no data'}). "
                "An expired certificate still reports as Available, so this does "
                "not confirm the certificate is usable — verify it manually with "
                f"'show crypto pki certificates {name}'.")
            return CheckResult(CheckStatus.WARN, "\n".join(lines))

        verdict = assess(parsed, trustpoint=name)
        state, detail = verdict["state"], verdict["detail"]
        lines.append(f"• Validity: {detail}")

        if state == "expired":
            lines.append(
                "\nThe controller's management certificate has expired. An AP "
                "cannot complete the DTLS handshake against an expired "
                "certificate, so no AP will join this controller until it is "
                "renewed.")
            return CheckResult(CheckStatus.FAIL, "\n".join(lines))

        if state == "not_yet_valid":
            lines.append(
                "\nThe certificate's start date is in the future. This is "
                "usually a controller clock problem rather than a certificate "
                "problem — check NTP on the WLC; APs will fail to join while "
                "this persists.")
            return CheckResult(CheckStatus.FAIL, "\n".join(lines))

        if state == "expiring":
            lines.append(
                "\nAP joins are unaffected today, but every AP at this site "
                "will fail to join once this certificate expires. Renew it "
                "before then.")
            return CheckResult(CheckStatus.WARN, "\n".join(lines))

        if state == "unknown":
            lines.append(
                "\nThe certificate was returned but its validity dates could "
                "not be read, so expiry has not been confirmed.")
            return CheckResult(CheckStatus.WARN, "\n".join(lines))

        return CheckResult(CheckStatus.OK, "\n".join(lines))


class ApWlcFabricEnabled(_PerWlcCheck):
    """The controller must be enabled for fabric operations.

    On success this is also where the node becomes a Fabric WLC on the canvas:
    the cyan chassis is a statement about fabric state, so it is emitted by the
    check that establishes it rather than at discovery time.

    A missing status is reported separately from a reported "Disabled". The
    parser only sets `fabric_status` when it matches the status line, so an
    unparseable or truncated output leaves the key absent -- and calling that
    "not enabled" would send someone to configure 'wireless fabric' on a
    controller that may already have it.
    """

    aspect = "Fabric State"
    running_note = "Checking fabric enablement…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        info = self._info(ctx)
        if info is None:
            return self._skip_no_data()
        state = getattr(info, "fabric_state", None) or {}
        status = state.get("fabric_status")

        # Recorded either way so ApWlcCollectionVerdict can tell whether any
        # controller at the site is fabric-enabled.
        ctx.state.setdefault("ap_wlc_fabric_status", {})[self.hostname] = status

        if status is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"Fabric status was not returned by 'show wireless fabric "
                f"summary' on {self.hostname}, so fabric enablement could not "
                "be confirmed. This is not evidence the controller is "
                "misconfigured — verify manually on the device before treating "
                "it as one.",
            )

        if status != "Enabled":
            return CheckResult(
                CheckStatus.FAIL,
                f"{self.hostname} is not enabled for fabric operations "
                f"(status: {status}). Remediation: configure 'wireless fabric' "
                "on the controller.",
            )

        return CheckResult(
            CheckStatus.OK,
            f"• Fabric: {status}",
            data={"mark_fabric_wlc": [self.target_node_id]},
        )


def _cp_line(c: dict) -> str:
    """One control plane as a display line."""
    return f"    CP Name: \"{c['name']}\" — {c['ip_address']} ({c['status']})"


def _cp_is_up(c: dict) -> bool:
    return (c.get("status") or "").strip().lower() == "up"


class ApWlcControlPlanes(_PerWlcCheck):
    """LISP control planes the WLC registers wireless clients to.

    Reads the raw command output rather than the parsed dict: Genie's
    ShowWirelessFabricSummary matches the control-plane name with \\S+, so any
    control plane whose name contains a space -- which Multi-Site Remote Border
    names routinely do -- is silently dropped. Counting from the parsed dict
    would under-report those without saying so.

    Status is judged, not merely printed. Only the site-local control planes
    can register this site's clients, so they decide the verdict; a Multi-Site
    control plane serves a remote site and its being down does not stop an AP
    onboarding here, so it is reported without affecting the result.

    A down session is graded and the flow continues; no LISP session
    troubleshooting is run from here. That diagnostic registers an EID, and at
    this point in the flow no AP has onboarded, so there is nothing to register
    -- it belongs to a later step, once an EID exists.
    """

    aspect = "Control Planes"
    running_note = "Reading the WLC's LISP control planes…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        info = self._info(ctx)
        if info is None:
            return self._skip_no_data()

        from wirelessmodules.multisite_cp import split_control_planes

        raw = (ctx.state.get("ap_wlc_raw_fabric") or {}).get(self.hostname)
        local, multisite = split_control_planes(raw or "")

        if not (local or multisite):
            return CheckResult(
                CheckStatus.FAIL,
                "No LISP control planes are defined on the WLC. Wireless clients "
                "cannot be registered to the fabric without one — re-provision "
                "the WLC from Catalyst Center.",
            )

        lines = ["• Site control planes"]
        lines += [_cp_line(c) for c in local] or ["    none"]
        if multisite:
            # Named after the remote site they serve; present when this site is
            # reached through a Multi-Site Remote Border.
            lines.append("• Multi-Site Control Planes")
            lines += [_cp_line(c) for c in multisite]

        ctx.state.setdefault("ap_wlc_control_planes", {})[self.hostname] = {
            "local": local, "multisite": multisite,
        }

        up = [c for c in local if _cp_is_up(c)]
        down = [c for c in local if not _cp_is_up(c)]

        if not local:
            # Multi-Site CPs exist but no site-local one: nothing here can
            # register a client that joins at this site.
            return CheckResult(
                CheckStatus.FAIL,
                "\n".join(lines) + "\n\nNo site control plane is defined on "
                "this WLC — only Multi-Site control planes, which serve remote "
                "sites. A client joining at this site has no control plane to "
                "register with; re-provision the WLC from Catalyst Center.",
            )

        if not up:
            return CheckResult(
                CheckStatus.FAIL,
                "\n".join(lines) + f"\n\nNone of the {len(local)} site control "
                "plane(s) is Up, so this WLC cannot register wireless clients "
                "to the fabric and no AP joining it will onboard a client. "
                "Check the control plane node(s) and the WLC's reachability to "
                "them.",
            )

        if down:
            names = ", ".join(f"{c['ip_address']} ({c['status']})" for c in down)
            return CheckResult(
                CheckStatus.WARN,
                "\n".join(lines) + f"\n\n{len(up)} of {len(local)} site "
                f"control planes is Up. Client registration works today, but "
                f"the redundancy is gone — {names} should be restored.",
            )

        return CheckResult(CheckStatus.OK, "\n".join(lines))


class ApWlcInfraVn(_PerWlcCheck):
    """INFRA_VN VNIDs -- the VN an AP onboards in.

    Hard-stops on a missing INFRA_VN, a missing L3 VNID, or an L3 VNID other
    than 4097; see _infra_vn_lines for why each is fatal rather than a warning.
    """

    aspect = "INFRA VN"
    running_note = "Checking the INFRA_VN VNIDs…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        info = self._info(ctx)
        if info is None:
            return self._skip_no_data()
        # The mapping lives inside the parsed fabric summary, not on its own
        # attribute.
        vnid_mapping = ((getattr(info, "fabric_state", None) or {})
                        .get("fabric_vnid_mapping") or {})
        error, lines = _infra_vn_lines(vnid_mapping)
        if error:
            # Recorded rather than stopping here: this controller cannot onboard
            # an AP, but another WLC at the site may be correctly provisioned.
            # ApWlcCollectionVerdict owns the site-wide decision, the same way
            # it does for collection and fabric state.
            ctx.state.setdefault("ap_wlc_bad_infra_vn", {})[self.hostname] = error
            return CheckResult(CheckStatus.FAIL, error)
        # The L2 VNID is the instance ID the AP's VLAN is derived from on the
        # edge (see ApInfraVnVlan). The L2LISP instance mapping to a fabric site
        # is always the same, so any correctly-provisioned controller is
        # authoritative for the site -- the first one to get here wins, and a
        # later controller disagreeing is itself the anomaly.
        l2_vnid = _infra_vn_l2_vnid(vnid_mapping)
        if l2_vnid is not None:
            ctx.state.setdefault("ap_infra_l2_vnid", l2_vnid)
        # Published for ApSviState, which grades the edge's gateway against
        # the subnet the controller advertises for this VN.
        subnet = _infra_vn_subnet(vnid_mapping)
        if subnet is not None:
            ctx.state.setdefault("ap_infra_subnet", str(subnet))
        return CheckResult(CheckStatus.OK, "\n".join(lines))


class ApWlcCountry(_PerWlcCheck):
    """Regulatory countries configured on the controller.

    An AP only brings up a radio in a country the controller is configured
    for. Join and country are separate failures, and the second is the
    quieter one: an AP whose country is not configured here joins, registers
    and serves nothing, because every radio stays down. That looks like an RF
    problem rather than a configuration one.

    Read over NETCONF (`country-oper`) rather than from
    `show wireless country configured`. The list is keyed on the country code,
    but which code to ask for is not known until the AP's own code has been
    read, so it is fetched whole -- it is one entry per configured country,
    not one per AP, and stays small.

    Opt-in with the rest of the NETCONF reads: with no credentials set this
    SKIPs and nothing else in the run changes.
    """

    aspect = "Country"
    running_note = "Reading the configured regulatory countries…"

    def __init__(self, hostname: str, mgmt_ip: str, node_id: str):
        super().__init__(hostname, node_id)
        self.mgmt_ip = mgmt_ip

    def run_ap(self, ctx: RunContext) -> CheckResult:
        from netconf_client import (
            NetconfError, country_oper, credentials, dig, session_for_wlc,
        )

        if not credentials():
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — NETCONF is not configured. Set NETCONF_USERNAME "
                "and NETCONF_PASSWORD (and NETCONF_PORT if the controllers do "
                "not listen on 830) to read the configured countries.",
            )

        session = session_for_wlc(self.mgmt_ip)
        if session is None:
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — no management address is known for "
                f"{self.hostname}.")

        try:
            entries = country_oper(session)
        except NetconfError as e:
            # The controller not answering NETCONF says nothing about its
            # country configuration, and the rest of this controller's
            # validation came over RADKit and is unaffected.
            return CheckResult(
                CheckStatus.WARN,
                f"The configured countries could not be read from "
                f"{self.hostname} — {e}")

        if not entries:
            return CheckResult(
                CheckStatus.WARN,
                f"{self.hostname} reports no configured regulatory country. "
                f"No AP can bring up a radio until one is configured.")

        codes = []
        lines = []
        for entry in entries:
            code = (dig(entry, "country-code", default="") or "").strip()
            if not code:
                continue
            codes.append(code)
            name = dig(entry, "country-string", default="") or ""
            lines.append(f"  {code:4} {name}")
            # The regulatory domain strings say which AP hardware variants the
            # country accepts; an AP whose domain is absent here is rejected
            # even though the country itself is configured.
            for band, leaf in (("802.11b/g", "reg-domain-str-80211bg"),
                               ("802.11a", "reg-domain-str-80211a")):
                domains = (dig(entry, leaf, default="") or "").strip()
                if domains:
                    # The device pads each domain to a fixed width and
                    # separates them with commas, so the raw string arrives
                    # as "    -AN^,    -NA^". Collapsed here rather than
                    # printed as-is.
                    domains = ", ".join(
                        d.strip() for d in domains.split(",") if d.strip())
                    lines.append(f"       {band:10} {domains}")

        # Published for the AP-side country check: the AP's own code is read
        # off its CAPWAP record later in the run, and graded against this.
        ctx.state.setdefault("ap_wlc_countries", {})[self.hostname] = codes

        plural = "y" if len(codes) == 1 else "ies"
        return CheckResult(
            CheckStatus.OK,
            f"{len(codes)} regulatory countr{plural} configured on "
            f"{self.hostname}:\n\n" + "\n".join(lines),
            data={"countries": codes},
        )


class ApWlcCollectionVerdict(_ApCheck):
    """Site-wide verdicts once every controller has been profiled.

    Three questions only answerable across all controllers: was any reached, is
    any of them fabric-enabled, and does any fabric-enabled one have a usable
    INFRA_VN. Each is fatal to the flow when the answer is "none", and none can
    be decided by a per-controller check.

    They are evaluated in that order because each narrows the previous: an
    unreachable controller has no fabric state, and a controller outside the
    fabric cannot onboard an AP whatever its INFRA_VN says.

    == Collection ==

    An unreachable controller is absence of evidence, not evidence of a fault:
    it may be perfectly healthy. On an HA pair or an N+1 site the remaining
    controllers still describe the site, so one failure does not stop the flow.

    Every controller failing is different -- there is then no WLC state at all
    behind the later steps, and an all-clear from them would be built on
    nothing. That sets `ap_stop`.

    Runs last in the queued batch, so it sees all outcomes. Reports on the XTR
    rather than a controller node: the verdict is about the site.
    """

    name = "WLC Site Verdict"
    target_node_id = "xtr"
    running_note = "Confirming the site has a usable Fabric WLC…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        candidates = ctx.state.get("ap_wlc_candidates") or []
        if not candidates:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no WLC was discovered (see WLC Discovery).",
            )

        failed = ctx.state.get("ap_wlc_uncollected") or {}
        collected = [h for h, _, _ in candidates if h not in failed]
        total = len(candidates)

        if not collected:
            detail = "\n".join(f"• {h}: {why}" for h, why in failed.items())
            ctx.state["ap_stop"] = (
                "no Fabric WLC could be reached (see WLC Collection Verdict)."
            )
            return CheckResult(
                CheckStatus.FAIL,
                f"None of the {total} discovered Fabric WLC(s) could be "
                f"reached:\n{detail}\n\nWithout controller state there is "
                "nothing for the later AP onboarding checks to verify, so they "
                "are skipped. Confirm the controllers are reachable through "
                "RADKit and re-run.",
            )

        if failed:
            detail = "\n".join(f"• {h}: {why}" for h, why in failed.items())
            return CheckResult(
                CheckStatus.WARN,
                f"{len(collected)} of {total} Fabric WLC(s) collected; the flow "
                f"continues on those.\n\nNot reached:\n{detail}\n\nIf the AP is "
                "expected to join an unreachable controller, its state was not "
                "verified here.",
            )

        return self._fabric_verdict(ctx, candidates, collected)

    def _fabric_verdict(self, ctx, candidates, collected) -> CheckResult:
        """Every reachable controller collected -- is any of them in the fabric?

        A single non-fabric controller is not fatal (another may serve the AP),
        but if none at the site is fabric-enabled there is no fabric WLC for an
        AP to join at all, and the later steps have nothing to verify.
        """
        status = ctx.state.get("ap_wlc_fabric_status") or {}
        enabled = [h for h in collected if status.get(h) == "Enabled"]
        total = len(candidates)
        plural = "" if total == 1 else "s"

        if not enabled:
            detail = "\n".join(
                f"• {h}: {status.get(h) or 'status not returned'}"
                for h in collected)
            ctx.state["ap_stop"] = (
                "no fabric-enabled WLC was found at this site "
                "(see WLC Site Verdict).")
            return CheckResult(
                CheckStatus.FAIL,
                f"None of the reachable Fabric WLC{plural} is enabled for "
                f"fabric operations:\n{detail}\n\nAn AP joins the wireless "
                "fabric through a fabric-enabled controller, so there is "
                "nothing for the later AP onboarding checks to verify. "
                "Configure 'wireless fabric' on the controller serving this "
                "site and re-run.",
            )

        if len(enabled) < len(collected):
            not_enabled = "\n".join(
                f"• {h}: {status.get(h) or 'status not returned'}"
                for h in collected if h not in enabled)
            return self._infra_vn_verdict(
                ctx, enabled,
                CheckResult(
                    CheckStatus.WARN,
                    f"{len(enabled)} of {len(collected)} reachable controller(s) "
                    f"are fabric-enabled; the flow continues on those.\n\n"
                    f"Not fabric-enabled:\n{not_enabled}",
                ))

        return self._infra_vn_verdict(
            ctx, enabled,
            CheckResult(
                CheckStatus.OK,
                f"All {total} discovered Fabric WLC{plural} collected and "
                "fabric-enabled.",
            ))

    def _infra_vn_verdict(self, ctx, enabled, otherwise) -> CheckResult:
        """Does any fabric-enabled controller have a usable INFRA_VN?

        Only the fabric-enabled controllers are considered: one that is not in
        the fabric has already been excluded, and its INFRA_VN state is moot.

        An AP onboards in the INFRA_VN, so a controller without a usable one
        cannot onboard an AP -- but a sibling WLC may be fine. Fatal only when
        no fabric-enabled controller has one, which leaves the later steps
        nothing to verify. `otherwise` is the verdict to return when at least
        one controller is usable.
        """
        bad = ctx.state.get("ap_wlc_bad_infra_vn") or {}
        broken = [h for h in enabled if h in bad]
        if not broken:
            return otherwise

        detail = "\n".join(f"• {h}: {bad[h]}" for h in broken)

        if len(broken) == len(enabled):
            ctx.state["ap_stop"] = (
                "no fabric-enabled WLC has a usable INFRA_VN "
                "(see WLC Site Verdict).")
            plural = "" if len(broken) == 1 else "s"
            return CheckResult(
                CheckStatus.FAIL,
                f"No fabric-enabled Fabric WLC has a usable INFRA_VN:\n{detail}"
                f"\n\nAn AP onboards in the INFRA_VN, so the controller{plural} "
                "cannot onboard one and the later AP onboarding checks have "
                "nothing to verify. Correct the INFRA_VN in Catalyst Center and "
                "re-provision.",
            )

        usable = len(enabled) - len(broken)
        return CheckResult(
            CheckStatus.WARN,
            f"{usable} of {len(enabled)} fabric-enabled controller(s) have a "
            f"usable INFRA_VN; the flow continues on those.\n\n"
            f"Unusable INFRA_VN:\n{detail}",
        )
