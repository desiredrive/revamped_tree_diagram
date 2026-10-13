"""AP Onboarding step 2 — WLC parameters.

`ApWlcDiscovery` and `ApWlcProfile` are standalone: they describe the wireless
controllers themselves and say nothing about any particular AP. `ApWlcApState`
is the manifest's step 5 and does the opposite -- it looks up one AP on each
controller and reports what that controller believes about it.

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
        # Last: every collection has been attempted by the time this runs.
        queued.append(ApWlcCollectionVerdict())
        plural = "" if len(candidates) == 1 else "s"
        return CheckResult(
            CheckStatus.OK,
            f"Validating {len(candidates)} Fabric WLC{plural}; each controller's "
            "results appear on its own node.",
            data={"queue_checks": queued},
        )


class ApWlcApStateProfile(_ApCheck):
    """Fan out the manifest's step 5: what each controller believes about this AP.

    Separate from `ApWlcProfile`, which runs at step 2, because this half has
    to run after the wired validations. Step 2 answers "are these controllers
    healthy", which everything downstream is built on -- `ApInfraVnVlan` takes
    the AP's onboarding VLAN from the L2 instance it reads. Step 5 answers
    "did this AP join", which is a conclusion about the wired path, not an
    input to it: a controller that has never heard of the AP tells you
    nothing until you know whether the port, the VLAN, the ACLs and the LISP
    registrations between them are sound.

    Running late also makes the uptime line readable. It names the AP as CDP
    saw it on the wire, and `ap_cdp_neighbor` is published by the step-3 edge
    checks -- so queued at step 2 the name was always empty.
    """

    name = "WLC AP State"
    target_node_id = "xtr"
    running_note = "Checking the AP's state on each controller…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        candidates = ctx.state.get("ap_wlc_candidates") or []
        if not candidates:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no WLC was discovered (see WLC Discovery).",
            )
        queued = []
        for hostname, mgmt_ip, node in candidates:
            # Ordered as the operator reads them: uptime, then the
            # controller's country configuration, then the AP's own config.
            queued.append(ApWlcApUptime(hostname, node))
            # Next to the uptime it qualifies: a recent association means more
            # when you know whether the AP has ever fallen over.
            queued.append(ApWlcApCrash(hostname, node))
            # Before the join itself: a discovery failure is the earlier
            # stage, and explains a join that never followed.
            queued.append(ApWlcApDiscovery(hostname, node))
            # After discovery, and needing the radio MAC ApWlcApState saves:
            # this table is keyed on the AP name and radio MAC, not the
            # Ethernet MAC the rest of the chain uses.
            queued.append(ApWlcApHistory(hostname, node))
            # The session the join rides on, after the history that explains
            # a session that keeps dropping.
            queued.append(ApWlcApDtls(hostname, node))
            queued.append(ApWlcApCountry(hostname, node))
            queued.append(ApWlcApState(hostname, node))
            # After the AP's state: the control-plane set it is configured
            # against, which is what the registration checks below resolve.
            # Runs last of the per-controller checks because an AP that is
            # not registered has already stopped the run by here.
            queued.append(ApWlcFabricControlPlane(hostname, node))
            # Item 1: the sessions carrying the registration to the control
            # planes the check above resolved.
            queued.append(ApWlcCpLispSession(hostname, node))
        # Last: every controller has been looked at by the time this runs.
        queued.append(ApWlcApStateVerdict())
        plural = "" if len(candidates) == 1 else "s"
        return CheckResult(
            CheckStatus.OK,
            f"Looking the AP up on {len(candidates)} Fabric WLC{plural}; each "
            "controller's results appear on its own node.",
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


def _ap_summary_rows(parsed):
    """`show ap summary` as {ap name: row}, or None if it did not parse.

    Genie keys the summary on the AP name: {'ap_name': {'AP-002': {...}}}.
    Returns None rather than {} when the shape is wrong, so the caller can
    distinguish "this controller has no APs" -- a real and informative answer
    -- from "the output was not what we expected".
    """
    # A GenieParseResult is a Mapping but NOT a dict; testing for dict here
    # would discard a perfectly good parse. See _trustpoint_fields above.
    if not isinstance(parsed, Mapping):
        return None
    rows = parsed.get("ap_name")
    if rows is None:
        # The parser emits no `ap_name` key at all when no AP is joined.
        return {} if "ap_neighbor_count" in parsed else None
    if not isinstance(rows, Mapping):
        return None
    return rows


def _find_ap_by_ethernet_mac(rows, ap_mac):
    """The (name, row) whose Ethernet MAC is `ap_mac`, or (None, None).

    Matches on the Ethernet MAC only. That is the MAC the edge switch sees on
    the wire and the one the rest of the AP chain carries, so it is the value
    the user supplies; the radio MAC is a different address on the same AP and
    matching it here would make two different inputs look equivalent when the
    rest of the chain can only act on one of them.

    Both sides are normalised before comparing: Genie prints the dotted-quad
    form, and a MAC typed with colons or in upper case is the same address.
    """
    from checks.shared import normalize_mac

    want = normalize_mac(ap_mac)
    for name, row in rows.items():
        if not isinstance(row, Mapping):
            continue
        if normalize_mac(row.get("ethernet_mac")) == want:
            return name, row
    return None, None


def _ap_config_general(wlc_hostname, ap_name, service):
    """`show ap name <ap> config general` as (fields, error).

    Reuses wirelessmodules.AccessPointInfo, which already issues exactly this
    command -- the per-AP collection the east-west wireless chain uses. Only
    one of the pair is ever non-None.
    """
    from wirelessmodules.accesspointinfo import AccessPointInfo

    try:
        info = AccessPointInfo(wlc_hostname)
        info.apconfiggeneral(ap_name, service)
        parsed = info.apconfiggeneral
    except BaseException as e:
        return None, f"{type(e).__name__}: {e}"

    if not isinstance(parsed, Mapping):
        return None, "the output did not parse into the expected shape"
    # Keyed on the AP name, the same way the summary is.
    by_name = parsed.get("ap_name")
    if isinstance(by_name, Mapping):
        entry = by_name.get(ap_name)
        if isinstance(entry, Mapping):
            return entry, None
        # The controller echoes the name it knows; if that differs in case
        # from the summary's, take the single entry rather than report
        # nothing.
        if len(by_name) == 1:
            only = next(iter(by_name.values()))
            if isinstance(only, Mapping):
                return only, None
    return None, "the output did not contain this AP's configuration"


class ApWlcApState(_PerWlcCheck):
    """Manifest step 5 — what this controller believes about the AP itself.

    Every other per-WLC check here describes the controller. This one answers
    the question the rest of the AP chain is in service of: has the AP joined,
    and did it land on the intended configuration. An AP that never joined
    makes every ACL, SGACL and LISP finding downstream a description of a path
    nothing is using.

    Two commands, in this order and for a reason:

      `show ap summary`                       one row per joined AP, carrying
                                              the Ethernet MAC. The AP chain
                                              learns that MAC from the edge
                                              switch -- it is what a switch
                                              sees on the wire -- while every
                                              per-AP command on the controller
                                              is keyed on the AP's *name*.
                                              This row is the bridge.

      `show ap name <name> config general`    the tags, profiles, country and
                                              mode, none of which appear in
                                              the summary.

    The AP being absent from the summary is the single most informative
    outcome and is not an error: it is the answer "this AP has not joined this
    controller", which on a multi-controller site is also the normal answer
    from every controller but one.
    """

    aspect = "AP State"
    running_note = "Looking the AP up on the controller…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        from checks.shared import normalize_mac

        service = ctx.service
        if not service:
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        ap_mac = normalize_mac(ctx.payload.get("mac"))
        if not ap_mac:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no AP MAC was supplied, so there is nothing to "
                "look up on the controller.")

        from radkit_cli import get_single_output_genie

        try:
            parsed = get_single_output_genie(
                self.hostname, "show ap summary", service)
        except BaseException as e:
            # One controller refusing the command is not a verdict on the AP:
            # it may well be joined to a different controller at this site.
            return CheckResult(
                CheckStatus.WARN,
                f"`show ap summary` could not be read from {self.hostname} — "
                f"{type(e).__name__}: {e}")

        rows = _ap_summary_rows(parsed)
        if rows is None:
            return CheckResult(
                CheckStatus.WARN,
                f"`show ap summary` from {self.hostname} did not parse into "
                f"the expected shape, so the AP could not be looked up.")

        name, row = _find_ap_by_ethernet_mac(rows, ap_mac)
        if not name:
            joined = len(rows)
            # Deliberately not a FAIL. A FAIL from an _ApCheck sets `ap_stop`
            # and skips every check after it, and on a site with more than one
            # controller the AP is absent from all but one of them by
            # definition. ApWlcApStateVerdict owns the site-wide decision.
            ctx.state.setdefault("ap_wlc_ap_absent", {})[self.hostname] = ap_mac
            return CheckResult(
                CheckStatus.WARN,
                f"No AP with Ethernet MAC {ap_mac} is joined to "
                f"{self.hostname}.\n\n"
                f"{joined} AP{'' if joined == 1 else 's'} "
                f"{'is' if joined == 1 else 'are'} joined to this controller. "
                f"The lookup matches the Ethernet MAC, which is what the edge "
                f"switch sees on the wire; if the value supplied was the AP's "
                f"radio MAC it will not match here even when the AP is "
                f"joined.")

        return self._describe(ctx, service, name, row, ap_mac)

    def _describe(self, ctx, service, name, row, ap_mac) -> CheckResult:
        """Render the AP's state, pulling tags and profiles from the AP itself."""
        from radkit_cli import get_single_output_genie
        from checks.shared import normalize_mac

        state = (row.get("state") or "").strip()
        # Published for the site-wide verdict and for later checks that need
        # to know the AP reached a controller at all.
        ctx.state.setdefault("ap_wlc_joined_on", []).append(self.hostname)
        ctx.state.setdefault("ap_wlc_ap_name", name)
        radio_mac = (row.get("radio_mac") or "").strip()
        if radio_mac:
            ctx.state.setdefault("ap_wlc_radio_mac", radio_mac)
        ap_ip = (row.get("ap_ip_address") or "").strip()
        if ap_ip:
            ctx.state.setdefault("ap_wlc_ap_ip", ap_ip)

        lines = [
            f"{name} is joined to {self.hostname}.",
            "",
            f"  State:         {state or '—'}",
            f"  Model:         {row.get('ap_model') or '—'}",
            f"  Ethernet MAC:  {row.get('ethernet_mac') or '—'}",
            f"  Radio MAC:     {radio_mac or '—'}",
            f"  IP address:    {ap_ip or '—'}",
            f"  Country:       {row.get('country') or '—'}"
            f"   Regulatory domain: {row.get('regulatory_domain') or '—'}",
            f"  Location:      {row.get('location') or '—'}",
        ]

        # The tags and profiles are the half of step 5 the summary cannot
        # answer, and they are per-AP rather than per-controller.
        cfg, cfg_error = _ap_config_general(self.hostname, name, service)
        if cfg:
            country = (cfg.get("country_code") or "").strip()
            if country:
                # Graded by ApWlcApCountry against the controller's own list.
                ctx.state.setdefault("ap_wlc_country", {})[self.hostname] = country
            ctx.state.setdefault("ap_wlc_tags", {})[self.hostname] = {
                "site_tag": cfg.get("site_tag_name"),
                "policy_tag": cfg.get("policy_tag_name"),
                "rf_tag": cfg.get("rf_tag_name"),
                "ap_join_profile": cfg.get("ap_join_profile"),
                "flex_profile": cfg.get("flex_profile"),
            }
            lines += [
                "",
                "  Tags and profiles",
                f"    Site tag:        {cfg.get('site_tag_name') or '—'}",
                f"    Policy tag:      {cfg.get('policy_tag_name') or '—'}",
                f"    RF tag:          {cfg.get('rf_tag_name') or '—'}",
                f"    AP-join profile: {cfg.get('ap_join_profile') or '—'}",
                f"    Flex profile:    {cfg.get('flex_profile') or '—'}",
                "",
                "  Mode and administration",
                f"    AP mode:         {cfg.get('ap_mode') or '—'}"
                f"   submode: {cfg.get('ap_submode') or '—'}",
                f"    Admin state:     {cfg.get('administrative_state') or '—'}"
                f"   operation: {cfg.get('operation_state') or '—'}",
                f"    Primary WLC:     {cfg.get('primary_cisco_controller_name') or '—'}"
                f" ({cfg.get('primary_cisco_controller_ip_address') or '—'})",
            ]

        # Not Registered is the one condition that ends the run. SDA allows a
        # single primary controller, so this is the controller the AP joins --
        # there is no second one for it to be registered on instead. Everything
        # the flow exists to validate (the radio MAC's LISP registration, the
        # access tunnel) is built on a CAPWAP session that does not exist, so
        # continuing would report a wall of absences that all restate this one
        # fault. CAPWAP has to be fixed before the rest means anything.
        if state and state.lower() != "registered":
            ctx.state["ap_stop"] = (
                f"AP {name} is {state} on {self.hostname}, not Registered.")
            return CheckResult(
                CheckStatus.FAIL,
                f"{name} is {state} on {self.hostname}, not Registered.\n\n"
                f"CAPWAP is not established, so nothing downstream of the join "
                f"can be validated -- the access tunnel and the radio MAC's "
                f"LISP registration do not exist until the AP registers. "
                f"Establish CAPWAP first, then re-run.")

        notes = []
        status = CheckStatus.OK

        def flag(message):
            nonlocal status
            status = CheckStatus.WARN
            notes.append(message)

        # The Ethernet MAC the controller reports, against the MAC this run was
        # started with. The lookup matched on it, so a mismatch here means the
        # summary row disagrees with itself rather than that the wrong AP was
        # found; worth surfacing because every wired check above keyed on the
        # input MAC.
        reported_mac = normalize_mac((row.get("ethernet_mac") or "").strip())
        if reported_mac and ap_mac and reported_mac != normalize_mac(ap_mac):
            flag(f"The controller reports Ethernet MAC {reported_mac}, but "
                 f"this run was started with {ap_mac}.")

        # The AP's address as the controller sees it, against what the edge
        # switch witnessed (SISF device-tracking, and the DHCP snooping
        # binding where the two agree). A disagreement means one of them is
        # stale: the AP moved, or re-addressed, and something is still
        # pointing at where it used to be.
        sisf_ip = (ctx.state.get("ap_ip") or "").strip()
        if ap_ip and sisf_ip and ap_ip != sisf_ip:
            source = ctx.state.get("ap_ip_source") or "the edge switch"
            flag(f"The controller has this AP at {ap_ip}, but {source} on the "
                 f"edge has {sisf_ip}.")

        # A fabric AP carries its traffic in the VXLAN access tunnel, which is
        # what the flex profile would override: a non-default one switches
        # traffic locally at the AP instead, so the tunnel this flow exists to
        # validate is bypassed and every check of it below would be measuring
        # a path the AP is not using. Returned rather than collected with the
        # warnings below, which would downgrade it.
        flex = ((cfg or {}).get("flex_profile") or "").strip()
        if flex and flex.lower() != _DEFAULT_FLEX_PROFILE:
            ctx.state["ap_stop"] = (
                f"AP {name} has flex profile {flex}, not "
                f"{_DEFAULT_FLEX_PROFILE}.")
            return CheckResult(
                CheckStatus.FAIL,
                "\n".join(lines + [
                    "",
                    f"  ✖ The AP's flex profile is {flex}, not "
                    f"{_DEFAULT_FLEX_PROFILE}. A fabric AP must carry its "
                    f"traffic in the VXLAN access tunnel; a flex profile "
                    f"switches it locally at the AP instead, so the tunnel "
                    f"this flow validates is bypassed.",
                ]))

        # Local is the mode an AP onboards in on a fabric edge. Anything else
        # is a different design, and the checks above and below it are reading
        # a topology the AP is not actually using.
        mode = ((cfg or {}).get("ap_mode") or "").strip()
        if mode and mode.lower() != "local":
            flag(f"The AP is in {mode} mode, not Local.")

        admin = ((cfg or {}).get("administrative_state") or "").strip()
        if admin and admin.lower() != "enabled":
            flag(f"The AP is administratively {admin}, not Enabled.")

        if cfg_error:
            # The summary row already proved the AP is joined, so failing to
            # read its config narrows what can be said, it does not reverse it.
            # It does mean mode and admin state went ungraded, which is why
            # this is surfaced rather than passed over.
            flag(f"The AP's tags and profiles could not be read — {cfg_error}")

        if notes:
            lines += [""] + [f"  ⚠ {n}" for n in notes]

        # Registered means the CAPWAP control session exists, so draw it.
        # Only here: the earlier returns are an AP that is absent from this
        # controller or not registered on it, and in neither case is there a
        # tunnel to show. The edge is the one piece of the AP's state that is
        # not about a single node, which is why it goes on the canvas rather
        # than into the message.
        return CheckResult(status, "\n".join(lines),
                           data={"ap_name": name, "state": state,
                                 "add_edges": [{
                                     "source": "ap",
                                     "target": self.target_node_id,
                                     "label": "CAPWAP Control",
                                     "id_prefix": "capwap",
                                     "capwap": True,
                                 }]})


def _not_found_message(cdp_name, ap_mac, wlc, rows, unreadable, expected):
    """The soft-warn text for an AP absent from `show ap uptime`."""
    who = f"AP {cdp_name} with MAC {ap_mac}" if cdp_name else f"AP {ap_mac}"
    lines = [f"The AP Uptime information for {who} was not found under "
             f"`show ap uptime` on {wlc}."]
    # A row the parser refused, or an AP the device counted but did not
    # print, is a different situation from a genuinely absent AP, and the
    # reader cannot tell them apart unless it is said.
    notes = []
    if unreadable:
        notes.append(
            f"{unreadable} row{'' if unreadable == 1 else 's'} in the output "
            f"could not be read, so the AP may be among them.")
    if expected is not None and len(rows) != expected:
        notes.append(
            f"The controller reported {expected} AP"
            f"{'' if expected == 1 else 's'} but {len(rows)} "
            f"{'was' if len(rows) == 1 else 'were'} read.")
    if notes:
        lines += [""] + [f"  ⚠ {n}" for n in notes]
    return "\n".join(lines)


def _uptime_message(name, row, uptime_seconds):
    """The found-AP reading, warning when the association is recent."""
    ap_up = row.get("ap_up_time") or "—"
    assoc_up = row.get("association_up_time") or "—"
    lines = [
        f"{name} is up on the controller.",
        "",
        f"  AP name:           {name}",
        f"  Ethernet MAC:      {row.get('ethernet_mac') or '—'}",
        f"  Radio MAC:         {row.get('radio_mac') or '—'}",
        f"  AP uptime:         {ap_up}",
        f"  Association time:  {assoc_up}",
    ]

    assoc_seconds = uptime_seconds(assoc_up)
    if assoc_seconds is None:
        # Not gradeable, so not graded, and silently: the durations the
        # device printed are already on the line above, and a note about an
        # unrecognised unit format is housekeeping rather than a finding.
        # Guessing the number instead would either warn about a stable AP or
        # stay silent about a flapping one.
        return CheckResult(CheckStatus.OK, "\n".join(lines))

    if assoc_seconds < _RECENT_ASSOCIATION:
        ap_seconds = uptime_seconds(ap_up)
        # Only claim the AP did not reload when its own uptime proves it.
        # If that could not be read, the association is still recent and
        # worth reporting -- the cause is simply not established.
        reloaded = (ap_seconds is not None
                    and ap_seconds < _RECENT_ASSOCIATION)
        if reloaded:
            note = (f"The AP associated {assoc_up} ago and its own uptime is "
                    f"{ap_up}, so it reloaded rather than flapped.")
        else:
            note = (f"The AP flapped recently but did not reload: it "
                    f"associated {assoc_up} ago while its uptime is {ap_up}.")
        return CheckResult(CheckStatus.WARN,
                           "\n".join(lines + ["", f"  ⚠ {note}"]))

    return CheckResult(CheckStatus.OK, "\n".join(lines))

#: An association younger than this means the AP re-joined the controller
#: recently. Ten minutes is the manifest's figure.
_RECENT_ASSOCIATION = 10 * 60

#: The only flex profile an SDA controller can use, in every deployment --
#: not a lab default or a site convention. A fabric AP carries its traffic in
#: the VXLAN access tunnel, and any other profile switches it locally at the
#: AP instead, so there is no site-specific value this could legitimately be.
_DEFAULT_FLEX_PROFILE = "default-flex-profile"


class ApWlcApUptime(_PerWlcCheck):
    """How long the AP has been up, and how long it has been associated.

    The two durations answer different questions, and the gap between them is
    the finding. An AP whose uptime is days but whose association is minutes
    did not reload -- it dropped its CAPWAP session and came back. That is a
    flap, and it is invisible in `show ap summary`, which reports such an AP
    as Registered exactly like one that has been up for a month.

    `show ap uptime` has no Genie parser, so the table is read by
    `parse_ap_uptime`. Soft throughout: this is a supplementary reading, and
    not finding the AP here says nothing that the registration checks have not
    already said better.
    """

    aspect = "AP Uptime"
    running_note = "Reading the AP's uptime and association time…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        from checks.shared import normalize_mac

        service = ctx.service
        if not service:
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        ap_mac = normalize_mac(ctx.payload.get("mac"))
        if not ap_mac:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no AP MAC was supplied, so there is nothing to "
                "look up.")

        # The name CDP saw on the wire, used only to make the message
        # readable: the lookup itself is on the MAC.
        cdp_name = ((ctx.state.get("ap_cdp_neighbor") or {}).get("device_id")
                    or "").strip()

        from radkit_cli import get_any_single_output
        from wirelessmodules.accesspointinfo import (
            parse_ap_uptime, uptime_seconds,
        )

        try:
            raw = get_any_single_output(
                self.hostname, "show ap uptime", service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"`show ap uptime` could not be read from {self.hostname} — "
                f"{type(e).__name__}: {e}")

        rows, unreadable, expected = parse_ap_uptime(raw)

        name, row = None, None
        for candidate, fields in rows.items():
            if normalize_mac(fields.get("ethernet_mac")) == ap_mac:
                name, row = candidate, fields
                break

        if not row:
            return CheckResult(
                CheckStatus.WARN,
                _not_found_message(cdp_name, ap_mac, self.hostname,
                                   rows, unreadable, expected))

        return _uptime_message(name, row, uptime_seconds)



def _resolve_ap_name(ctx, wlc_hostname, service):
    """This AP's name on `wlc_hostname`, or "" if it is not joined to it.

    Prefers the name `ApWlcApState` published, and falls back to resolving it
    from `show ap summary`. The fallback is what makes the per-WLC checks
    independent of the order they are queued in: whichever runs first pays for
    the lookup, and the rest read it from state.

    The lookup is on the Ethernet MAC, which is what the run was started with.
    """
    from checks.shared import normalize_mac

    name = ctx.state.get("ap_wlc_ap_name")
    if name:
        return name
    ap_mac = normalize_mac(ctx.payload.get("mac"))
    if not ap_mac:
        return ""
    from radkit_cli import get_single_output_genie
    try:
        parsed = get_single_output_genie(
            wlc_hostname, "show ap summary", service)
    except BaseException:
        return ""
    rows = _ap_summary_rows(parsed)
    if not rows:
        return ""
    name, _row = _find_ap_by_ethernet_mac(rows, ap_mac)
    return name or ""


def _ap_country_direct(ctx, wlc_hostname, service):
    """The AP's own country, read from the controller without ApWlcApState.

    Returns "" when the AP cannot be resolved -- the caller then shows the
    controller's list and says it did not grade, which is honest about what
    was and was not established.
    """
    name = _resolve_ap_name(ctx, wlc_hostname, service)
    if not name:
        return ""
    cfg, _error = _ap_config_general(wlc_hostname, name, service)
    if not cfg:
        return ""
    country = (cfg.get("country_code") or "").strip()
    if country:
        ctx.state.setdefault("ap_wlc_country", {})[wlc_hostname] = country
    return country


class ApWlcApCrash(_PerWlcCheck):
    """Has this AP ever written a crash file to the controller?

    Historical, not current state: the file stays in bootflash after the AP
    recovers, so an entry does not mean the AP is crashing now. It means that
    any flap this run is investigating has a crash behind it at least once,
    which is the difference between an AP that is being disconnected and one
    that is falling over on its own. That is why it is a warning rather than
    a fault -- it narrows the cause, it does not establish one.
    """

    aspect = "AP Crash"
    running_note = "Checking for AP crash files…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        name = _resolve_ap_name(ctx, self.hostname, service)
        if not name:
            # Not a finding about crashes: the AP is not on this controller,
            # which ApWlcApState and its verdict already report.
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — the AP is not joined to {self.hostname}, so it "
                f"has no crash files here.")

        from radkit_cli import get_any_single_output
        from wirelessmodules.accesspointinfo import parse_ap_crash_files

        try:
            raw = get_any_single_output(
                self.hostname, "show ap crash-file", service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"`show ap crash-file` could not be read from "
                f"{self.hostname} — {type(e).__name__}: {e}")

        # Rows the parser could not read are passed over: this check reports
        # whether an entry for one named AP exists, and a count of malformed
        # lines is housekeeping rather than a finding about that AP.
        rows, _unreadable = parse_ap_crash_files(raw)
        entry = rows.get(name)

        if entry is None:
            return CheckResult(
                CheckStatus.OK,
                f"{name} has no crash file on {self.hostname}.")

        lines = [
            f"{name} has a crash file on {self.hostname}.",
            "",
            f"  AP name:     {name}",
            f"  Crash file:  {entry['crash_file']}",
        ]
        if entry.get("mac"):
            lines.append(f"  MAC:         {entry['mac']}")
        lines += [
            "",
            f"  ⚠ This AP crashed at some point. Any flap event seen in this "
            f"run has a crash behind it rather than the AP simply being "
            f"disconnected. The file stays on the controller after the AP "
            f"recovers, so this does not mean it is crashing now.",
        ]
        return CheckResult(CheckStatus.WARN, "\n".join(lines))


class ApWlcApDiscovery(_PerWlcCheck):
    """The AP's last failed discovery attempt on this controller, if any.

    Reports only a failure. An AP that has never failed discovery, or that is
    not in the table at all, produces nothing worth saying: a successful
    discovery is already evident from the AP being joined, which the checks
    around this one establish directly.

    The controller keeps one failure per AP -- the most recent -- so this is a
    single event, not a history.
    """

    aspect = "AP Discovery"
    running_note = "Checking AP discovery failures…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        from checks.shared import normalize_mac
        ap_mac = normalize_mac(ctx.payload.get("mac"))
        if not ap_mac:
            return CheckResult(CheckStatus.SKIP,
                               "Skipped — no AP MAC was supplied.")

        from radkit_cli import get_any_single_output
        from wirelessmodules.accesspointinfo import (
            parse_ap_discovery_stats, NO_DISCOVERY_FAILURE,
        )

        try:
            raw = get_any_single_output(
                self.hostname, "show wireless stats ap discovery", service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"`show wireless stats ap discovery` could not be read from "
                f"{self.hostname} — {type(e).__name__}: {e}")

        rows, _unreadable, _expected = parse_ap_discovery_stats(raw)
        entry = rows.get(ap_mac.lower())

        if entry is None:
            # The AP has sent no discovery request to this controller. Not a
            # finding here: whether it should have is what ApWlcApState and
            # its site-wide verdict answer.
            return CheckResult(
                CheckStatus.OK,
                f"No discovery failure is recorded for {ap_mac} on "
                f"{self.hostname}.")

        failure = (entry.get("last_failure_type") or "").strip()
        if not failure or failure.lower() == NO_DISCOVERY_FAILURE:
            return CheckResult(
                CheckStatus.OK,
                f"The AP has no recorded discovery failure on "
                f"{self.hostname}.")

        lines = [
            f"The AP last failed discovery on {self.hostname}.",
            "",
            f"  Failure type:  {failure}",
            f"  Failure time:  {entry.get('last_failure_time') or '—'}",
            # The address the AP held at the time, which is what makes the
            # failure actionable: a discovery failure from an address the AP
            # no longer has is a different problem from one at its current
            # address.
            f"  IP address:    {entry.get('ip_address') or '—'}",
        ]
        success = (entry.get("last_success_time") or "").strip()
        if success:
            lines.append(f"  Last success:  {success}")
        return CheckResult(CheckStatus.WARN, "\n".join(lines))


#: More disjoins than this on one calendar day is reported as flapping. One
#: or two in a day is ordinary -- an AP reloads, a switch port is bounced,
#: someone upgrades a stack -- but a third means something is recurring.
_DISJOINS_PER_DAY = 2

#: How far back to look. The controller keeps more, but the older entries
#: describe a configuration that may no longer exist.
_DISJOIN_WINDOW = 10


class ApWlcApHistory(_PerWlcCheck):
    """The AP's recent join and disjoin history on this controller.

    A log rather than a snapshot, and the only check here that can say an AP
    is flapping rather than merely down right now. Reported against calendar
    days: a single disjoin is ordinary and says nothing, while several on one
    day is a pattern.

    Planned image upgrades are not counted. The AP disconnects to load new
    software and rejoins, which is a disconnect but not a fault.
    """

    aspect = "AP History"
    running_note = "Reading the AP's join history…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        name = _resolve_ap_name(ctx, self.hostname, service)
        radio_mac = (ctx.state.get("ap_wlc_radio_mac") or "").strip()
        if not name and not radio_mac:
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — the AP could not be identified on "
                f"{self.hostname}.")

        from radkit_cli import get_any_single_output
        from wirelessmodules.accesspointinfo import (
            parse_ap_history, disjoins_for, disjoins_by_day,
        )

        try:
            raw = get_any_single_output(
                self.hostname, "show wireless stats ap history", service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"`show wireless stats ap history` could not be read from "
                f"{self.hostname} — {type(e).__name__}: {e}")

        rows, _unreadable = parse_ap_history(raw)
        disjoins = disjoins_for(rows, ap_name=name, radio_mac=radio_mac,
                                limit=_DISJOIN_WINDOW)
        who = name or radio_mac

        if not disjoins:
            return CheckResult(
                CheckStatus.OK,
                f"{who} has no recorded disjoins on {self.hostname}.")

        lines = [
            f"The last {len(disjoins)} disjoin"
            f"{'' if len(disjoins) == 1 else 's'} for {who} on "
            f"{self.hostname}:",
            "",
        ]
        for row in disjoins:
            lines.append(f"  {row['time']}   {row['disconnect_reason']}")

        by_day = disjoins_by_day(disjoins)
        busy = {d: n for d, n in by_day.items() if n > _DISJOINS_PER_DAY}
        if not busy:
            return CheckResult(CheckStatus.OK, "\n".join(lines))

        worst = ", ".join(f"{n} on {d}" for d, n in sorted(
            busy.items(), key=lambda kv: kv[1], reverse=True))
        lines += [
            "",
            f"  ⚠ The AP flapped: {worst}. More than "
            f"{_DISJOINS_PER_DAY} disjoins in one day is a recurring fault "
            f"rather than an isolated disconnect.",
        ]
        return CheckResult(CheckStatus.WARN, "\n".join(lines))


class ApWlcApDtls(_PerWlcCheck):
    """The DTLS session carrying this AP's CAPWAP control traffic.

    CAPWAP control runs inside DTLS, so no session means no control channel.
    Reported as a warning rather than a failure, per the manifest's rule that
    a fabric fault does not stop the run: the checks around this one still
    explain the path the AP was trying to use.

    The version, ciphersuite and peer port are reported as they are. The peer
    address is graded, because it is the one field that can disagree with
    something: a live session to an address the edge no longer associates
    with this AP means one of the two is stale.
    """

    aspect = "AP DTLS"
    running_note = "Checking the AP's DTLS session…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        name = _resolve_ap_name(ctx, self.hostname, service)
        if not name:
            # Absence from this controller is ApWlcApState's finding.
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — the AP is not joined to {self.hostname}.")

        from radkit_cli import get_any_single_output
        from wirelessmodules.accesspointinfo import (
            parse_dtls_connections, control_session_for,
        )

        try:
            raw = get_any_single_output(
                self.hostname, "show wireless dtls connections", service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"`show wireless dtls connections` could not be read from "
                f"{self.hostname} — {type(e).__name__}: {e}")

        rows, _unreadable = parse_dtls_connections(raw)
        session = control_session_for(rows, name)

        if session is None:
            return CheckResult(
                CheckStatus.WARN,
                f"{name} holds no DTLS session on {self.hostname}.\n\n"
                f"CAPWAP control runs inside DTLS, so the AP has no control "
                f"channel to this controller. The checks around this one "
                f"still have findings worth having about the path it was "
                f"trying to use.")

        lines = [
            f"{name} holds a DTLS control session on {self.hostname}.",
            "",
            f"  Peer IP:      {session.get('peer_ip') or '—'}",
            f"  Peer port:    {session.get('peer_port') or '—'}",
            f"  Version:      {session.get('version') or '—'}",
            f"  Ciphersuite:  {session.get('ciphersuite') or '—'}",
        ]

        # The address the live session is actually to, against what the edge
        # switch witnessed. ApWlcApState grades the controller's record of
        # the AP; this grades the session itself, which can differ.
        peer_ip = (session.get("peer_ip") or "").strip()
        sisf_ip = (ctx.state.get("ap_ip") or "").strip()
        if peer_ip and sisf_ip and peer_ip != sisf_ip:
            source = ctx.state.get("ap_ip_source") or "the edge switch"
            return CheckResult(
                CheckStatus.WARN,
                "\n".join(lines + [
                    "",
                    f"  ⚠ The DTLS session is to {peer_ip}, but {source} on "
                    f"the edge has this AP at {sisf_ip}.",
                ]))

        return CheckResult(CheckStatus.OK, "\n".join(lines))


class ApWlcApCountry(_PerWlcCheck):
    """Is the AP's own country configured on the controller it joined?

    A quieter failure than a join failure, and easy to mistake for an RF
    problem. An AP whose country is not configured on its controller joins,
    registers and then serves nothing, because every radio stays down. The
    registration checks all pass; only the radios are missing.

    Needs the AP's own country, which `ApWlcApState` reads from `show ap name
    <ap> config general`, so it runs after it. The controller's list comes
    from `show wireless country configured`, which Genie has no parser for.
    """

    aspect = "AP Country"
    running_note = "Checking the AP's country is configured on the controller…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if not service:
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        ap_country = ((ctx.state.get("ap_wlc_country") or {})
                      .get(self.hostname) or "").strip()
        if not ap_country:
            # This check is ordered ahead of the one that normally publishes
            # the country, so it resolves its own rather than grade nothing.
            # Only when that has not already happened: on the usual ordering
            # this costs no extra device call.
            ap_country = _ap_country_direct(ctx, self.hostname, service)

        from radkit_cli import get_any_single_output
        from wirelessmodules.accesspointinfo import parse_wireless_country

        try:
            raw = get_any_single_output(
                self.hostname, "show wireless country configured", service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"The configured countries could not be read from "
                f"{self.hostname} — {type(e).__name__}: {e}")

        countries, unreadable = parse_wireless_country(raw)

        if not countries:
            detail = ""
            if unreadable:
                detail = (f" {unreadable} line"
                          f"{'' if unreadable == 1 else 's'} under the table "
                          f"could not be read, so the list may be incomplete.")
            return CheckResult(
                CheckStatus.WARN,
                f"{self.hostname} reports no configured regulatory country."
                f"{detail}\n\nNo AP can bring up a radio until one is "
                f"configured.")

        lines = [f"{len(countries)} regulatory countr"
                 f"{'y' if len(countries) == 1 else 'ies'} configured on "
                 f"{self.hostname}:", ""]
        for code, entry in sorted(countries.items()):
            lines.append(f"  {code}  {entry['name']}")
            if entry["bands"]:
                lines.append(f"      {entry['bands']}")

        if not ap_country:
            # Without the AP's country there is nothing to grade against, but
            # the controller's list is still worth showing.
            lines += ["", "  ⚠ The AP's own country was not read (see AP "
                          "State), so it was not graded against this list."]
            return CheckResult(CheckStatus.OK, "\n".join(lines))

        lines += ["", f"  AP country:  {ap_country}"]
        if ap_country.upper() in countries:
            return CheckResult(CheckStatus.OK, "\n".join(lines))

        return CheckResult(
            CheckStatus.WARN,
            "\n".join(lines + [
                "",
                f"  ⚠ The AP's country {ap_country} is not configured on "
                f"{self.hostname}. The AP can join and register, but every "
                f"radio stays down until the country is added.",
            ]))


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


class ApWlcApStateVerdict(_ApCheck):
    """Site-wide: did the AP join any controller at all?

    The per-controller check cannot decide this. On a site with more than one
    Fabric WLC the AP is absent from all but one of them by definition, so
    "not on this controller" is the expected answer almost everywhere and
    means nothing on its own. Only the view across every controller does.

    Absent everywhere is a fabric fault, and the manifest's rule is that a
    fabric fault is a WARN: the tool can continue, and the edge-side checks
    after this one still have findings worth having -- the port, the VLAN, the
    ACLs and the LISP registrations are what explain *why* the AP did not
    reach a controller. Stopping here would discard exactly the evidence
    someone needs to act on.

    Runs on the XTR rather than a controller: the verdict is about the site.
    """

    name = "WLC AP State Verdict"
    target_node_id = "xtr"
    running_note = "Confirming the AP joined a controller…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        candidates = ctx.state.get("ap_wlc_candidates") or []
        if not candidates:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no WLC was discovered (see WLC Discovery).")

        from checks.shared import normalize_mac
        ap_mac = normalize_mac(ctx.payload.get("mac"))
        if not ap_mac:
            return CheckResult(
                CheckStatus.SKIP, "Skipped — no AP MAC was supplied.")

        joined_on = ctx.state.get("ap_wlc_joined_on") or []
        if joined_on:
            name = ctx.state.get("ap_wlc_ap_name") or "The AP"
            where = ", ".join(joined_on)
            if len(joined_on) == 1:
                return CheckResult(
                    CheckStatus.OK,
                    f"{name} ({ap_mac}) is joined to {where}.")
            # Two controllers both claiming the same AP is a genuine anomaly
            # rather than redundancy: an AP holds one CAPWAP session at a
            # time, so this is either a stale record or a split site.
            return CheckResult(
                CheckStatus.WARN,
                f"{name} ({ap_mac}) is reported as joined by more than one "
                f"controller: {where}.\n\n"
                f"An AP holds one CAPWAP session at a time, so one of these "
                f"records is stale or the controllers disagree about who owns "
                f"the AP.")

        absent = ctx.state.get("ap_wlc_ap_absent") or {}
        checked = len(absent)
        if not checked:
            # Nothing reported either way -- every per-controller check
            # skipped or errored, so there is no verdict to give.
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no controller reported on this AP (see the "
                "per-controller AP State checks).")

        return CheckResult(
            CheckStatus.WARN,
            f"No controller at this site has AP {ap_mac} joined.\n\n"
            f"Checked {checked} controller{'' if checked == 1 else 's'}: "
            f"{', '.join(absent)}.\n\n"
            f"The AP has not completed CAPWAP. The edge-side checks that "
            f"follow examine the path it would use to get there -- the access "
            f"port, the INFRA_VN VLAN, the route to the controller and the "
            f"access lists along it.")


class ApWlcFabricControlPlane(_PerWlcCheck):
    """The control-plane set this AP is configured against, resolved to
    addresses.

    First of the block that follows step 5: the AP's radio MAC reaches the
    edge's access tunnel only after the controller registers it to a control
    plane, so everything below here is a consequence of this resolving.

    Two commands on the controller:

      `show ap name <name> config general`   the AP's own fabric status, its
                                             RLOC, and the *name* of the
                                             control-plane group it uses.

      `show wireless fabric summary`         that name resolved to addresses,
                                             and the subnet the L3 instance
                                             expects the AP to be addressed
                                             in.

    Three faults end the run rather than being noted, which departs from the
    manifest's rule that a fabric fault is a warning. The departure is the
    same one ApWlcApState makes for an unregistered AP, and for the same
    reason: each of the three means this AP has no control plane at all, so
    every check below would report an absence that restates this one fault
    instead of adding to it.
    """

    aspect = "fabric control plane"
    running_note = "resolving the AP's control-plane set"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        from radkit_cli import get_any_single_output
        from wirelessmodules.accesspointinfo import (
            CP_STATUS_UP,
            INFRA_VN_L3_VNID,
            control_planes_named,
            parse_ap_fabric_fields,
            parse_wireless_fabric_summary,
            subnet_contains,
            vnid_for_l3,
        )

        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        name = _resolve_ap_name(ctx, self.hostname, service)
        if not name:
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped — the AP is not joined to {self.hostname}, so this "
                f"controller holds no fabric configuration for it.")

        # Genie parses this command but captures only fabric_status of the
        # three fields wanted here, so it is read raw.
        try:
            raw_cfg = get_any_single_output(
                self.hostname, f"show ap name {name} config general", service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"Could not read {name}'s configuration on {self.hostname}: "
                f"{type(e).__name__}: {e}.")

        fields = parse_ap_fabric_fields(raw_cfg)
        fabric_status = fields["fabric_status"]
        rloc = fields["rloc"]
        cp_name = fields["control_plane_name"]

        # Rule 1. Not fabric-enabled: no control plane applies, and no access
        # tunnel is ever built for this AP.
        if fabric_status and fabric_status.lower() != "enabled":
            ctx.state["ap_stop"] = (
                f"{name} is not fabric-enabled on {self.hostname} "
                f"(fabric status {fabric_status}).")
            return CheckResult(
                CheckStatus.FAIL,
                f"{name} has fabric status {fabric_status} on "
                f"{self.hostname}.\n\n"
                f"The AP is not operating as a fabric AP, so it registers to "
                f"no control plane and the edge builds no access tunnel for "
                f"it. Everything validated below depends on that "
                f"registration.")

        try:
            raw_fabric = get_any_single_output(
                self.hostname, "show wireless fabric summary", service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"Could not read the fabric summary on {self.hostname}: "
                f"{type(e).__name__}: {e}.")

        summary, _unreadable = parse_wireless_fabric_summary(raw_fabric)

        # Rule 2. The name the AP carries has to exist on the controller.
        planes = control_planes_named(summary, cp_name)
        if not planes:
            ctx.state["ap_stop"] = (
                f"Control plane {cp_name or '(none)'} is not configured on "
                f"{self.hostname}.")
            return CheckResult(
                CheckStatus.FAIL,
                f"{name} is configured against control plane "
                f"{cp_name or '(none)'}, which {self.hostname} does not "
                f"have.\n\n"
                f"The LISP control plane for VNI {INFRA_VN_L3_VNID} on this "
                f"controller is configured with a name the fabric does not "
                f"resolve, so the AP registers nowhere.")

        # Rule 3. The L3 instance has to expect the AP where it actually is.
        ap_ip = (ctx.state.get("ap_ip") or "").strip()
        vnid = vnid_for_l3(summary, INFRA_VN_L3_VNID)
        if vnid is None:
            ctx.state["ap_stop"] = (
                f"{self.hostname} has no L3-VNID {INFRA_VN_L3_VNID} mapping.")
            return CheckResult(
                CheckStatus.FAIL,
                f"{self.hostname} maps no fabric VNID to L3 instance "
                f"{INFRA_VN_L3_VNID}.\n\n"
                f"That instance is the INFRA_VN an AP onboards in. Without "
                f"it the controller has no subnet to place the AP in and no "
                f"control plane to register it to.")

        inside = subnet_contains(ap_ip, vnid.get("ip_address"),
                                 vnid.get("subnet"))
        if ap_ip and inside is False:
            ctx.state["ap_stop"] = (
                f"{ap_ip} is outside the L3-VNID {INFRA_VN_L3_VNID} subnet "
                f"on {self.hostname}.")
            return CheckResult(
                CheckStatus.FAIL,
                f"{name} holds {ap_ip}, which is outside "
                f"{vnid.get('ip_address')}/{vnid.get('subnet')} -- the "
                f"subnet L3-VNID {INFRA_VN_L3_VNID} maps on "
                f"{self.hostname}.\n\n"
                f"The AP is addressed outside the INFRA_VN the controller "
                f"expects it in, so the control plane has no instance to "
                f"register it under.")

        # Resolved. Publish what the rest of the block runs on.
        addresses = [p["ip_address"] for p in planes]
        ctx.state["ap_cp_set"] = addresses
        ctx.state["ap_cp_name"] = cp_name
        ctx.state["ap_wlc_rloc"] = rloc
        ctx.state["ap_infra_l3_vnid"] = INFRA_VN_L3_VNID

        down = [p for p in planes
                if (p.get("status") or "").strip().lower() != CP_STATUS_UP]
        lines = [
            f"{name} is fabric-enabled on {self.hostname} and resolves to "
            f"{len(planes)} control plane{'' if len(planes) == 1 else 's'}.",
            "",
            "  Fabric",
            f"    Fabric status:      {fabric_status or '—'}",
            f"    RLOC:               {rloc or '—'}",
            f"    Control plane name: {cp_name or '—'}",
            "",
            f"  L3-VNID {INFRA_VN_L3_VNID}",
            f"    Mapping:            {vnid.get('name') or '—'}",
            f"    Subnet:             {vnid.get('ip_address') or '—'}"
            f" / {vnid.get('subnet') or '—'}",
            f"    AP address:         {ap_ip or '— (not resolved)'}",
            "",
            "  Control planes",
        ]
        for plane in planes:
            lines.append(f"    {plane['ip_address']:<16} {plane.get('status')}")

        # A control plane that is down is a fabric fault, not a tool one: the
        # manifest's warn-and-continue rule applies, because the other plane
        # of the pair may still be carrying the registration.
        if down:
            return CheckResult(
                CheckStatus.WARN,
                "\n".join(lines) + "\n\n"
                + f"{len(down)} of these is not Up, so the AP may be "
                  f"registering to fewer control planes than the fabric "
                  f"intends.")
        return CheckResult(CheckStatus.OK, "\n".join(lines),
                           data={"control_planes": addresses})


class _ApEidAttributes:
    """An AP's radio MAC shaped as the endpoint object the LISP session
    troubleshooter expects.

    `fabricEnabledWirelessSession` was written for a wireless *client*, whose
    attributes come from `show wireless client mac-address <mac> detail`. An
    AP is not a client: that command returns nothing for a radio MAC, so
    WirelessEndpointMac cannot collect for one.

    It does not need to. FEWEIDIdentification reads exactly five fields out of
    `endpointinfo["fabric"]`, and the AP chain already establishes every one
    of them -- three from the AP's own `config general`, the L2 VNID from the
    controller's INFRA_VN mapping. This carries those across rather than
    issuing a command that cannot answer.

    The EID itself is the radio MAC, not the Ethernet MAC the rest of the AP
    chain keys on: the radio MAC is what the controller registers to LISP and
    what the edge builds its access tunnel for.
    """

    #: An AP registers with no SGT of its own.
    SGT = 0

    def __init__(self, hostname, radio_mac, fabric_status, rloc, vnid,
                 control_plane_name):
        self.hostname = hostname
        self.mac = radio_mac
        self.endpointinfo = {
            "fabric": {
                "status": fabric_status,
                "rloc": rloc,
                "vnid": vnid,
                "sgt": self.SGT,
                "control_plane_name": control_plane_name,
            }
        }


class ApWlcCpLispSession(_PerWlcCheck):
    """The LISP sessions carrying this AP's registration to its control planes.

    Item 1 of the block: the controller registers the AP's radio MAC to the
    control planes ApWlcFabricControlPlane resolved, and the edge builds the
    access tunnel from what the control plane hands back. A session that is
    not up is why a registration is missing, which is why a control plane
    reported Down is the trigger for this rather than a finding on its own.

    Wraps `fabricEnabledWirelessSession`, the existing troubleshooter, with
    the AP's radio MAC as the EID. That module already warns per down control
    plane and continues -- the manifest's rule -- so the status here reflects
    what it found rather than reimplementing the judgement.
    """

    aspect = "CP LISP Session"
    running_note = "Validating LISP sessions to the control planes…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        if service is None:
            return CheckResult(CheckStatus.SKIP, "Skipped — no RSA service.")

        info = self._info(ctx)
        if info is None:
            return self._skip_no_data()

        radio_mac = (ctx.state.get("ap_wlc_radio_mac") or "").strip()
        if not radio_mac:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's radio MAC was not resolved, so there is "
                "no EID to look for. ApWlcApState publishes it once the AP "
                "is found on a controller.")

        cp_name = (ctx.state.get("ap_cp_name") or "").strip()
        if not cp_name:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's control-plane set was not resolved (see "
                "the fabric control plane check).")

        catc = ctx.state.get("catc_name")
        if not catc:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no Catalyst Center name, which the control-plane "
                "lookup resolves each node through.")

        endpoint = _ApEidAttributes(
            hostname=self.hostname,
            radio_mac=radio_mac,
            fabric_status=(ctx.state.get("ap_wlc_fabric_status") or {})
                .get(self.hostname),
            rloc=ctx.state.get("ap_wlc_rloc"),
            vnid=ctx.state.get("ap_infra_l2_vnid"),
            control_plane_name=cp_name,
        )

        try:
            from traffic_flows.lispsessiontroubleshooting import (
                fabricEnabledWirelessSession)
            _step, control_planes, cp_info = fabricEnabledWirelessSession(
                info, None, 0, catc, endpoint, service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"Could not validate the LISP sessions on {self.hostname}: "
                f"{type(e).__name__}: {e}.")

        ctx.state["ap_cp_info"] = cp_info
        ctx.state["ap_cp_sessions"] = control_planes

        rows = control_planes or []
        down = [cp for cp in rows
                if (cp.get("status") or "").strip().lower() != "up"]

        lines = [
            f"The radio MAC {radio_mac} registers to {cp_name} through "
            f"{len(rows)} control plane{'' if len(rows) == 1 else 's'}.",
            "",
            "  LISP sessions",
        ]
        for cp in rows:
            lines.append(f"    {(cp.get('ip') or '?'):<16} "
                         f"{cp.get('status') or '?'}")

        if not rows:
            return CheckResult(
                CheckStatus.WARN,
                f"No LISP session was returned for {cp_name} on "
                f"{self.hostname}, so the AP's radio MAC registers nowhere.")
        if down:
            return CheckResult(
                CheckStatus.WARN,
                "\n".join(lines) + "\n\n"
                + f"{len(down)} of these is not up. A registration missing "
                  f"below is a consequence of this, not a separate fault.")
        return CheckResult(CheckStatus.OK, "\n".join(lines))
