"""AP Onboarding — Fabric Enabled Wireless.

Traces a fabric-enabled access point onto the wireless fabric: the switchport it
lands on, the address it needs, the CAPWAP join, and the access tunnel that
carries its clients.

Two things about this flow differ from the others:

  * It is gated on the XTR being an **Edge node**. An AP onboards through a
    fabric edge; pointed at a border or a control plane, none of the downstream
    verification means anything, so everything after the gate skips rather than
    reporting misleading results. See `ApEdgeGate` and `_ApCheck`.

  * It distinguishes **platform-independent** (PI) from **platform-dependent**
    (PD) verification. `show mac address-table` is PI -- it says what IOS
    believes. `show platform software fed ... matm macTable` is PD: what the
    hardware was actually programmed with. The two disagree exactly when the
    interesting bugs happen.

PD-eligible objects found along the way are recorded (see `pd_objects`) and
verified in a later pass, once the PI picture is complete.
"""

import re
from collections.abc import Mapping

from checks.base import Check, CheckResult, CheckStatus, RunContext
from checks.shared import normalize_mac
from traffic_flows.dhcp_troubleshooting import abbrev_port


# Objects whose hardware programming can be verified separately from what IOS
# reports. Collected during the PI pass, verified in the PD pass.
PD_ELIGIBLE = (
    "MATM",             # a mac-address-table entry
    "WiredClient",      # an authentication session's client entry
    "adjacency",
    "route",
    "fib_entry",
    "IFM",              # interface manager programming
    "cts_sgacl_entry",
    "acl_entry",
    "qos_entry",
    "copp_drops",
)


def record_pd_object(ctx: RunContext, kind: str, **attrs) -> None:
    """Queue a PD-eligible object for hardware verification later.

    Called during the PI pass. Deferred rather than verified inline because a PD
    lookup needs identifiers the PI pass discovers (an interface's IF-ID, a
    MAC's VLAN), and because hardware state is worth reading once the software
    picture is settled -- not midway through it.

    Every object carries `radkit_hostname`: the PD pass has to run `show
    platform` on the device the object was found on, and that name is the
    RADKit inventory handle it will be executed against, not a display label.
    """
    if "radkit_hostname" not in attrs:
        raise ValueError(
            f"PD object {kind!r} needs radkit_hostname -- the PD pass runs "
            f"commands against it"
        )
    if kind not in PD_ELIGIBLE:
        raise ValueError(f"{kind!r} is not a PD-eligible object type")
    ctx.state.setdefault("pd_objects", []).append(dict(kind=kind, **attrs))


class _ApCheck(Check):
    """Base for every AP-onboarding check after the gate.

    An AP onboards through a fabric edge. On any other role the downstream
    verification is not merely inapplicable -- it would be misleading -- so each
    check skips instead. Subclasses implement `run_ap`.
    """

    def run(self, ctx: RunContext) -> CheckResult:
        if not ctx.state.get("edge"):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the XTR is not an Edge node (see XTR Role Classification).",
            )
        # A check that establishes an unrecoverable prerequisite failure sets
        # `ap_stop` with its reason. The chain deliberately does not break on
        # FAIL (see scenario_runner), so this is how "nothing can continue" is
        # expressed: one clear reason on every later check, rather than a wall
        # of unrelated failures derived from data we never obtained.
        stop = ctx.state.get("ap_stop")
        if stop:
            return CheckResult(CheckStatus.SKIP, f"Skipped — {stop}")

        result = self.run_ap(ctx)

        # A FAIL ends the flow. Every check here is a precondition for the ones
        # after it -- an AP whose gateway cannot relay DHCP is not going to
        # register in LISP, and reporting that as a second, separate failure
        # says nothing the first did not already say. Continuing past a FAIL
        # produces a wall of consequences and buries the cause.
        #
        # Set here rather than in each check so the rule holds everywhere by
        # construction: a check states its verdict, and the flow stops on it
        # without each one having to remember to say so. A check that has a
        # more specific reason still sets `ap_stop` itself, and that reason
        # wins -- this only fills in the ones that do not.
        if result.status == CheckStatus.FAIL and not ctx.state.get("ap_stop"):
            ctx.state["ap_stop"] = f"{self.name} failed on this AP"

        return result

    def run_ap(self, ctx: RunContext) -> CheckResult:
        raise NotImplementedError


class ApEdgeGate(Check):
    """Stop the flow unless the XTR is an Edge node.

    Reads the `edge` flag XtrRoleClassification set. Everything downstream
    subclasses _ApCheck and skips when this fails, so a wrong device produces
    one clear error rather than a wall of unrelated failures.

    Extended-node APs are not covered yet: they onboard through an extended
    node whose upstream is a fabric edge, so the guidance is to run this against
    that edge.
    """

    name = "Edge Node Gate"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if ctx.state.get("edge"):
            return CheckResult(
                CheckStatus.OK,
                "XTR is an Edge node — AP onboarding checks apply.",
            )

        if not ctx.state.get("xtr_is_fabric"):
            return CheckResult(
                CheckStatus.FAIL,
                "This device is not a fabric member, so it cannot be the edge an "
                "AP onboards through. Re-run against the fabric edge the AP is "
                "cabled to.",
            )

        roles = ctx.state.get("xtr_roles") or []
        found = ", ".join(roles) if roles else "no roles reported"
        return CheckResult(
            CheckStatus.FAIL,
            f"AP onboarding requires an Edge node; this device is: {found}. "
            "All further checks are skipped. If the AP is behind an extended "
            "node, that flow is not available yet — re-run against the fabric "
            "edge upstream of it.",
        )


class ApInfraVnVlan(_ApCheck):
    """The VLAN the AP onboards in, derived from the INFRA_VN's L2 instance.

    Step 2 read the INFRA_VN's L2 VNID from a Fabric WLC. That instance ID is
    site-wide -- the L2LISP instance mapping to a fabric site is always the same
    -- so the edge's own LISP configuration translates it into the VLAN the AP
    lands in: `show lisp instance-id <iid> ethernet | i EID table`.

    Deriving the VLAN rather than asking for it is deliberate. A typed VLAN
    would be an assumption to verify; this one is the fabric's own answer, and
    every later check (VLAN state, SVI, MAC learning, L2 LISP) hangs off it.

    Two distinct faults, both fatal:
      * the instance does not exist on the edge -- the L2 VNI must be
        configured before an AP can onboard
      * the instance exists but has no EID table -- it needs `eid-table vlan`
    """

    name = "INFRA VN VLAN"
    target_node_id = "xtr"
    running_note = "Deriving the AP's VLAN from the INFRA_VN L2 instance…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        vnid = ctx.state.get("ap_infra_l2_vnid")
        if not (hostname and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname).",
            )
        if vnid is None:
            # Not a fault of the edge: step 2 never produced a usable INFRA_VN.
            # That failure is already reported on the controllers themselves.
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no INFRA_VN L2 VNID was obtained from any Fabric WLC "
                "(see WLC INFRA VN).",
            )

        from routingmodules.lisp import l2lisp_info

        info = l2lisp_info()
        try:
            info.vlan_from_iid(hostname, vnid, ctx.service)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"vlan_from_iid({vnid})")

        vlan = getattr(info, "vlanfromiid", None)
        if vlan is not None:
            ctx.state["ap_vlan"] = vlan
            return CheckResult(
                CheckStatus.OK,
                f"INFRA_VN L2 instance {vnid} maps to VLAN {vlan} on {hostname}. "
                f"The AP onboards in VLAN {vlan}.",
                data={"vlan": vlan, "l2_vnid": vnid},
            )

        # No VLAN. Re-read the same command to tell the two faults apart: IOS
        # answers a missing instance with an explicit error, which survives the
        # `| i` filter, so a second command is not needed.
        raw = self._raw(ctx, hostname, vnid)
        if not (raw or "").strip():
            # Nothing came back. That is not evidence of a misconfiguration --
            # reporting one would send the user to fix config that may be fine.
            ctx.state["ap_stop"] = (
                f"the INFRA_VN L2 instance {vnid} could not be read from "
                f"{hostname} (see INFRA VN VLAN)."
            )
            return CheckResult(
                CheckStatus.FAIL,
                f"No output from `show lisp instance-id {vnid} ethernet` on "
                f"{hostname}, so the AP's VLAN could not be derived. This says "
                f"nothing about whether the instance is configured — check the "
                f"device is reachable and the collection log for the command.",
            )
        ctx.state["ap_stop"] = (
            f"the INFRA_VN L2 instance {vnid} yields no VLAN on {hostname} "
            f"(see INFRA VN VLAN)."
        )
        if raw is not None and "could not find eid table" in raw.lower():
            return CheckResult(
                CheckStatus.FAIL,
                f"LISP instance ID {vnid} does not exist on {hostname}:\n"
                f"    {raw.strip().splitlines()[0] if raw.strip() else ''}\n\n"
                f"The INFRA_VN L2 VNI must be configured on this edge before an "
                f"AP can onboard through it. Re-provision the edge from Catalyst "
                f"Center so the fabric site's INFRA_VN is applied.",
            )
        return CheckResult(
            CheckStatus.FAIL,
            f"LISP instance ID {vnid} exists on {hostname} but has no EID table, "
            f"so it is not mapped to a VLAN. An AP has no VLAN to onboard into. "
            f"Set `eid-table vlan <vlan>` under this instance — normally by "
            f"re-provisioning the edge from Catalyst Center.",
        )

    @staticmethod
    def _raw(ctx: RunContext, hostname: str, vnid) -> str | None:
        """The command's own output, to separate 'absent' from 'unmapped'."""
        try:
            from radkit_cli import get_any_single_output
            return get_any_single_output(
                hostname,
                f"show lisp instance-id {vnid} ethernet | i EID table",
                ctx.service,
            )
        except BaseException:
            return None


class ApMacLearning(_ApCheck):
    """Is the AP's MAC learned on the edge, and on a port that makes sense?

    Reuses `switchingmodules.maclearning.mac_learning`, qualified by the VLAN
    derived in ApInfraVnVlan so the lookup is scoped rather than fabric-wide.
    The module's `entry` carries the table row whole, which is what the PD pass
    compares hardware against.

    The port is judged, not merely reported. An AP is cabled to a physical
    access port, so:
      * not present      -> the AP is not on this edge at all; hard stop, since
                            every later check reads state keyed on this MAC
      * Drop             -> learned but blackholed
      * Tu* / L2L*       -> learned via LISP, i.e. the AP lives on a different
                            edge and this run is pointed at the wrong device
      * Ac* (AccessTunnel) -> a MAC behind an AP, not an AP: the address given
                            is a wireless client's

    The MAC is recorded as a PD-eligible object for the hardware pass.
    """

    name = "AP MAC Learning"
    target_node_id = "xtr"
    running_note = "Looking for the AP's MAC on the edge…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        mac = ctx.payload.get("mac")
        vlan = ctx.state.get("ap_vlan")
        if not (hostname and mac and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname / mac).",
            )
        if vlan is None:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's VLAN is unknown (see INFRA VN VLAN).",
            )

        from switchingmodules.maclearning import mac_learning

        info = mac_learning(hostname)
        try:
            info.mac_learning_mac(mac, vlan, ctx.service)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"mac_learning_mac({mac}, vlan {vlan})")

        port = getattr(info, "port", None)
        m_type = getattr(info, "type", None)
        entry = getattr(info, "entry", None) or {}

        # Not in the INFRA_VN VLAN. That is not the same as absent: the AP can
        # be present on a port that authentication put in another VLAN (a
        # RADIUS-assigned one, or the critical-auth VLAN when the server was
        # unreachable). Retrying without the VLAN qualifier tells the two apart,
        # and the module already reports whichever VLAN the device returned.
        found_vlan = vlan
        if port is None:
            try:
                info.mac_learning_mac(mac, None, ctx.service)
            except BaseException as e:
                from checks.shared import _legacy_fail
                return _legacy_fail(e, f"mac_learning_mac({mac}, no vlan)")
            port = getattr(info, "port", None)
            m_type = getattr(info, "type", None)
            entry = getattr(info, "entry", None) or {}
            found_vlan = getattr(info, "vlan", None)

        if port is None:
            # Last resort before declaring the AP absent: the authentication
            # session is keyed on the MAC and reports the interface itself, so
            # it finds a port the MAC table does not. A port whose authorization
            # failed can carry a session while the MAC never lands in the table
            # -- reporting "not on this edge" there sends the user to check
            # cabling for what is really an authorization failure.
            port, found_vlan = self._port_from_auth(ctx, mac, hostname, found_vlan)
            m_type = m_type or "auth-session"
            if port is None:
                return self._absent(ctx, mac, vlan, hostname)

        if port == "Drop":
            ctx.state["ap_stop"] = (
                f"the AP's MAC {mac} is in a drop state on {hostname} "
                f"(see AP MAC Learning)."
            )
            return CheckResult(
                CheckStatus.FAIL,
                f"MAC {mac} is learned in VLAN {vlan} on {hostname} but is in "
                f"DROP state, so the AP's traffic is discarded in hardware. "
                f"This is usually a security violation or a MAC-move loop — "
                f"check port security and for the same MAC on another port.",
            )

        if isinstance(port, str) and (("Tu" in port) or ("L2L" in port)):
            ctx.state["ap_stop"] = (
                f"the AP is on a different edge ({port} on {hostname}) "
                f"(see AP MAC Learning)."
            )
            return CheckResult(
                CheckStatus.FAIL,
                f"MAC {mac} is learned in VLAN {vlan} on {hostname} via {port} "
                f"— a LISP-learned entry, meaning the AP is physically cabled "
                f"to a different fabric edge. Re-run this flow against the edge "
                f"the AP is actually connected to.",
            )

        if isinstance(port, str) and port.startswith("Ac"):
            ctx.state["ap_stop"] = (
                f"{mac} is a wireless client, not an AP (see AP MAC Learning)."
            )
            return CheckResult(
                CheckStatus.FAIL,
                f"MAC {mac} is learned on {port} — an access tunnel, which "
                f"carries traffic from clients behind an AP. This address "
                f"belongs to a wireless client, not to an access point. Use "
                f"the AP's own Ethernet MAC.",
            )

        ctx.state["ap_port"] = port
        ctx.state["ap_mac_type"] = m_type
        # The reused DHCP checks (CDP, authentication session) read the port and
        # the module object under their own names. Set here so they need no
        # AP-specific branch.
        ctx.state["xtr_port"] = port
        ctx.state["mac_learning_info"] = info
        # The whole table entry is kept, not just the fields this check reads:
        # the PD pass compares hardware against what IOS reported, so it needs
        # IOS's answer verbatim rather than a summary of it.
        record_pd_object(ctx, "MATM", radkit_hostname=hostname, mac=mac,
                         vlan=found_vlan, entry=entry)

        # Divergence: present, but not in the VLAN it onboards in. The flow
        # continues rather than stopping, because the reason lives downstream --
        # authentication is what put the port in this VLAN, so its grading is
        # the explanation. The terminal judgement is the switchport's access
        # VLAN, which runs after it and stops the flow if it is still wrong.
        if found_vlan is not None and str(found_vlan) != str(vlan):
            ctx.state["ap_vlan_divergent"] = True
            ctx.state["ap_found_vlan"] = found_vlan
            return CheckResult(
                CheckStatus.WARN,
                f"MAC {mac} is learned on {port} of {hostname} ({m_type}), but "
                f"in VLAN {found_vlan} -- not the INFRA_VN VLAN {vlan} the AP "
                f"onboards in. The AP is present and cabled to this edge, so "
                f"this is a VLAN assignment problem rather than a missing AP. "
                f"Authentication is checked next, since what assigned this VLAN "
                f"is what explains it.",
                data={"port": port, "type": m_type, "vlan": found_vlan,
                      "expected_vlan": vlan, "divergent": True},
            )

        return CheckResult(
            CheckStatus.OK,
            f"MAC {mac} is learned in VLAN {found_vlan} on {port} of {hostname} "
            f"({m_type}). Recorded for hardware verification.",
            data={"port": port, "type": m_type, "vlan": found_vlan},
        )

    @staticmethod
    def _port_from_auth(ctx: RunContext, mac, hostname, found_vlan):
        """(port, vlan) from the MAC-keyed authentication session, or (None, ...).

        `show authentication sessions mac <mac> detail` reports `Interface:`
        and, when a policy assigned one, the VLAN -- both derived from the MAC
        alone, so this does not need the port it is being used to find. Failure
        is non-fatal: it leaves the caller to report the AP as absent, which is
        what it would have done anyway.
        """
        try:
            from securitymodules.authenticationsession import (
                AuthenticationSession, parse_show_auth_sessions_detail)
            sess = AuthenticationSession(hostname)
            sess.authenticationsessionmac(mac, ctx.service)
            raw = getattr(sess, "authsessionmac", None)
        except BaseException:
            return None, found_vlan
        if not raw:
            return None, found_vlan

        # Same Mapping-not-dict trap as elsewhere: a GenieParseResult must be
        # used as-is, not re-parsed from its repr.
        parsed = raw if isinstance(raw, Mapping) else parse_show_auth_sessions_detail(str(raw))
        interfaces = (parsed or {}).get("interfaces") or {}
        for intf, body in interfaces.items():
            if not intf or intf == "Unknown":
                continue
            ctx.state["ap_auth_session_prefetch"] = parsed
            for entry in ((body or {}).get("mac_address") or {}).values():
                assigned = ((entry or {}).get("local_policies") or {}).get("assigned_vlan")
                if assigned is not None:
                    return intf, assigned
            return intf, found_vlan
        return None, found_vlan

    @staticmethod
    def _absent(ctx: RunContext, mac, vlan, hostname) -> CheckResult:
        """Not learned: nothing downstream can be established, so stop."""
        ctx.state["ap_stop"] = (
            f"the AP's MAC {mac} is not learned on {hostname} "
            f"(see AP MAC Learning)."
        )
        return CheckResult(
            CheckStatus.FAIL,
            f"MAC {mac} is not in the mac-address-table for VLAN {vlan} on "
            f"{hostname}, so the AP is not currently seen on this edge. Either "
            f"it is cabled elsewhere, its port is down, or it is not powered. "
            f"Confirm the MAC is the AP's Ethernet (not radio) address and that "
            f"it is connected to this switch.",
        )


def _cdp_address(neighbor: dict):
    """The neighbor's management IP, or None.

    Genie reports it as a dict keyed by address. `CDPinfo` passes only
    management_addresses through, so an AP advertising no management address
    yields nothing here even though CDP saw an entry address for it -- which is
    why this is a convenience, not a source of truth.
    """
    addrs = neighbor.get("management_addresses")
    if isinstance(addrs, dict) and addrs:
        return next(iter(addrs))
    if isinstance(addrs, (list, tuple)) and addrs:
        return addrs[0]
    return None


def _is_ap_neighbor(neighbor: dict) -> bool:
    """The CDP signature of a Cisco access point.

    Same test the DHCP flow uses (dhcp_troubleshooting.py:2071): a Cisco
    platform advertising both Router and Trans-Bridge.
    """
    platform = (neighbor.get("platform") or "").lower()
    caps = neighbor.get("capabilities") or ""
    return "cisco" in platform and "Router" in caps and "Trans-Bridge" in caps


def _cdp_version(neighbor: dict):
    """The version number from CDP's free-text version blob, or None.

    CDP carries the version as the device chose to print it: for an AP that is
    a couple of lines of image name and product line ("Cisco AP Software,
    (ap1g8), C9130...") followed by `Version x.y.z`. Only the number is wanted
    on the node, so nothing but an explicit Version is accepted -- an
    unrecognised blob yields None rather than putting the image banner on the
    canvas.
    """
    raw = neighbor.get("software_version") or ""
    # `Version:` and `Version ` both occur -- the colon form is what a C9105
    # (ap1g6a) prints, the bare form what a C9130 (ap1g8) does.
    m = re.search(r"\bVersion:?\s+([0-9][\w.()]*)", raw)
    if m:
        return m.group(1)
    return None


def _cdp_model(neighbor: dict):
    """The neighbor's model, without CDP's leading vendor word.

    CDP reports `cisco C9130AXI-A`; the node label already reads as a Cisco
    device, so the vendor prefix is dropped and only the model kept.
    """
    platform = (neighbor.get("platform") or "").strip()
    if not platform:
        return None
    parts = platform.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "cisco":
        return parts[1].strip()
    return platform


def _ap_topology(ctx, port, ap, neighbors):
    """The nodes and edges that draw the AP, given what CDP found on its port.

    Three shapes, decided by CDP alone -- the MAC is already known to be on
    `port`, so the only open question is what sits between the edge and the AP:

      * AP is the CDP neighbor -- it is cabled straight to the edge. One AP
        node hanging off the edge, labelled with what CDP told us about it.
      * some other device is the neighbor -- an extended node (or any switch)
        is in between. That switch is drawn under its CDP hostname and the AP
        hangs off *it*, because that is where the AP physically is.
      * nothing answers CDP -- the MAC on the port is still proof the AP is
        there, so the AP is drawn directly, tagged so nobody mistakes an
        assumed topology for an observed one.

    Returns (add_nodes, add_edges).
    """
    ap_port = abbrev_port(port)

    if ap is not None:
        label = [ap.get("device_id") or "Access Point"]
        model = _cdp_model(ap)
        if model:
            label.append(model)
        version = _cdp_version(ap)
        if version:
            label.append(f"Version {version}")
        # The address line is always drawn. CDP only reports a management
        # address once the AP has one, so "IP: None" is the meaningful state
        # of an AP that is up on the port but has not yet been addressed --
        # an omitted line would read as if we had not looked.
        ip = _cdp_address(ap)
        label.append(f"IP: {ip}" if ip else "IP: None")
        return [{
            "id": "ap",
            "role": "access-point",
            "label": "\n".join(label),
            "ip": ip or None,
            "connect_to": ctx.state.get("xtr_node_id") or "xtr",
            "edge_label": ap_port,
            "tags": ["AP"],
        }], []

    if neighbors:
        # Whatever answered CDP is between the edge and the AP. Its own model
        # is shown, but no version -- an intermediate switch is context here,
        # not the subject, and CDP may not carry one for it anyway.
        sw = neighbors[0]
        sw_name = sw.get("device_id") or "Switch"
        sw_label = [sw_name]
        sw_model = _cdp_model(sw)
        if sw_model:
            sw_label.append(sw_model)
        sw_ip = _cdp_address(sw)
        if sw_ip:
            sw_label.append(sw_ip)
        remote = sw.get("remoteinterface")
        edge_label = (f"{ap_port} \u2194 {abbrev_port(remote)}"
                      if remote else ap_port)
        return [
            {
                "id": "ap-uplink-sw",
                "role": "underlay-switch",
                "label": "\n".join(sw_label),
                "ip": sw_ip or None,
                "cdp_device_id": sw_name,
                "connect_to": ctx.state.get("xtr_node_id") or "xtr",
                "edge_label": edge_label,
            },
            {
                # The AP hangs off the intermediate switch, not the edge. Its
                # port on that switch is not visible from here -- CDP told us
                # about the switch, and the switch has not been asked.
                "id": "ap",
                "role": "access-point",
                "label": "Access Point",
                "connect_to": "ap-uplink-sw",
                "tags": ["AP", "Port unknown"],
            },
        ], []

    # No CDP at all. The MAC learned on the port is the whole basis for this
    # node, and the tag says so.
    return [{
        "id": "ap",
        "role": "access-point",
        "label": "Access Point",
        "connect_to": ctx.state.get("xtr_node_id") or "xtr",
        "edge_label": ap_port,
        "tags": ["AP", "No CDP Info"],
    }], []


class ApCdpNeighbor(_ApCheck):
    """What CDP sees on the AP's port.

    Reuses `switchingmodules.cdp.CDPinfo` and the same AP signature the DHCP
    flow uses -- a neighbor advertising Cisco, Router and Trans-Bridge
    (dhcp_troubleshooting.py:2071).

    Never fatal, whatever it finds. CDP is best effort here: an AP cabled to an
    extended node is a CDP neighbor of that node, not of this edge, so its
    absence is expected in a supported topology rather than evidence of a
    fault. The MAC being learned on the port is the load-bearing fact, and
    ApMacLearning has already established it.

    The neighbor is still worth reporting: it names the AP, its platform and
    its address, which the later steps and the person reading the run both use.
    """

    name = "AP CDP Neighbor"
    target_node_id = "xtr"
    running_note = "Asking CDP what is on the AP's port…"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        port = ctx.state.get("ap_port")
        if not (hostname and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname).",
            )
        if not port:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's port is unknown (see AP MAC Learning).",
            )

        try:
            from switchingmodules.cdp import CDPinfo
            cdp = CDPinfo(hostname)
            cdp.cdpneighborinterface(port, ctx.service)
            neighbors = getattr(cdp, "cdpneighbors", []) or []
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"CDP on {hostname} {port}")

        ap = next((n for n in neighbors if _is_ap_neighbor(n)), None)

        # Drawn from what CDP found: the AP either hangs off this edge or off
        # whatever switch answered instead. Built once, here, so all three
        # verdicts below render the topology they just described.
        nodes, edges = _ap_topology(ctx, port, ap, neighbors)

        # Consumed by ApAuthenticationSession, which reuses the DHCP validator
        # and reads these two keys.
        ctx.state["is_ap"] = ap is not None
        ctx.state["cdpneighborhost"] = neighbors
        if ap:
            ctx.state["ap_cdp_neighbor"] = ap
            # CDP is the earliest sighting of the AP's address. Recorded so the
            # later "does the AP have an IP" check has something to reconcile
            # device-tracking and the DHCP snooping binding against.
            ip = _cdp_address(ap)
            if ip:
                ctx.state["ap_cdp_ip"] = ip

        if not neighbors:
            return CheckResult(
                CheckStatus.OK,
                f"No CDP neighbor on {hostname} {port}. This does not mean the "
                f"AP is absent — an AP behind an extended node peers with that "
                f"node rather than with this edge, and CDP may simply be "
                f"disabled. The MAC is learned on this port either way.",
                data={"is_ap": False, "cdp_neighbors": 0,
                      "add_nodes": nodes, "add_edges": edges},
            )

        lines = [f"• {n.get('device_id') or '(unknown)'} — "
                 f"platform: {n.get('platform') or '(unknown)'}, "
                 f"port: {n.get('remoteinterface') or '(unknown)'}, "
                 f"capabilities: {n.get('capabilities') or '-'}"
                 for n in neighbors]

        if ap is None:
            return CheckResult(
                CheckStatus.OK,
                f"CDP on {hostname} {port}:\n" + "\n".join(lines) +
                "\n\nNone of these advertises the access-point signature "
                "(Cisco / Router / Trans-Bridge). If the AP is behind an "
                "extended node this is expected — that node is the neighbor "
                "here, and the AP peers with it.",
                data={"is_ap": False, "cdp_neighbors": len(neighbors),
                      "add_nodes": nodes, "add_edges": edges},
            )

        return CheckResult(
            CheckStatus.OK,
            f"CDP on {hostname} {port}:\n" + "\n".join(lines) +
            f"\n\nAccess point confirmed: {ap.get('device_id')} "
            f"({ap.get('platform')}).",
            data={"is_ap": True, "cdp_neighbors": len(neighbors),
                  "add_nodes": nodes, "add_edges": edges},
        )


# Service templates that authorize a port *without* the endpoint having passed
# authentication. A port holding one of these reports "Authorized" while the
# endpoint sits in the critical VLAN, so the status field alone cannot be
# trusted -- this is the exact state that strands an AP outside the INFRA_VN.
# Service templates that mean the port was authorized by critical-auth
# fallback rather than by a successful authentication.
#
# DefaultCriticalVoice_SRV_TEMPLATE is deliberately NOT here. Edge1's stranded
# AP carried it alongside the data template, but it is about voice, and an AP
# has no business in a voice domain either way -- treating it as evidence of a
# critical-auth fallback would fail healthy ports that merely have it bound.
# DefaultCriticalAuthVlan_SRV_TEMPLATE is what actually identifies the
# fallback, and Edge1 carries that too.
# When dot1x runs first, an AP -- which has no dot1x supplicant -- never answers
# and just waits for the timer to expire before MAB runs. Past this many seconds
# that wait is long enough that the AP looks like it failed to onboard rather
# than being slow. Irrelevant when MAB runs first: the AP authenticates at once.
DOT1X_TIMEOUT_WARN_SECONDS = 21

CRITICAL_AUTH_TEMPLATES = (
    "DefaultCriticalAuthVlan_SRV_TEMPLATE",
    "CRITICAL_AUTH_VLAN",
)


def _auth_session_for_mac(auth_details, port, mac):
    """The parsed session for `mac` on `port`, or None.

    Interface names are matched the way the DHCP validator does it
    (dhcp_troubleshooting.py:820-830): a direct hit first, then by the numeric
    part, because the table is keyed by the long form ("TenGigabitEthernet1/0/17")
    while the MAC table reports the short one ("Te1/0/17").
    """
    raw = getattr(auth_details, "authsessionintf", {})
    data = raw() if callable(raw) else raw
    interfaces = (data or {}).get("interfaces", {}) or {}

    intf = interfaces.get(port)
    if intf is None:
        m = re.search(r"\d+(/\d+)+", port or "")
        target = m.group() if m else port
        for name, entry in interfaces.items():
            if target and target in name:
                intf = entry
                break
    if not intf:
        return None
    return (intf.get("mac_address", {}) or {}).get(mac)


def _auth_sessions_on_port(auth_details, port):
    """Every parsed session on `port`, as {mac: entry}.

    Same interface-name matching as `_auth_session_for_mac` -- the table is
    keyed by the long form while the MAC table reports the short one.
    """
    raw = getattr(auth_details, "authsessionintf", {})
    data = raw() if callable(raw) else raw
    interfaces = (data or {}).get("interfaces", {}) or {}

    intf = interfaces.get(port)
    if intf is None:
        m = re.search(r"\d+(/\d+)+", port or "")
        target = m.group() if m else port
        for name, entry in interfaces.items():
            if target and target in name:
                intf = entry
                break
    return (intf or {}).get("mac_address", {}) or {}


def _session_vlan(session):
    """The VLAN this session landed in, or None if it did not override one."""
    return ((session or {}).get("local_policies", {}) or {}).get("assigned_vlan")


def _auth_mode(auth_details, port):
    """"closed", "open", or None when no template is bound to the port.

    Read from the template the interface is bound to, the same way the DHCP
    validator does (dhcp_troubleshooting.py:748-777): find the interface's
    static template, then look for "access-session closed" in its config.
    """
    interface_dict = (getattr(auth_details, "templateinterface", {}) or {}).get("interface", {}) or {}
    info = interface_dict.get(port) or {}
    if not info:
        m = re.search(r"\d+(/\d+)+", port or "")
        target = m.group() if m else port
        for name, data in interface_dict.items():
            if target and target in name:
                info = data
                break
    # The binding method is whatever bound the template, and all of them are
    # real: CatC provisions AP ports via AutoConf, which binds `dynamic /
    # Modified Built-in`, not `static`. Reading only `static` returned None on
    # every such port and graded it as though no template were bound.
    methods = info.get("method", {}) or {}
    template = None
    for _method, data in methods.items():
        template = (data or {}).get("template_name")
        if template:
            break
    if not template:
        return None, None
    config = (getattr(auth_details, "templateconfig", {}) or {}).get(template, []) or []
    mode = "closed" if any("access-session closed" in c for c in config) else "open"
    return mode, template


def _auth_order(config):
    """"dot1x then MAB", "MAB then dot1x", or None.

    Read from the template's service-policy line the same way the DHCP
    validator does (dhcp_troubleshooting.py:779-785).
    """
    for cmd in config or []:
        if "service-policy" in cmd:
            if "1X_MAB" in cmd:
                return "dot1x then MAB"
            if "MAB_1X" in cmd:
                return "MAB then dot1x"
    return None


def _dot1x_timeout(auth_details):
    """(total_seconds, supp_timeout, max_req) or (None, None, None).

    How long a port stays blocked on dot1x before another method gets a turn
    (dhcp_troubleshooting.py:788-800). Matters for an AP: it has no dot1x
    supplicant, so it waits out this whole timer on every link-up before MAB
    can authenticate it.
    """
    params = (getattr(auth_details, "dot1xinterfaceparameter", {}) or {}).get("parameters", {}) or {}
    supp = params.get("SuppTimeout")
    max_req = params.get("MaxReq")
    if not supp or not max_req:
        return None, None, None
    return supp * max_req, supp, max_req


def _critical_auth_templates(session):
    """Names of any critical-auth service templates applied to this session."""
    templates = ((session or {}).get("local_policies", {}) or {}).get("templates", {}) or {}
    return [n for n in templates if any(c.lower() in n.lower() for c in CRITICAL_AUTH_TEMPLATES)]


def _auth_methods(session):
    """(succeeded, failed) method names from the session's method status list."""
    methods = (session or {}).get("method_status", {}) or {}
    ok, bad = [], []
    for name, info in methods.items():
        state = (info or {}).get("state", "") or ""
        low = state.lower()
        if "success" in low:
            ok.append(name)
        elif "failed" in low or "fail" in low:
            bad.append(name)
    return ok, bad


class ApAuthenticationSession(_ApCheck):
    """Whether authentication has left the AP's port usable.

    Reuses the DHCP flow's collection (`authen_session_for_interface`) and its
    validator, then grades for the AP case on top. The extra grading is not
    duplication -- the DHCP validator tests `status != Authorized`, and the
    failure that strands an AP does not look like that:

        Status:  Authorized          <- passes the DHCP test
        mab      Authc Failed        <- but nothing actually authenticated
        Service Template: DefaultCriticalAuthVlan_SRV_TEMPLATE
        Vlan: 4096                   <- and the port is in the critical VLAN

    That is a port RADIUS could not authorize, held open by critical-auth
    fallback. It reports Authorized and an AP on it can never onboard, so it
    has to be caught here by the method results and the applied templates
    rather than by the status field.

    Grading follows the authentication mode, since the two modes promise
    different things:

      * no session at all -- the port is unauthenticated *and unrestricted*,
        so traffic flows. Treated as working, per operator direction.
      * open mode  -- authentication is advisory; what matters is the VLAN the
        port ended up in, and its ACLs.
      * closed mode -- nothing passes until authorization succeeds, so the
        domain must be DATA and the authorization must be real.
    """

    name = "AP Authentication Session"
    target_node_id = "xtr"
    running_note = "Checking authentication on the AP's port…"

    # Where this instance sits in the chain. The check is registered twice, once
    # either side of the interface checks, and each instance runs only in the
    # case it is there for:
    #
    #   early=True  -- only when the MAC was learned outside the INFRA_VN VLAN.
    #     Authentication assigned that VLAN, so its result is the explanation,
    #     and it has to be on the canvas before the interface checks that report
    #     the consequence.
    #   early=False -- the normal path. Facts before verdict: the port's own L2
    #     state is established first, and authentication grades on top of it.
    #
    # Exactly one runs per flow; the other skips silently.
    def __init__(self, early: bool = False):
        self.early = early

    def applies(self, ctx: RunContext) -> bool:
        return bool(ctx.state.get("ap_vlan_divergent")) == self.early

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        port = ctx.state.get("ap_port")
        mac = (ctx.payload.get("mac") or "").strip().lower()
        vlan = ctx.state.get("ap_vlan")

        if not (hostname and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname).",
            )
        if not port:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's port is unknown (see AP MAC Learning).",
            )

        # Collected once by ApAuthTemplate, which runs first. Falling back to
        # collecting it here keeps this check runnable on its own.
        auth_details = ctx.state.get("authensessiondetails")
        if auth_details is None:
            try:
                from securitymodules.authenticationsession import authen_session_for_interface
                auth_details = authen_session_for_interface(hostname, port, ctx.service)
            except BaseException as e:
                from checks.shared import _legacy_fail
                return _legacy_fail(e, f"authen_session_for_interface({hostname}, {port})")
            ctx.state["authensessiondetails"] = auth_details
        # Resolved by ApAuthTemplate, which runs first. Recomputed only when
        # this check is run on its own.
        if "ap_auth_mode" in ctx.state:
            mode = ctx.state["ap_auth_mode"]
            template = ctx.state.get("ap_auth_template")
        else:
            mode, template = _auth_mode(auth_details, port)
        session = _auth_session_for_mac(auth_details, port, mac)

        # Only when a session actually exists. No session means there is
        # nothing for the PD pass to compare hardware against -- an absent
        # session is not a client the hardware should be holding. Stored
        # verbatim, the way the MATM object is, so the comparison is against
        # what IOS reported rather than a summary of it.
        if session:
            record_pd_object(
                ctx, "WiredClient", radkit_hostname=hostname,
                mac=mac, interface=port,
                device_name=session.get("device_name"),
                device_type=session.get("device_type"),
                entry=session,
            )

        if not self.early:
            return self._grade(ctx, hostname, port, mac, vlan, mode, template, session)

        # Divergence path. The grading is wanted -- it is the explanation for
        # the wrong VLAN -- but its `ap_stop` is not: the switchport check that
        # follows is what decides whether the flow can continue, and stopping
        # here would skip the very check that delivers that verdict. So the
        # result is kept and the stop is rolled back.
        before = ctx.state.get("ap_stop")
        result = self._grade(ctx, hostname, port, mac, vlan, mode, template, session)
        if ctx.state.get("ap_stop") != before:
            ctx.state["ap_stop"] = before
            if before is None:
                ctx.state.pop("ap_stop", None)
        return result

    def _grade(self, ctx, hostname, port, mac, vlan, mode, template, session):
        """Turn the collected session into a verdict. Split out to be testable
        against captured device output without reaching for a device."""
        where = f"{hostname} {port}"

        # No session. Per operator direction the port is treated as authorized
        # and working: with nothing authenticating, nothing is restricting
        # traffic either, so this does not block the AP.
        if not session:
            if mode is None:
                return CheckResult(
                    CheckStatus.OK,
                    f"No authentication is configured on {where}. The port is "
                    f"unrestricted, so the AP is free to onboard — there is "
                    f"simply no authentication state to verify.",
                )
            return CheckResult(
                CheckStatus.OK,
                f"No authentication session for {mac} on {where} "
                f"({mode} mode, template '{template}'). Nothing is "
                f"authenticating the AP and nothing is restricting it either, "
                f"so the port is treated as usable.",
            )

        status = (session.get("status") or "").strip()
        domain = (session.get("domain") or "").strip().upper()
        assigned = (session.get("local_policies", {}) or {}).get("assigned_vlan")
        critical = _critical_auth_templates(session)
        ok_methods, failed_methods = _auth_methods(session)
        dev_type = (session.get("device_type") or "").strip()

        detail = [f"Status: {status or 'Unknown'}", f"Domain: {domain or 'Unknown'}"]
        if dev_type:
            detail.append(f"Device-type: {dev_type}")
        if ok_methods:
            detail.append("Passed: " + ", ".join(ok_methods))
        if failed_methods:
            detail.append("Failed: " + ", ".join(failed_methods))
        if assigned is not None:
            detail.append(f"Assigned VLAN: {assigned}")
        if template:
            detail.append(f"Template: {template} ({mode} mode)")
        body = f"Authentication session for {mac} on {where}:\n" + "\n".join(
            f"• {d}" for d in detail)

        # No authentication method ran at all. IBNS 2.0 creates a session for
        # an endpoint whether or not the port authenticates it -- AutoConf
        # opens one off device classification alone -- so an empty method list
        # means the port simply does not do authentication. On such a port
        # `Unauthorized` and `Domain: UNKNOWN` are the expected values, not
        # symptoms: nothing tried, so nothing failed and no domain was ever
        # assigned. Grading them against the closed-mode bar reported a fault
        # on a correctly-working port and stopped the flow with it.
        #
        # Ordered before the authorization gate because it decides whether that
        # gate applies at all. `Domain: UNKNOWN` remains a genuine fault in
        # closed mode, which is graded further down -- it is only inapplicable
        # here, where there is no authentication to be in a domain for.
        if not ok_methods and not failed_methods and not critical:
            ctx.state["ap_auth_none"] = True
            return CheckResult(
                CheckStatus.OK,
                body + "\n\n"
                "No authentication method ran on this port -- the method list "
                "is empty, so neither dot1x nor MAB is doing anything here. The "
                "session exists because IBNS 2.0 opens one regardless (device "
                "classification alone will create it), which is why the status "
                "reads Unauthorized and the domain UNKNOWN. On a port with no "
                "authentication configured those are expected, not faults: "
                "traffic is unrestricted and the AP is free to onboard.",
            )

        # Authorization is the gate, except in open mode. An unauthorized port
        # in closed mode passes no traffic, so nothing downstream -- VLAN,
        # domain, ACLs, which method ran -- changes the outcome or is worth
        # reporting as a separate fault. Open mode forwards whether or not
        # authentication succeeded, so it overrides the gate: the port is
        # usable and grading continues to the things that do decide onboarding.
        #
        # Substring matching is wrong here: "Unauthorized" contains
        # "authorized". IOS prints one word, so compare the whole thing.
        low = (status or "").strip().lower()
        authorized = low == "authorized" or low.startswith("authorized ")
        if not authorized and mode != "open":
            ctx.state["ap_stop"] = f"the AP's port is not authorized on {where}"
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n\n"
                f"The port is not authorized (status: {status or 'Unknown'}), "
                f"so no traffic passes and the AP cannot onboard. Nothing else "
                f"about this session matters until that is resolved."
                + (f"\n\nAuthentication failed: {', '.join(failed_methods)}."
                   if failed_methods else ""),
            )

        # From here the port either claims Authorized or is in open mode.
        # An Authorized claim is not sufficient on its own: critical-auth
        # authorizes a port precisely when authentication did NOT succeed, so
        # the status field is checked against what actually happened before it
        # is believed. In open mode the distinction does not arise -- the port
        # forwards either way -- so the fallback is reported, not fatal.
        if critical and mode != "open":
            ctx.state["ap_stop"] = (
                f"the AP's port fell back to critical authentication on {where}")
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n\n"
                f"The port is authorized by critical-auth fallback "
                f"({', '.join(critical)}), not by a successful "
                f"authentication. That happens when RADIUS is unreachable or "
                f"rejects the endpoint: IOS reports 'Authorized' and drops the "
                f"port into the critical VLAN"
                + (f" ({assigned})" if assigned is not None else "") +
                f" instead of the INFRA_VN"
                + (f" ({vlan})" if vlan else "") +
                ". The AP cannot onboard from there.\n\n"
                "Check RADIUS/ISE reachability from this switch and whether "
                "the AP's MAC is authorized for MAB.",
            )

        # Same open-mode override: a total authentication failure on an
        # open-mode port is reported by _grade_by_mode, which does not block.
        if failed_methods and not ok_methods and mode != "open":
            ctx.state["ap_stop"] = f"authentication failed for the AP on {where}"
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n\n"
                f"Every authentication method failed ({', '.join(failed_methods)}). "
                f"Whatever the port's status field says, nothing has "
                f"authenticated this AP.",
            )
        return self._grade_by_mode(
            ctx, body, where, vlan, mode, status, domain, assigned, session)

    def _grade_by_mode(self, ctx, body, where, vlan, mode, status,
                       domain, assigned, session):
        """Open and closed mode promise different things, so they are graded
        against different bars.

        A closed-mode port reaching here is authorized and got there
        legitimately -- `_grade` gates on both. An open-mode port reaches here
        whatever its status, because open mode forwards regardless.
        """
        low = (status or "").strip().lower()
        authorized = low == "authorized" or low.startswith("authorized ")
        # The VLAN test is the same in both modes and is the one that decides
        # whether the AP can reach its controller at all. Only applied when
        # both numbers are known -- an unreported VLAN means the port is not
        # overriding anything, not that it is wrong.
        vlan_wrong = (
            assigned is not None and vlan is not None
            and str(assigned) != str(vlan)
        )
        if vlan_wrong:
            ctx.state["ap_stop"] = (
                f"the AP's port is in VLAN {assigned}, not the INFRA_VN VLAN {vlan}")
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n\n"
                f"Authentication put this port in VLAN {assigned}, but the AP "
                f"onboards in the INFRA_VN VLAN {vlan}. An AP outside the "
                f"INFRA_VN cannot reach its controller, so onboarding cannot "
                f"proceed until the authorization returns the right VLAN.",
            )

        acls = self._session_acls(session)
        acl_note = ("\n\nACLs applied: " + ", ".join(acls)) if acls else ""

        # In open mode a critical-auth fallback is not fatal -- the port
        # forwards regardless -- but it still means RADIUS did not authenticate
        # this AP, which is worth saying out loud rather than passing green.
        critical = _critical_auth_templates(session)
        if critical and mode == "open":
            return CheckResult(
                CheckStatus.WARN,
                body + "\n\n"
                f"The port fell back to critical authentication "
                f"({', '.join(critical)}), meaning RADIUS is unreachable or "
                f"rejected the AP. Open mode forwards anyway, so onboarding is "
                f"not blocked, but the AP is running unauthenticated."
                + acl_note,
            )

        if mode == "closed":
            # Closed mode passes no traffic except to an authorized session, so
            # the domain it authorized into has to be right too. (Authorization
            # itself was already established by _grade.)
            if domain and domain != "DATA":
                ctx.state["ap_stop"] = f"the AP's port is in the {domain} domain"
                return CheckResult(
                    CheckStatus.FAIL,
                    body + "\n\n"
                    f"The session is in the {domain} domain; an AP must "
                    f"authorize into DATA to onboard in the INFRA_VN.",
                )
            return CheckResult(
                CheckStatus.OK,
                body + "\n\nAuthorized in the DATA domain"
                + (f", VLAN {assigned} matches the INFRA_VN" if assigned is not None
                   else "; no VLAN override, so the port keeps its access VLAN")
                + "." + acl_note,
            )

        # Open mode (or no template bound): authentication is advisory. The
        # port forwards either way, so the VLAN -- checked above -- is what
        # decides onboarding, and a failed authentication is reported without
        # blocking the AP.
        if not authorized:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n\n"
                f"The session is not authorized (status: {status or 'Unknown'}), "
                f"but the port is in open mode, so traffic is not blocked and "
                f"the AP can still onboard. Worth resolving: the AP is running "
                f"without the policy it should have." + acl_note,
            )
        return CheckResult(
            CheckStatus.OK,
            body + "\n\nAuthorized"
            + (f", VLAN {assigned} matches the INFRA_VN" if assigned is not None
               else "; no VLAN override, so the port keeps its access VLAN")
            + "." + acl_note,
        )

    @staticmethod
    def _session_acls(session):
        """Any ACL the authorization pushed onto the port.

        `parse_show_auth_sessions_detail` records a downloadable ACL under
        server_policies as "ACS ACL"; local ACLs arrive as template entries.
        """
        out = []
        for pol in ((session or {}).get("server_policies", {}) or {}).values():
            name = (pol or {}).get("name", "")
            if "ACL" in name.upper():
                val = (pol or {}).get("policies")
                out.append(f"{name}: {val}" if val else name)
        return out


class ApDataSessionCount(_ApCheck):
    """Whether more than one DATA session is authenticated on the AP's port.

    A directly-connected AP is one endpoint and should hold one DATA session.
    Two means either the AP is presenting two MAC addresses, or something
    behind it is being authenticated in its own right -- traffic arriving
    without a VXLAN header, or re-injected onto the port. Neither is fatal on
    its own, so both are warnings: the AP may well onboard, but the port is not
    carrying what it should be carrying.

    Only meaningful when CDP put the AP directly on this port. With a switch in
    between, or with no deterministic CDP answer, multiple sessions are exactly
    what is expected -- the other sessions belong to whatever else is behind
    that switch -- so the check reports and does not warn.
    """

    name = "AP Data Session Count"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        port = ctx.state.get("ap_port")
        auth_details = ctx.state.get("authensessiondetails")
        where = f"{hostname} {port}"

        if not auth_details or not port:
            return CheckResult(
                CheckStatus.OK,
                "No authentication session data was collected for this port, "
                "so there is nothing to count. The preceding authentication "
                "check reports why.",
            )

        sessions = _auth_sessions_on_port(auth_details, port)
        data_sessions = {
            mac: sess for mac, sess in sessions.items()
            if (sess.get("domain") or "").strip().upper() == "DATA"
        }

        if len(data_sessions) <= 1:
            return CheckResult(
                CheckStatus.OK,
                f"{len(data_sessions)} DATA authentication session on {where}, "
                f"which is what a single endpoint should hold.",
            )

        detail = "\n".join(
            f"• {mac}: VLAN {_session_vlan(s) if _session_vlan(s) is not None else 'not overridden'}"
            f", status {(s.get('status') or 'Unknown').strip()}"
            for mac, s in data_sessions.items())
        body = (f"{len(data_sessions)} DATA authentication sessions on "
                f"{where}:\n{detail}")

        # Directness decides whether this is a fault at all. `is_ap` is set by
        # ApCdpNeighbor and is true only when CDP identified an AP on this very
        # port -- a switch in between, or no CDP answer, leaves it false.
        if not ctx.state.get("is_ap"):
            return CheckResult(
                CheckStatus.OK,
                body + "\n\nCDP did not place the AP directly on this port, so "
                "multiple sessions are expected -- they belong to whatever else "
                "sits behind the intervening switch. Reported for context only.",
            )

        vlans = {_session_vlan(s) for s in data_sessions.values()}
        if len(vlans) == 1:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n\nThe AP is directly connected, so this port should "
                "hold one DATA session. Two sessions in the same VLAN means the "
                "AP is presenting more than one MAC address, which is not "
                "expected of a single AP.",
            )
        return CheckResult(
            CheckStatus.WARN,
            body + "\n\nThe AP is directly connected, so this port should hold "
            "one DATA session. These sessions are in different VLANs, which "
            "points at the AP sending traffic without its VXLAN header and "
            "having it authenticated on its own, or at packets being "
            "re-injected onto this port.",
        )


def _authentication_present(auth_details):
    """(verdict, reason) for whether this port authenticates at all.

    verdict is True (a method is configured), False (the device said neither
    is), or None (we could not tell). Three values, not two, because "we did
    not get an answer" must never be reported as "there is no authentication".

    Two commands, because neither alone is conclusive:

      * `show dot1x interface <port>` prints a PAE block when an authenticator
        runs and prints NOTHING when it does not -- which is the same thing a
        failed collection looks like.
      * `show mab interface <port> details` states the negative outright:
        "MAC-Auth-Bypass is not configured on this interface".

    So MAB's explicit no is what turns dot1x's silence into evidence. Only when
    MAB says "not configured" AND dot1x shows no PAE is the absence a fact.
    """
    dot1x = getattr(auth_details, "dot1xinterfaceparameter", None) or {}
    mab = getattr(auth_details, "mabinterfaceparameter", None) or {}

    pae = (dot1x.get("parameters") or {}).get("PAE")
    dot1x_on = bool(pae)
    mab_configured = mab.get("configured")

    if dot1x_on:
        return True, f"dot1x is running on this port (PAE = {pae})"
    if mab_configured:
        return True, "MAB is configured on this port"
    if mab_configured is False:
        return False, ("the switch reports MAC-Auth-Bypass is not configured "
                       "on this interface, and `show dot1x interface` returns "
                       "no authenticator")
    # dot1x silent and MAB unreadable -- absence of evidence only.
    return None, ("neither `show dot1x interface` nor `show mab interface "
                  "details` returned a readable answer for this port")


class ApAuthTemplate(_ApCheck):
    """What authentication the AP's port is configured to do.

    Mirrors the template step of the DHCP validator
    (dhcp_troubleshooting.py:747-804): the bound template, closed vs open, the
    method order, and the dot1x timeout. Configuration only -- what actually
    happened to the session is the next check's job.
    """

    name = "AP Authentication Template"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        port = ctx.state.get("ap_port")
        where = f"{hostname} {port}"

        if not (hostname and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname).",
            )
        if not port:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's port is unknown (see AP MAC Learning).",
            )

        try:
            from securitymodules.authenticationsession import authen_session_for_interface
            auth_details = authen_session_for_interface(hostname, port, ctx.service)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"authen_session_for_interface({hostname}, {port})")

        # Shared with the session and count checks so the port is read once.
        ctx.state["authensessiondetails"] = auth_details

        # Settled from the device's own answers rather than inferred from the
        # template config, which may be unreadable. Published for the session
        # check so it grades an empty method list against a known fact.
        auth_present, auth_reason = _authentication_present(auth_details)
        ctx.state["ap_auth_present"] = auth_present
        ctx.state["ap_auth_present_reason"] = auth_reason

        mode, template = _auth_mode(auth_details, port)
        # Published once here so later checks read the resolved mode rather
        # than parsing the template again.
        ctx.state["ap_auth_mode"] = mode
        ctx.state["ap_auth_template"] = template

        # No template bound is reported, not graded. Plenty of APs sit on ports
        # that use no template at all, so an unbound port is a valid
        # configuration -- and with nothing authenticating, nothing is
        # restricting the AP either.
        if not template:
            if auth_present is False:
                return CheckResult(
                    CheckStatus.OK,
                    f"No authentication is configured on {where}. No template "
                    f"is bound, and {auth_reason}. Nothing is restricting the "
                    f"AP on this port.",
                )
            if auth_present is None:
                return CheckResult(
                    CheckStatus.WARN,
                    f"No authentication template is bound to {where}, but "
                    f"{auth_reason} -- so this cannot be confirmed as a port "
                    f"with no authentication.",
                )
            return CheckResult(
                CheckStatus.WARN,
                f"No authentication template is bound to {where}, yet "
                f"{auth_reason}. Authentication is running without a template "
                f"to describe it.",
            )

        config = (getattr(auth_details, "templateconfig", {}) or {}).get(template, []) or []
        order = _auth_order(config)
        ctx.state["ap_auth_order"] = order

        detail = [f"Template: {template}",
                  f"Mode: {mode or 'Unknown'}",
                  f"Order: {order or 'Unknown'}"]
        total, supp, max_req = _dot1x_timeout(auth_details)
        # Only when dot1x runs first. With MAB first the AP authenticates
        # straight away and never reaches this timer, so it costs it nothing.
        dot1x_first = order == "dot1x then MAB"
        if dot1x_first and total is not None:
            detail.append(
                f"dot1x timeout: {total}s (SuppTimeout {supp} x MaxReq {max_req})")
        body = f"Authentication template on {where}:\n" + "\n".join(
            f"• {d}" for d in detail)

        # An empty config with a template bound means the read failed, not that
        # the template is empty. Saying so beats reporting "open mode", which
        # is what an unreadable template silently looks like.
        if not config and auth_present is False:
            # The template read failed, but the verdict does not depend on it:
            # the device has already stated that neither method is configured,
            # so there is no mode for the template to have got wrong. Reporting
            # "not trustworthy" here would hide an answer we actually have.
            return CheckResult(
                CheckStatus.OK,
                f"No authentication is configured on {where}. Template "
                f"'{template}' is bound but its configuration could not be "
                f"read -- that does not change the verdict, because "
                f"{auth_reason}.",
                data={"auth_template": template, "authentication": "none"},
            )

        if not config:
            return CheckResult(
                CheckStatus.WARN,
                body + f"\n\nTemplate '{template}' is bound but its "
                f"configuration could not be read, so the mode and order above "
                f"are not trustworthy -- an unreadable template reads as open "
                f"mode whether or not it is.",
            )

        # An AP waits out this timer in silence before MAB can authenticate it.
        # Past ~21s that shows up as an AP that eventually joins but takes far
        # longer than it should -- or gives up and retries the link first.
        if dot1x_first and total is not None and total > DOT1X_TIMEOUT_WARN_SECONDS:
            return CheckResult(
                CheckStatus.WARN,
                body + f"\n\nThe dot1x timer is {total}s "
                f"(SuppTimeout {supp} x MaxReq {max_req}). An AP has no dot1x "
                f"supplicant, so it waits out that entire timer on every "
                f"link-up before MAB can authenticate it. Above "
                f"{DOT1X_TIMEOUT_WARN_SECONDS}s that delay is long enough to "
                f"look like an onboarding failure.",
                data={"auth_template": template, "dot1x_timeout": total},
            )

        return CheckResult(
            CheckStatus.OK, body,
            data={"auth_template": template,
                  **({"dot1x_timeout": total} if dot1x_first and total is not None else {})})


# What the device classifier calls a Cisco access point.
#
# "-lap" (lightweight AP) is the whole test, because it is the one part of the
# profile name that is stable across the entire AP range: Catalyst profiles as
# Cisco-CAT-LAP, Aironet as Cisco-AIR-LAP, and the same suffix carries the
# older lines (1700 / 2800 / 3800) that no product-line token would have
# matched.
#
# Model numbers are deliberately NOT matched. An earlier version listed c91 /
# c92 / c93, which was wrong in both directions at once: it missed every AP
# outside the Catalyst 9100-9300 range, and "c93" matches a Catalyst 9300
# SWITCH as readily as an access point. Any such list is a guess at Cisco's
# model range that goes stale with the next release, so the profile name --
# Cisco's own taxonomy -- is the only thing worth keying on.
AP_CLASSIFIER_PROFILES = (
    "-lap", "aironet", "access-point",
)


def _as_mapping(value):
    """A parsed device result as something with .get(), or {}.

    RADKit hands back a GenieParseResult: a Mapping, but NOT a dict, so
    `isinstance(x, dict)` is False for it even though `.get()` works. Guarding
    with a dict test therefore threw away a perfectly good result and reported
    the device as having nothing to say -- which is how a switch that had
    profiled the AP correctly came back as "classifier returned nothing at all".
    """
    return value if isinstance(value, Mapping) else {}


def _classifier_entry(classifier, port, mac):
    """The classifier's entry for `mac`, or None.

    Genie keys the result by MAC and records the port as `port_id`, so the MAC
    is looked up directly and the port only confirms it is the same port.
    """
    macs = _as_mapping(classifier).get("mac_address", {}) or {}
    entry = macs.get(mac)
    if entry is None:
        return None
    # Same numeric-suffix comparison used everywhere else here: Genie
    # normalises to the long form while the MAC table reports the short one.
    m = re.search(r"\d+(/\d+)+", port or "")
    target = m.group() if m else port
    got = entry.get("port_id") or ""
    if target and got and target not in got:
        # The classifier knows this MAC, but on another port. Returned with the
        # mismatch flagged so the check can say where, rather than reporting it
        # as an absent profile.
        return dict(entry, _other_port=got)
    return entry


def _looks_like_ap(entry):
    """Whether the classifier profiled this endpoint as a Cisco AP.

    Reads `profile_name` only. `device_name` carries the model string ("cisco
    C9130AXI-A"), and matching model text is what made a Catalyst switch
    satisfy an AP test -- the classifier's own profile name is the answer to
    this question, so it is the only field consulted.
    """
    blob = str(entry.get("profile_name") or "").lower()
    return any(tok in blob for tok in AP_CLASSIFIER_PROFILES)


class ApDeviceClassifier(_ApCheck):
    """What the switch itself thinks is attached to the AP's port.

    An independent second opinion on CDP. CDP reports what the neighbour
    advertises about itself; the device classifier reports what the switch
    concluded from the traffic it saw. When they disagree about whether this is
    an access point, that is worth knowing -- and it is the classifier's answer
    that RADIUS policy is usually written against.
    """

    name = "AP Device Classifier"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        port = ctx.state.get("ap_port")
        mac = (ctx.payload.get("mac") or "").strip().lower()
        where = f"{hostname} {port}"

        if not (hostname and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname).",
            )
        if not port:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's port is unknown (see AP MAC Learning).",
            )

        try:
            from securitymodules.authenticationsession import AuthenticationSession
            probe = AuthenticationSession(hostname)
            probe.deviceclassifierinterface(port, ctx.service)
            classifier = getattr(probe, "deviceclassifier", {}) or {}
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"device classifier on {where}")

        ctx.state["ap_device_classifier"] = classifier
        entry = _classifier_entry(classifier, port, mac)

        # Directness gates every verdict below. With a switch in between, or no
        # deterministic CDP answer, the classifier is profiling whatever is
        # behind that switch rather than the AP, so its answer is context only.
        direct = bool(ctx.state.get("is_ap"))

        if not entry:
            note = (f"The device classifier has no entry for {mac} on {where}.")
            if not direct:
                return CheckResult(
                    CheckStatus.OK,
                    note + " CDP did not place the AP directly on this port, so "
                    "there is nothing here to profile against it.",
                )
            # "Disabled globally" was asserted here without being read, and
            # that is a different fault with a different fix -- a switch with
            # the feature on and no entry for this endpoint is not the same as
            # a switch that profiles nothing. The table itself answers it: an
            # empty result means the feature is off or has profiled nothing at
            # all, while entries for other endpoints mean it is running and
            # this AP alone is missing.
            others = len(_as_mapping(classifier).get("mac_address", {}) or {})
            if others:
                return CheckResult(
                    CheckStatus.WARN,
                    note + f" The classifier is running on this switch -- it has "
                    f"profiled {others} other endpoint(s) -- so the feature is "
                    f"enabled and this AP alone is unprofiled. Without a profile, "
                    f"AAA has no device attributes to match on and may select a "
                    f"different policy than intended for this AP.",
                )
            return CheckResult(
                CheckStatus.WARN,
                note + " The classifier returned nothing at all for this port, "
                "so it is either disabled on this switch or has profiled "
                "nothing. Confirm with 'show run | include device classifier'. "
                "Without a profile, AAA has no device attributes to match on "
                "and may select a different policy than intended for this AP.",
            )

        # Known to the classifier, but attached somewhere else. Either the AP
        # has moved and this entry has not aged out, or the MAC is present on
        # two ports -- both worth surfacing rather than grading the profile.
        other_port = entry.get("_other_port")
        if other_port:
            if not direct:
                return CheckResult(
                    CheckStatus.OK,
                    f"The device classifier has {mac} on {other_port}, not "
                    f"{port}. CDP did not place the AP directly on this port, "
                    f"so that is expected.",
                )
            return CheckResult(
                CheckStatus.WARN,
                f"The device classifier has {mac} on {other_port}, not {port} "
                f"where the MAC table learned it. The AP has either moved and "
                f"this profile has not aged out yet, or it is being seen on two "
                f"ports -- AAA policy would be matched against the profile from "
                f"the wrong port.",
                data={"classifier_port": other_port},
            )

        profile = entry.get("profile_name") or "Unknown"
        device = entry.get("device_name") or "Unknown"
        detail = [f"Profile: {profile}", f"Device: {device}"]
        if entry.get("profile_type"):
            detail.append(f"Profile type: {entry['profile_type']}")
        if entry.get("proto"):
            detail.append("Protocols: " + ", ".join(entry["proto"]))
        body = f"Device classifier for {mac} on {where}:\n" + "\n".join(
            f"• {d}" for d in detail)

        if _looks_like_ap(entry):
            return CheckResult(
                CheckStatus.OK,
                body + "\n\nThe switch profiled this endpoint as a Cisco access "
                "point, which agrees with CDP.",
                data={"classifier_profile": profile},
            )

        if not direct:
            return CheckResult(
                CheckStatus.OK,
                body + f"\n\nProfiled as '{profile}' rather than an access "
                f"point, but CDP did not place the AP directly on this port -- "
                f"this is most likely whatever sits behind the intervening "
                f"switch. Reported for context only.",
                data={"classifier_profile": profile},
            )

        return CheckResult(
            CheckStatus.WARN,
            body + f"\n\nThe AP is directly connected but the switch profiled "
            f"it as '{profile}', not as an access point. RADIUS profiling may "
            f"pick a different policy for a mis-profiled device, so this is "
            f"worth fixing on the device classifier if the AAA server is "
            f"applying the wrong policy to this AP.",
            data={"classifier_profile": profile},
        )


# The attributes the accounting filter-list is expected to carry. These are what
# get sent to AAA on an accounting update: CDP and LLDP are how the AP announces
# itself, DHCP and HTTP are what ISE profiles it from.
ACCT_FILTER_ATTRIBUTES = ("cdp", "lldp", "dhcp", "http")

ACCT_LIST_NAME = "Def_Acct_List"


def _parse_accounting_config(raw, list_name=ACCT_LIST_NAME):
    """(attributes_present, filter_spec_applied) from `show run | se <list>`.

    Looks for the two halves that have to both be there:

        access-session attributes filter-list list Def_Acct_List
         cdp
         lldp
         dhcp
         http
        access-session accounting attributes filter-spec include list Def_Acct_List

    The list can exist with nothing referencing it, and the filter-spec can
    reference a list that was never defined, so the two are reported separately.
    """
    text = raw or ""
    attrs = []
    in_list = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(rf"access-session\s+attributes\s+filter-list\s+list\s+{re.escape(list_name)}\b",
                    stripped):
            in_list = True
            continue
        # Sub-commands are indented; any unindented line ends the block.
        if in_list:
            if line[:1].strip():
                in_list = False
            elif stripped.lower() in ACCT_FILTER_ATTRIBUTES:
                attrs.append(stripped.lower())
                continue
            else:
                continue
    spec = bool(re.search(
        rf"access-session\s+accounting\s+attributes\s+filter-spec\s+include\s+list\s+{re.escape(list_name)}\b",
        text))
    return attrs, spec


class ApAccountingAttributes(_ApCheck):
    """Whether the switch sends AAA the attributes it needs to profile the AP.

    Without the accounting filter-list and the filter-spec that applies it, the
    switch authenticates the AP but tells AAA almost nothing about it -- no CDP,
    LLDP, DHCP or HTTP attributes.

    Never fatal. Profiling MIGHT not work without these, but authentication can
    still succeed on identity alone -- a MAB policy matched purely on MAC
    address needs none of them. So every shortfall here is a warning about
    profiling, not a verdict on whether the AP can onboard.

    Global configuration, so it is graded regardless of how the AP is attached.
    """

    name = "AP Accounting Attributes"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")

        if not (hostname and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname).",
            )

        try:
            from securitymodules.authenticationsession import AuthenticationSession
            probe = AuthenticationSession(hostname)
            probe.accountingattributes(ctx.service)
            raw = getattr(probe, "accountingconfig", None)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"accounting attributes on {hostname}")

        attrs, spec = _parse_accounting_config(raw)
        ctx.state["ap_accounting_attributes"] = attrs

        if not attrs and not spec:
            return CheckResult(
                CheckStatus.WARN,
                f"No accounting attribute filter is configured on {hostname}. "
                f"Neither the '{ACCT_LIST_NAME}' filter-list nor the "
                f"accounting filter-spec that applies it is present, so the "
                f"switch sends AAA no CDP, LLDP, DHCP or HTTP attributes for "
                f"this AP. Profiling has nothing to match on -- which only "
                f"matters if AAA relies on it; a policy matching purely on MAC "
                f"address still authenticates this AP.",
            )

        missing = [a for a in ACCT_FILTER_ATTRIBUTES if a not in attrs]
        detail = [f"Filter-list '{ACCT_LIST_NAME}': "
                  + (", ".join(attrs) if attrs else "not configured"),
                  f"Accounting filter-spec: "
                  + ("applied" if spec else "not applied")]
        body = f"Accounting attributes on {hostname}:\n" + "\n".join(
            f"• {d}" for d in detail)

        # The list exists but nothing applies it -- configured and inert.
        if attrs and not spec:
            return CheckResult(
                CheckStatus.WARN,
                body + f"\n\nThe filter-list is defined but no accounting "
                f"filter-spec references it, so none of these attributes are "
                f"actually sent to AAA. Profiling may not work; identity-based "
                f"authentication is unaffected.",
            )

        # Applied, but the list it points at was never defined.
        if spec and not attrs:
            return CheckResult(
                CheckStatus.WARN,
                body + f"\n\nThe accounting filter-spec references "
                f"'{ACCT_LIST_NAME}', but that list defines none of the "
                f"expected attributes, so nothing is sent to AAA. Profiling "
                f"may not work; identity-based authentication is unaffected.",
            )

        if missing:
            return CheckResult(
                CheckStatus.WARN,
                body + f"\n\nMissing: {', '.join(missing)}. AAA will not "
                f"receive those attributes, so any profiling policy that "
                f"depends on them will not match this AP. Harmless if "
                f"authentication is identity-based rather than profiled.",
            )

        return CheckResult(
            CheckStatus.OK,
            body + "\n\nAll expected attributes are collected and applied to "
            "accounting, so AAA receives what it needs to profile the AP.",
            data={"accounting_attributes": attrs},
        )


class ApRouteToWlc(_ApCheck):
    """The Edge's route to each WLC's management address.

    First of the three that trace the path to the controller: RIB, then CEF,
    then the physical interfaces the path resolves onto. The AP's CAPWAP join
    rides this path, so a missing route here explains a join failure that
    looks like a wireless problem.

    `route` is a PD-eligible object -- recorded for the later platform pass.
    """

    name = "AP Route to WLC"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        wlcs = ctx.state.get("ap_wlc_candidates") or []
        if not wlcs:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no WLC was discovered (see WLC Discovery).")

        from routingmodules.iprouting import IPRoute
        lines, routes, unreadable = [], {}, []
        for wlc_host, mgmt_ip, _node in wlcs:
            route = IPRoute(mgmt_ip, "default", hostname)
            try:
                route.iproute_prefix(ctx.service, 0)
            except SystemExit:
                # The module exits when there is no route at all, not even a
                # default. That is a finding about the fabric, so it is
                # reported rather than allowed to stop the run.
                lines.append(
                    f"• {wlc_host} ({mgmt_ip}): no route, not even a default "
                    f"route. Traffic to this controller is dropped.")
                routes[mgmt_ip] = {"reachable": False}
                continue
            except BaseException as e:
                unreadable.append(f"{mgmt_ip}: {type(e).__name__}: {e}")
                continue

            prefix = getattr(route, "prefix", None)
            mask = getattr(route, "mask", None)
            proto = str(getattr(route, "protocol", "") or "unknown")
            nexthop = getattr(route, "nexthop", None)
            covering = f"{prefix}/{mask}" if prefix and mask else str(prefix)
            # A default route here is normal in this design: the WLC sits
            # outside the fabric and is reached through the border.
            is_default = str(prefix) == "0.0.0.0"
            routes[mgmt_ip] = {"prefix": covering, "protocol": proto,
                               "nexthop": nexthop, "default_route": is_default,
                               "reachable": True}
            hops = ", ".join(nexthop) if isinstance(nexthop, list) else str(nexthop)
            lines.append(
                f"• {wlc_host} ({mgmt_ip}): via {covering} "
                + ("(default route) " if is_default else "")
                + f"learned by {proto}, next-hop {hops}.")

        if unreadable and not routes:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the route to any WLC from {hostname}:\n"
                + "\n".join(f"• {u}" for u in unreadable),
                data={"errors": unreadable})

        # A WLC whose route could not be read was not checked. Reporting the
        # others as "every WLC" would state a clean result for a path nothing
        # verified, so an unreadable route fails even when a sibling WLC reads
        # fine -- the tool could not answer the question it was asked.
        if unreadable:
            return CheckResult(
                CheckStatus.FAIL,
                f"{hostname} could not be checked against every WLC:\n\n"
                + "\n".join(lines
                             + ["• Could not be read: " + "; ".join(unreadable)]),
                data={"routes": routes, "errors": unreadable})

        ctx.state["ap_wlc_routes"] = routes
        for r in routes.values():
            if r.get("reachable"):
                record_pd_object(ctx, "route", radkit_hostname=hostname,
                                 prefix=r.get("prefix"), vrf="default")

        if any(not r.get("reachable") for r in routes.values()):
            return CheckResult(
                CheckStatus.WARN,
                f"{hostname} cannot route to every WLC:\n\n" + "\n".join(lines),
                data={"routes": routes})

        return CheckResult(
            CheckStatus.OK,
            f"{hostname} has a route to every WLC:\n\n" + "\n".join(lines),
            data={"routes": routes})


class ApCefToWlc(_ApCheck):
    """The Edge's CEF entry for each WLC's management address.

    Second of the three that trace the path to the controller. The RIB says
    what the control plane decided; CEF is what the box actually forwards on.
    They normally agree, and when they do not it is CEF that wins, so a
    mismatch here is a real forwarding fault that a routing check alone
    cannot see.

    The covering prefix is expected to differ from the RIB's: CEF holds
    LISP-derived covering entries (0.0.0.0/1) that the RIB does not, so only
    the resolved next-hop is compared.

    `fib entry` is a PD-eligible object -- recorded for the later platform pass.
    """

    name = "AP CEF to WLC"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        wlcs = ctx.state.get("ap_wlc_candidates") or []
        if not wlcs:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no WLC was discovered (see WLC Discovery).")

        rib = ctx.state.get("ap_wlc_routes") or {}

        from routingmodules.cef import IPCef
        lines, entries, unreadable, mismatches = [], {}, [], []
        for wlc_host, mgmt_ip, _node in wlcs:
            cef = IPCef(mgmt_ip, "default", hostname)
            try:
                cef.get_cef_internal(ctx.service)
            except BaseException as e:
                unreadable.append(f"{mgmt_ip}: {type(e).__name__}: {e}")
                continue

            prefix = getattr(cef, "prefix", None)
            nexthops = getattr(cef, "nexthops", None) or []
            hops = [h.get("nexthop") for h in nexthops if h.get("nexthop")]
            oifs = [h.get("oif") for h in nexthops if h.get("oif")]
            # The (address, interface) pairs are kept intact alongside the
            # flattened lists: an adjacency is keyed on both together, so
            # parallel lists would lose which next-hop sits on which port.
            pairs = [(h.get("nexthop"), h.get("oif")) for h in nexthops
                     if h.get("nexthop")]
            entries[mgmt_ip] = {"prefix": prefix, "nexthops": hops,
                                "oifs": oifs, "pairs": pairs,
                                "sources": getattr(cef, "sources", None),
                                "is_mpls": bool(getattr(cef, "ismpls", False))}

            if not nexthops:
                # A receive/punt entry or a special adjacency. Either way the
                # Edge is not forwarding this prefix anywhere.
                lines.append(
                    f"• {wlc_host} ({mgmt_ip}): CEF entry {prefix} resolves to "
                    f"no next-hop. Traffic to this controller is not forwarded.")
                entries[mgmt_ip]["forwarding"] = False
                continue

            entries[mgmt_ip]["forwarding"] = True
            # CEF is what the box forwards on, so a disagreement with the RIB
            # means the route the previous check reported is not the one in use.
            rib_hop = (rib.get(mgmt_ip) or {}).get("nexthop")
            rib_hops = rib_hop if isinstance(rib_hop, list) else ([rib_hop] if rib_hop else [])
            disagrees = bool(rib_hops) and set(rib_hops) != set(hops)
            if disagrees:
                mismatches.append(mgmt_ip)
            entries[mgmt_ip]["matches_rib"] = not disagrees

            detail = ", ".join(
                f"{h.get('nexthop')} out {h.get('oif')}" for h in nexthops)
            lines.append(
                f"• {wlc_host} ({mgmt_ip}): CEF {prefix} → {detail}."
                + (f" RIB says {', '.join(rib_hops)} — CEF wins, so this is "
                   f"the path in use." if disagrees else ""))

        if unreadable and not entries:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the CEF entry for any WLC from {hostname}:\n"
                + "\n".join(f"• {u}" for u in unreadable),
                data={"errors": unreadable})

        # As in the route check: a WLC whose CEF entry could not be read was
        # not checked, so the others cannot be reported as "every WLC".
        if unreadable:
            return CheckResult(
                CheckStatus.FAIL,
                f"{hostname} could not be checked against every WLC:\n\n"
                + "\n".join(lines
                             + ["• Could not be read: " + "; ".join(unreadable)]),
                data={"cef": entries, "errors": unreadable})

        ctx.state["ap_wlc_cef"] = entries
        for e in entries.values():
            if e.get("prefix"):
                # No separate adjacency object: the PD pass entrypoint
                # validate_route_with_adjacencies() takes only the prefix and
                # derives the adjacencies itself, re-reading CEF and pairing
                # each nexthop with its interface. Recording them here would
                # queue the same hardware walk twice.
                record_pd_object(ctx, "fib_entry", radkit_hostname=hostname,
                                 prefix=e.get("prefix"), vrf="default")


        if any(not e.get("forwarding") for e in entries.values()):
            return CheckResult(
                CheckStatus.WARN,
                f"{hostname} has no CEF next-hop for every WLC:\n\n"
                + "\n".join(lines),
                data={"cef": entries})

        if mismatches:
            return CheckResult(
                CheckStatus.WARN,
                f"{hostname} forwards to the WLC differently than the RIB "
                f"says:\n\n" + "\n".join(lines),
                data={"cef": entries, "mismatches": mismatches})

        return CheckResult(
            CheckStatus.OK,
            f"{hostname} has a CEF path to every WLC:\n\n" + "\n".join(lines),
            data={"cef": entries})


class ApPhysicalPathToWlc(_ApCheck):
    """The physical ports the path to the WLC resolves onto.

    Last of the three that trace the path to the controller. CEF names an
    outgoing interface, but that interface is often not a port: a port-channel
    has to be expanded to its active members, and an SVI has to be resolved
    through ARP and MAC learning to the port the next-hop is actually learnt
    on. This check does that recursion and then reads each resulting port, so
    a saturated or erroring uplink shows up as a cause of a CAPWAP join
    failure rather than as an unexplained wireless fault.

    `interface programming` is PD-eligible -- recorded for the later pass.
    """

    name = "AP Physical Path to WLC"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        wlcs = ctx.state.get("ap_wlc_candidates") or []
        if not wlcs:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no WLC was discovered (see WLC Discovery).")

        cef_state = ctx.state.get("ap_wlc_cef") or {}
        if not cef_state:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — CEF did not resolve a path to the WLC "
                "(see AP CEF to WLC).")

        from routingmodules.cef import IPCef, physical_recursion
        from switchingmodules.interfaces import Interfaces

        lines, ports_by_wlc, unreadable, bad = [], {}, [], []
        # WLCs whose path could not be verified at all. Tracked separately
        # from `bad` so an unchecked path is never reported as a clean one.
        unverified = []
        for wlc_host, mgmt_ip, _node in wlcs:
            entry = cef_state.get(mgmt_ip) or {}
            if not entry.get("forwarding"):
                lines.append(
                    f"• {wlc_host} ({mgmt_ip}): skipped, CEF resolved no "
                    f"next-hop to recurse.")
                unverified.append(mgmt_ip)
                continue

            # physical_recursion reads .vrf and .nexthops off the CEF object,
            # so it is rebuilt here rather than reconstructed from state.
            cef = IPCef(mgmt_ip, "default", hostname)
            try:
                cef.get_cef_internal(ctx.service)
                rec = physical_recursion(cef, hostname)
                total_phys = rec.get_physical_interfaces(ctx.service, 0)
            except SystemExit as e:
                # Incomplete ARP, a MAC learnt nowhere, or a next-hop that
                # resolves to no port. All are fabric faults, so they are
                # reported instead of stopping the run.
                lines.append(f"• {wlc_host} ({mgmt_ip}): {e}")
                bad.append(mgmt_ip)
                continue
            except BaseException as e:
                unreadable.append(f"{mgmt_ip}: {type(e).__name__}: {e}")
                unverified.append(mgmt_ip)
                continue

            # total_phys is a list per next-hop; flatten and de-duplicate
            # while keeping the order the recursion produced.
            ports = []
            for group in (total_phys or []):
                for p in (group if isinstance(group, list) else [group]):
                    if p and p not in ports:
                        ports.append(p)

            if not ports:
                lines.append(
                    f"• {wlc_host} ({mgmt_ip}): the path resolved to no "
                    f"physical port.")
                bad.append(mgmt_ip)
                continue

            port_data = {}
            for port in ports:
                intf = Interfaces(port, hostname)
                try:
                    intf.show_interface(ctx.service)
                except BaseException as e:
                    unreadable.append(f"{port}: {type(e).__name__}: {e}")
                    continue

                # As in ApInterfaceStatus: show_interface returns silently on
                # an empty parse, so an unset oper_status means the read
                # failed -- not that the port is down.
                if intf.operstate is None:
                    unreadable.append(f"{port}: returned nothing usable")
                    port_data[port] = {"readable": False}
                    continue

                oper = str(intf.operstate)
                line = str(intf.linestate or "")
                # Every error counter the parser exposes, not a subset.
                # Giants and runts in particular are what an MTU mismatch on a
                # VXLAN-carrying uplink looks like, which is exactly the fault
                # this check exists to catch -- reading only CRCs and drops
                # called such a link "clean".
                errs = {"crc_errors": _int0(intf.crcerrors),
                        "input_queue_drops": _int0(intf.iqdrops),
                        "output_drops": _int0(intf.outputdrops),
                        "giants": _int0(intf.giants),
                        "runts": _int0(intf.runts),
                        "overruns": _int0(intf.overruns),
                        "unknown_protocol_drops": _int0(intf.unknownproto),
                        "input_errors": _int0(intf.inerrors),
                        "output_errors": _int0(intf.outerrors)}
                is_up = oper.lower() == "up" and (not line or line.lower() == "up")
                noisy = any(v for v in errs.values())
                port_data[port] = dict(errs, oper_status=oper,
                                       line_protocol=line, up=is_up)

                if not is_up:
                    bad.append(mgmt_ip)
                    lines.append(
                        f"• {wlc_host} ({mgmt_ip}) via {port}: {oper}/{line}"
                        + (" (err-disabled)" if intf.errdisabled else "")
                        + ". The path to the controller is broken here.")
                elif noisy:
                    bad.append(mgmt_ip)
                    lines.append(
                        f"• {wlc_host} ({mgmt_ip}) via {port}: up, but "
                        + ", ".join(f"{k.replace('_', ' ')} {v}"
                                    for k, v in errs.items() if v) + ".")
                else:
                    lines.append(
                        f"• {wlc_host} ({mgmt_ip}) via {port}: up/up, clean.")

            # Any unreadable port is a failure, not a partial success. A port
            # that will not parse is one the device does not have (`% Invalid
            # input`), so the recursion resolved onto something that is not a
            # real interface -- the path cannot be called verified even if a
            # sibling port-channel member reads clean.
            if any(not d.get("readable", True) for d in port_data.values()):
                unverified.append(mgmt_ip)
            ports_by_wlc[mgmt_ip] = port_data

        if unreadable and not ports_by_wlc:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not resolve the physical path to any WLC from "
                f"{hostname}:\n" + "\n".join(f"• {u}" for u in unreadable),
                data={"errors": unreadable})

        ctx.state["ap_wlc_physical_ports"] = ports_by_wlc
        for pd in ports_by_wlc.values():
            for port, d in pd.items():
                if d.get("readable", True):
                    record_pd_object(ctx, "IFM", radkit_hostname=hostname,
                                     interface=port)

        if unreadable:
            lines.append("• Could not be read: " + "; ".join(unreadable))

        if bad:
            return CheckResult(
                CheckStatus.WARN,
                f"The physical path from {hostname} to the WLC has "
                f"problems:\n\n" + "\n".join(lines),
                data={"ports": ports_by_wlc})

        if unverified:
            # Nothing was found wrong, but nothing was confirmed right
            # either. Saying "clean" here would hide the gap.
            return CheckResult(
                CheckStatus.FAIL,
                f"The physical path from {hostname} to the WLC could not be "
                f"verified:\n\n" + "\n".join(lines),
                data={"ports": ports_by_wlc, "unverified": unverified})

        return CheckResult(
            CheckStatus.OK,
            f"The physical path from {hostname} to every WLC is up and "
            f"clean:\n\n" + "\n".join(lines),
            data={"ports": ports_by_wlc})


class ApInterfaceStatus(_ApCheck):
    """The AP port's line state, load and error counters.

    A port can be up and still be the reason an AP misbehaves: input errors,
    CRCs and drops point at cabling or duplex, while a saturated link explains
    loss that looks like a fabric fault. Read here so those are on record
    before the LISP and tunnel checks interpret what they see.

    Platform-independent. The interface programming behind it is a PD object
    for the later pass.
    """

    name = "AP Interface Status"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        port = ctx.state.get("ap_port")
        if not port:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's switchport is unknown (see AP MAC "
                "Learning).")

        from switchingmodules.interfaces import Interfaces
        intf = Interfaces(port, hostname)
        try:
            intf.show_interface(ctx.service)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"show interface {port}")

        # show_interface returns silently when the parse yields nothing, so an
        # unset oper_status means the read failed -- NOT that the port is down.
        if intf.operstate is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the state of {port} on {hostname}: "
                f"`show interface {port}` returned nothing usable, so the "
                f"port's condition is unknown.",
                data={"port": port})

        oper = str(intf.operstate)
        line = str(intf.linestate or "")
        data = {"port": port, "oper_status": oper, "line_protocol": line,
                "mtu": intf.mtu, "speed": intf.speed, "bandwidth": intf.bw,
                "description": intf.description,
                "crc_errors": _int0(intf.crcerrors),
                "giants": _int0(intf.giants), "runts": _int0(intf.runts),
                "input_queue_drops": _int0(intf.iqdrops),
                "output_drops": _int0(intf.outputdrops),
                "overruns": _int0(intf.overruns),
                "unknown_protocol_drops": _int0(intf.unknownproto),
                "input_errors": _int0(intf.inerrors),
                "output_errors": _int0(intf.outerrors),
                "in_rate_pkts": _int0(intf.inputpps),
                "out_rate_pkts": _int0(intf.outputpps)}

        if oper.lower() != "up" or (line and line.lower() != "up"):
            return CheckResult(
                CheckStatus.WARN,
                f"{port} on {hostname} is {oper}/{line}"
                + (f" and is err-disabled" if intf.errdisabled else "")
                + f". The AP cannot onboard through a port that is not up.",
                data=data)

        errors = {"CRC error": _int0(intf.crcerrors),
                  "giant": _int0(intf.giants),
                  "runt": _int0(intf.runts),
                  "overrun": _int0(intf.overruns),
                  "unknown protocol drop": _int0(intf.unknownproto),
                  "input error": _int0(intf.inerrors),
                  "output error": _int0(intf.outerrors),
                  "input queue drop": _int0(intf.iqdrops),
                  "output drop": _int0(intf.outputdrops)}
        seen = {k: v for k, v in errors.items() if v}

        lines = [f"• {port} is up/{line}, {intf.speed or 'unknown speed'}, "
                 f"MTU {intf.mtu or '?'}."]
        if intf.description:
            lines.append(f"• Description: {intf.description}")
        lines.append(f"• Load: {_int0(intf.inputpps)} pps in, "
                     f"{_int0(intf.outputpps)} pps out.")

        if seen:
            lines.append(
                "• Counters: "
                + ", ".join(f"{v} {k}{'s' if v != 1 else ''}"
                            for k, v in seen.items())
                + ". These accumulate since the counters were last cleared, "
                  "so check whether they are still incrementing before "
                  "treating them as the cause.")
            return CheckResult(CheckStatus.WARN, "\n".join(lines), data=data)

        lines.append("• No CRC errors, giants, runts or drops recorded.")
        return CheckResult(CheckStatus.OK, "\n".join(lines), data=data)


class ApSwitchportState(_ApCheck):
    """Whether the AP's port is an access port in the right VLAN.

    An AP onboards on an access port in the INFRA_VN VLAN. A routed port, a
    trunk, or the wrong access VLAN all leave the AP unable to reach its
    controller, so this is where the port's own L2 configuration is graded.

    Platform-independent: what the port is configured to be. The programming
    behind it is a PD object for the later pass.
    """

    name = "AP Switchport State"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        port = ctx.state.get("ap_port")
        vlan = ctx.state.get("ap_vlan")
        where = f"{hostname} {port}"

        if not (hostname and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname).",
            )
        if not port:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's port is unknown (see AP MAC Learning).",
            )

        try:
            from switchingmodules.interfaces_l2 import interface_switchport
            swport = interface_switchport(port, hostname)
            swport.switchport_status(ctx.service)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"switchport_status({hostname}, {port})")

        # The module leaves switchport_enable unset when the command returned
        # nothing, and sets it False on a routed port. Both mean the same thing
        # here: there is no L2 port for the AP to onboard on.
        enabled = getattr(swport, "switchport_enable", None)
        if not enabled:
            ctx.state["ap_stop"] = f"{port} on {hostname} is not a switchport"
            return CheckResult(
                CheckStatus.FAIL,
                f"{where} is not a switched port. An AP onboards on an L2 "
                f"access port in the INFRA_VN VLAN, so a routed interface "
                f"cannot carry it -- nothing further can be verified on this "
                f"port until it is configured as a switchport.",
            )

        admin = getattr(swport, "adminmode", None) or "Unknown"
        oper = getattr(swport, "opermode", None) or "Unknown"
        access_vlan = getattr(swport, "accessvlan", None)
        voice_vlan = getattr(swport, "voicevlan", None)
        native_vlan = getattr(swport, "nativevlan", None)
        native_tag = getattr(swport, "nativetagging", None)

        detail = [f"Admin mode: {admin}", f"Operational mode: {oper}",
                  f"Access VLAN: {access_vlan if access_vlan is not None else 'none'}"]
        if voice_vlan and str(voice_vlan).lower() not in ("none", "0"):
            detail.append(f"Voice VLAN: {voice_vlan}")
        if native_vlan is not None:
            detail.append(f"Native VLAN: {native_vlan}"
                          + (" (tagged)" if native_tag else ""))
        body = f"Switchport state on {where}:\n" + "\n".join(
            f"• {d}" for d in detail)

        # Queued whatever the verdict below: the PD pass compares hardware
        # against what IOS reported, and a port IOS calls access while the
        # hardware programmed something else is exactly the mismatch worth
        # catching. Stored verbatim, the way the MATM object is.
        record_pd_object(
            ctx, "IFM", radkit_hostname=hostname,
            interface=port, admin_mode=admin, oper_mode=oper,
            access_vlan=access_vlan, voice_vlan=voice_vlan,
            native_vlan=native_vlan, native_tagging=native_tag,
            trunking=getattr(swport, "istrunking", None),
            trunk_vlans=getattr(swport, "allowedvlanstrunk", None),
            trunk_negotiation=getattr(swport, "trunknegotiation", None),
        )

        # Operational mode is the whole test: what the port is actually doing,
        # not what it is configured to try. Admin mode may say "dynamic auto"
        # on a port that negotiated its way to access, and that port is fine.
        if "access" not in (oper or "").lower():
            ctx.state["ap_stop"] = (
                f"{port} on {hostname} is not in access mode ({oper})")
            trunk_note = (
                " On a trunk the AP's traffic is tagged and never lands in the "
                "INFRA_VN, so it cannot reach its controller."
                if "trunk" in (oper or "").lower() else "")
            return CheckResult(
                CheckStatus.FAIL,
                body + f"\n\nThe port's operational mode is '{oper}', not "
                f"access. An AP onboards on an access port, so nothing "
                f"downstream will work until this is corrected." + trunk_note,
            )

        # Access VLAN against the INFRA_VN. Only graded when both are known --
        # an unreported VLAN is a gap in what we read, not a fault on the port.
        if access_vlan is not None and vlan is not None:
            if str(access_vlan) != str(vlan):
                ctx.state["ap_stop"] = (
                    f"{port} is in VLAN {access_vlan}, not the INFRA_VN VLAN {vlan}")
                return CheckResult(
                    CheckStatus.FAIL,
                    body + f"\n\nThe port's access VLAN is {access_vlan}, but "
                    f"the AP onboards in the INFRA_VN VLAN {vlan}. An AP "
                    f"outside the INFRA_VN cannot reach its controller.",
                )
            return CheckResult(
                CheckStatus.OK,
                body + f"\n\nAn access port in VLAN {access_vlan}, which is the "
                f"INFRA_VN VLAN. The AP is on the right L2 segment.",
                data={"access_vlan": access_vlan},
            )

        return CheckResult(
            CheckStatus.WARN,
            body + "\n\nThe port is in access mode, but "
            + ("the INFRA_VN VLAN is unknown, so the access VLAN could not be "
               "confirmed against it." if vlan is None
               else "no access VLAN was reported, so it could not be compared "
                    f"against the INFRA_VN VLAN {vlan}."),
        )


class ApSviState(_ApCheck):
    """The INFRA_VN gateway the AP relies on to reach its controller.

    The AP's default gateway is the SVI for its VLAN, so nothing beyond L2
    works if this interface is down, in the wrong VRF, or has no address. Four
    questions, each of which strands the AP on its own:

      * Is it up? A shutdown or line-protocol-down SVI leaves the AP with L2
        connectivity and nothing else.
      * Is it in the global routing table? The AP's traffic to the WLC is
        routed in the underlay's table. An SVI parked in a VRF sends it
        somewhere the WLC is not.
      * Does it have helper addresses? Without one the AP's DHCP DISCOVER is
        never relayed, so it never gets an address -- the failure the DHCP
        flow exists to chase, caught here before it is triggered.
      * Is CEF enabled on it? Process switching an AP's CAPWAP traffic is a
        performance problem rather than an outage, so it is reported but does
        not fail the check on its own.

    Collection is `switchingmodules.dhcp.DHCPDevice.svi_configuration`, reused
    rather than reimplemented: it already issues `show ip interface vlan <id>`
    and extracts exactly these fields. Only the two SVI methods are called --
    the snooping and relay collection in that class belongs to the DHCP flow.
    """

    name = "AP SVI State"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        vlan = ctx.state.get("ap_vlan")

        if not (hostname and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname).",
            )
        if not vlan:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's VLAN is unknown (see INFRA VN VLAN).",
            )

        try:
            from switchingmodules.dhcp import DHCPDevice
            info = DHCPDevice(hostname)
            info.svi_configuration(vlan, ctx.service)
            info.svi_running_config(vlan, ctx.service)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"svi_configuration(vlan {vlan}) on {hostname}")

        # Shared so the later routing and DHCP checks read the SVI once.
        ctx.state["ap_svi_info"] = info

        svi = getattr(info, "svi", None)
        where = f"{hostname} Vlan{vlan}"

        # No SVI at all is terminal: the VLAN has no gateway on this switch, so
        # every later check that depends on routing has nothing to stand on.
        if not svi:
            ctx.state["ap_stop"] = (
                f"VLAN {vlan} has no SVI on {hostname}, so the AP has no gateway")
            return CheckResult(
                CheckStatus.FAIL,
                f"No SVI exists for VLAN {vlan} on {hostname}. The AP has no "
                f"default gateway, so it cannot reach the WLC even with the "
                f"port and VLAN correct.",
            )

        # `svivrf` is set only inside svi_configuration's ipv4 branch, so it is
        # genuinely absent on an SVI with no address -- read defensively rather
        # than assume the attribute exists. svi_running_config sets `vrf`
        # separately from the running config, with "default" as its fallback.
        vrf = getattr(info, "svivrf", None) or getattr(info, "vrf", None) or "default"
        enabled = bool(getattr(info, "svienabled", False))
        oper = (getattr(info, "svioperational", None) or "down").lower()
        helpers = getattr(info, "helper_address", None) or []
        cef = bool(getattr(info, "cef_state", False))
        prefix = getattr(info, "prefix", None)
        mask = getattr(info, "mask", None)

        address = f"{prefix}/{mask}" if prefix else "none"
        detail = [
            f"SVI: {svi}",
            f"State: {'up' if enabled else 'administratively down'} / {oper}",
            f"Address: {address}",
            f"VRF: {vrf}",
            f"Helper addresses: {', '.join(helpers) if helpers else 'none'}",
            f"CEF: {'enabled' if cef else 'disabled'}",
        ]
        body = f"INFRA_VN gateway on {where}:\n" + "\n".join(f"• {d}" for d in detail)

        # Down is terminal. The AP may hold an address from before the SVI went
        # down, so this is not the same as "no IP" -- but nothing it sends
        # leaves the VLAN, and every routing check after this would report a
        # failure whose real cause is this one.
        if not enabled or oper != "up":
            ctx.state["ap_stop"] = f"{svi} on {hostname} is down"
            return CheckResult(
                CheckStatus.FAIL,
                body + f"\n\nThe AP's gateway is down, so nothing it sends "
                f"leaves the VLAN. Traffic to the WLC cannot be routed until "
                f"{svi} is up.",
                data={"svi": svi, "svi_state": oper},
            )

        # The AP reaches its WLC through the underlay's own table. An SVI in a
        # VRF routes it into a table the WLC is not in, which looks like a
        # reachability problem anywhere else it is diagnosed.
        if vrf.lower() not in ("default", "global"):
            return CheckResult(
                CheckStatus.FAIL,
                body + f"\n\nThe INFRA_VN gateway is in VRF '{vrf}', not the "
                f"global routing table. An AP reaches its controller through "
                f"the global table, so traffic to the WLC is being routed "
                f"somewhere the WLC is not.",
                data={"svi": svi, "svi_vrf": vrf},
            )

        if not prefix:
            return CheckResult(
                CheckStatus.FAIL,
                body + f"\n\n{svi} is up but has no IP address, so it cannot "
                f"act as a gateway and cannot relay the AP's DHCP requests.",
                data={"svi": svi},
            )

        # Both of these are requirements, not preferences.
        #
        # An AP has no other way to get an address: it does not come with a
        # static one, so a gateway that does not relay DHCP cannot onboard an
        # AP at all. An AP already holding a lease keeps working until it
        # renews, which makes this a fault that surfaces later, on a reboot or
        # a lease expiry, long after the change that caused it.
        #
        # CEF is required rather than merely desirable here: the fabric data
        # path is built on it, and an SVI that is process switching is not
        # forwarding the AP's traffic the way the design expects.
        problems = []
        if not helpers:
            problems.append(
                f"{svi} has no helper address, so a DHCP request from the AP "
                f"is never relayed to a server. An AP has no static address to "
                f"fall back on, so it cannot onboard through this gateway")
        if not cef:
            problems.append(
                f"CEF is not enabled on {svi}. The fabric data path requires "
                f"it, so the AP's traffic is not being forwarded as designed")

        if problems:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n\n" + "\n\n".join(problems),
                data={"svi": svi, "svi_vrf": vrf,
                      "helper_addresses": helpers, "cef": cef},
            )

        return CheckResult(
            CheckStatus.OK, body,
            data={"svi": svi, "svi_vrf": vrf,
                  "helper_addresses": helpers, "cef": cef},
        )


# ---------------------------------------------------------------------------
# Spec 3b.3 -- L2 LISP.
#
# Graded as a sequence, in the order the fabric builds it: the instance has to
# exist before the AP's MAC can be a dynamic EID, it has to be a dynamic EID
# before it lands in the ETR database, and it has to be in the database before
# a control plane can hear about it. Each step is a separate check so the
# canvas says which link in that chain broke, rather than one node that fails
# for four different reasons.
#
# routingmodules.lisp.l2_lisp_parameters already collects all of this, but it
# reports failure by calling sys.exit() -- fine for the CLI it was written for,
# fatal for a streamed run, and the reason the existing E-W checks can only
# ever return OK. The commands and parse shapes below are the same ones it
# uses; what differs is that a "no" here returns a verdict instead of ending
# the process.
# ---------------------------------------------------------------------------

def _l2_dyneid_summary(ctx, hostname, vlan):
    """(iid, eids, error) from `show lisp eid-table vlan <vlan> dynamic-eid summary`.

    `iid` is the L2 instance for the AP's VLAN and `eids` the MACs the switch
    has learned into it. An empty instance is a real state -- a VLAN can be
    mapped to LISP with nothing learned yet -- so it is reported as an empty
    list, not as an error.
    """
    from radkit_cli import get_single_output_genie
    cmd = f"show lisp eid-table vlan {vlan} dynamic-eid summary"
    parsed = _as_mapping(get_single_output_genie(hostname, cmd, ctx.service))
    if not parsed:
        return None, [], f"`{cmd}` returned nothing"

    try:
        instances = parsed["lisp_id"][0]["instance_id"]
    except (KeyError, IndexError, TypeError):
        return None, [], f"`{cmd}` returned no instance"

    iid = next(iter(instances), None)
    if not iid:
        return None, [], f"no L2 LISP instance is mapped to VLAN {vlan}"

    # The dyn-EID group is named after the instance it belongs to.
    body = _as_mapping(instances.get(iid))
    group = _as_mapping(body.get("dynamic_eids")).get(f"Auto-L2-group-{iid}")
    eids = list((_as_mapping(group).get("eids") or {}))
    return iid, eids, None


class ApL2LispInstance(_ApCheck):
    """Whether an L2 LISP instance exists for the AP's VLAN.

    The first link in the chain. Without an instance the VLAN is not part of
    the fabric's L2 overlay at all, so nothing after this can be true: no
    dynamic EID, no database entry, no registration.
    """

    name = "AP L2 LISP Instance"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        vlan = ctx.state.get("ap_vlan")

        if not (hostname and ctx.service):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — required state missing (service / xtr_hostname).")
        if not vlan:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's VLAN is unknown (see INFRA VN VLAN).")

        try:
            iid, eids, err = _l2_dyneid_summary(ctx, hostname, vlan)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"L2 LISP dynamic-eid summary for VLAN {vlan}")

        if err or not iid:
            return CheckResult(
                CheckStatus.FAIL,
                f"No L2 LISP instance is mapped to VLAN {vlan} on {hostname} "
                f"({err or 'no instance returned'}). The AP's VLAN is not part "
                f"of the L2 overlay, so its MAC cannot be registered to the "
                f"fabric.",
            )

        # Both published: the later steps read the instance, and the EID list
        # is the same output the next check grades -- collected once.
        ctx.state["ap_l2_iid"] = iid
        ctx.state["ap_l2_dyneids"] = eids

        return CheckResult(
            CheckStatus.OK,
            f"VLAN {vlan} on {hostname} is mapped to L2 LISP instance {iid}, "
            f"with {len(eids)} MAC(s) learned as dynamic EIDs.",
            data={"l2_iid": iid, "dyneid_count": len(eids)},
        )


class ApL2LispDynamicEid(_ApCheck):
    """Whether the AP's MAC was learned as a dynamic EID in that instance.

    The switch learns a MAC into the dyn-EID group when it sees traffic from it
    on a LISP-enabled VLAN. A MAC that the switch knows at L2 but that never
    became a dynamic EID is the signature of a missing `database-mapping` for
    the VLAN -- the AP is present on the wire, but the fabric was never told to
    treat its VLAN as an EID space.
    """

    name = "AP L2 LISP Dynamic EID"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        vlan = ctx.state.get("ap_vlan")
        iid = ctx.state.get("ap_l2_iid")
        mac = normalize_mac(ctx.payload.get("mac"))

        if not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the L2 LISP instance is unknown (see AP L2 LISP "
                "Instance).")
        if not mac:
            return CheckResult(
                CheckStatus.SKIP, "Skipped — the AP's MAC is unknown.")

        eids = ctx.state.get("ap_l2_dyneids") or []
        # Compared normalized on both sides: the device prints dotted-hex, but
        # the MAC reaching us came from the payload and may be in any format.
        if mac not in {normalize_mac(e) for e in eids}:
            return CheckResult(
                CheckStatus.FAIL,
                f"The AP's MAC {mac} is not a dynamic EID in L2 LISP instance "
                f"{iid} on {hostname}. The switch has the AP at L2, but its "
                f"MAC was never learned into the LISP dynamic-EID group for "
                f"VLAN {vlan} -- check that `database-mapping` is configured "
                f"for this VLAN.",
                data={"l2_iid": iid, "mac": mac},
            )

        return CheckResult(
            CheckStatus.OK,
            f"The AP's MAC {mac} is a dynamic EID in L2 LISP instance {iid} on "
            f"{hostname}.",
            data={"l2_iid": iid, "mac": mac},
        )


class ApL2LispDatabase(_ApCheck):
    """Whether the AP's MAC is in the ETR mapping database.

    The database is what this switch will register to the control plane. A MAC
    that is a dynamic EID but absent here has been learned and then not
    accepted into the mapping database -- so nothing is ever registered for it,
    and the rest of the fabric has no way to reach the AP.

    The unfiltered command is deliberate: `... ethernet database <mac>/48` is
    rejected by the device, so the whole table is read and searched, which is
    what the CLI module does too.
    """

    name = "AP L2 LISP Database"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        iid = ctx.state.get("ap_l2_iid")
        mac = normalize_mac(ctx.payload.get("mac"))

        if not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the L2 LISP instance is unknown (see AP L2 LISP "
                "Instance).")
        if not mac:
            return CheckResult(
                CheckStatus.SKIP, "Skipped — the AP's MAC is unknown.")

        from radkit_cli import get_single_output_genie
        cmd = f"show lisp instance-id {iid} ethernet database"
        try:
            parsed = _as_mapping(get_single_output_genie(hostname, cmd, ctx.service))
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, cmd)

        try:
            entries = parsed["lisp_id"][0]["instance_id"][iid]["entries"]["eids"]
        except (KeyError, IndexError, TypeError):
            return CheckResult(
                CheckStatus.FAIL,
                f"The L2 LISP database for instance {iid} on {hostname} could "
                f"not be read, so it cannot be confirmed that the AP's MAC is "
                f"registered with the fabric.",
            )

        # Database keys carry the /48 prefix length.
        found = None
        for key in entries:
            if normalize_mac(str(key).split("/")[0]) == mac:
                found = _as_mapping(entries.get(key))
                break

        if found is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"The AP's MAC {mac} is not in the L2 LISP database for "
                f"instance {iid} on {hostname}. It was learned as a dynamic "
                f"EID but never entered the mapping database, so this switch "
                f"registers nothing for the AP and the rest of the fabric "
                f"cannot reach it.",
                data={"l2_iid": iid, "mac": mac},
            )

        ctx.state["ap_l2_db_entry"] = found

        # The `do not register` flag is deliberately not graded here. It is
        # ordinary across a healthy instance -- entries carry it routinely --
        # so failing on it would report a false fault. Whether the AP is
        # actually registered is settled by the next check against the control
        # plane itself, which is the real evidence either way.

        return CheckResult(
            CheckStatus.OK,
            f"The AP's MAC {mac} is in the L2 LISP database for instance {iid} "
            f"on {hostname}, and is eligible for registration.",
            data={"l2_iid": iid, "mac": mac},
        )


class ApL2LispRegistration(_ApCheck):
    """Whether every control plane has acknowledged the AP's registration.

    The switch having the AP in its database is not the same as the fabric
    knowing where the AP is. The database entry names each map-server this
    switch registered the MAC to and whether that map-server acknowledged it.
    An ACK of No means the registration was sent and never confirmed, so that
    control plane cannot answer map-requests for the AP -- and a site normally
    has more than one, with a MAC acked on one and not the other being a real
    and common fault that reporting a single verdict would hide.

    The ack column is read from the switch's own output rather than by querying
    each control plane. That is deliberate: the answer is already here, and a
    per-CP query costs a session to every CP on every run to learn what this
    one command already states. A CP whose ack is missing is what triggers full
    LISP session troubleshooting from this edge to that CP.

    The filtered form of the command is required. `... database` unfiltered
    prints locators but no map-server block, and appending `/48` to the MAC is
    rejected by the device -- only the bare MAC yields the ack table.
    """

    name = "AP L2 LISP Registration"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        iid = ctx.state.get("ap_l2_iid")
        mac = normalize_mac(ctx.payload.get("mac"))

        if not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the L2 LISP instance is unknown (see AP L2 LISP "
                "Instance).")
        if not mac:
            return CheckResult(
                CheckStatus.SKIP, "Skipped — the AP's MAC is unknown.")

        from radkit_cli import get_single_output_genie
        cmd = f"show lisp instance-id {iid} ethernet database {mac}"
        try:
            parsed = _as_mapping(get_single_output_genie(hostname, cmd, ctx.service))
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, cmd)

        try:
            entry = _as_mapping(parsed["lisp_id"][0]["instance_id"][iid])
        except (KeyError, IndexError, TypeError):
            entry = {}

        servers = _as_mapping(entry.get("map_servers"))
        if not servers:
            return CheckResult(
                CheckStatus.FAIL,
                f"The L2 LISP database entry for {mac} on {hostname} names no "
                f"map-server, so this switch has registered the AP nowhere in "
                f"instance {iid} and no other fabric node can learn where the "
                f"AP is.",
                data={"l2_iid": iid, "mac": mac},
            )

        # The ACK rows say who acknowledged, but not who this site depends on.
        # With SDA transit an EID is also registered to transit control planes,
        # and those are not this site's to be healthy or not -- so the site's
        # own map-servers are enumerated separately and the rows are graded
        # against that set. A CP in the rows but not in the set is reported as
        # context, never as a fault of this site.
        try:
            site_cps = _site_map_servers(ctx, hostname, iid, "ethernet")
        except BaseException:
            site_cps = []

        acked, missing, other = [], [], []
        for cp, body in servers.items():
            body = _as_mapping(body)
            # Anything that is not an explicit yes is treated as not acked:
            # "No", "never", and an absent value all mean the same thing here,
            # which is that this control plane has not confirmed it holds the
            # AP. Guessing in the other direction would report an unreachable
            # CP as healthy.
            is_acked = str(body.get("ack") or "").strip().lower() == "yes"
            if site_cps and cp not in site_cps:
                other.append((cp, "acknowledged" if is_acked
                              else f"ACK {str(body.get('ack') or 'none').strip()}"))
            elif is_acked:
                acked.append((cp, body.get("uptime")))
            else:
                missing.append((cp, str(body.get("ack") or "none").strip()))

        # Every map-server the site expects, that the entry never mentions at
        # all. Absent from the ACK table is not "acknowledged".
        listed = set(servers.keys())
        for cp in site_cps:
            if cp not in listed:
                missing.append((cp, "not listed"))

        return self._grade(ctx, hostname, iid, mac, acked, missing, other)

    @staticmethod
    def _grade(ctx, hostname, iid, mac, acked, missing, other=()):
        total = len(acked) + len(missing)
        lines = [f"• {cp}: acknowledged (up {up})" for cp, up in acked]
        lines += [f"• {cp}: NOT acknowledged (ACK {ack})"
                  for cp, ack in missing]
        # Shown, but not graded: these are not this site's control planes.
        lines += [f"• {cp}: {state} — not a control plane of this site "
                  f"(transit, or registered elsewhere)"
                  for cp, state in other]
        body = (f"AP MAC {mac} in L2 LISP instance {iid}, across {total} "
                f"map-server(s) of this site:\n" + "\n".join(lines))

        if missing:
            names = [cp for cp, _ in missing]
            # Recorded whichever way this grades, so the LISP session
            # troubleshooting can later be pointed at the specific control
            # plane that never acknowledged rather than at whichever one
            # happens to be listed first.
            ctx.state["ap_l2_reg_missing"] = names
            plural = ("that control plane" if len(names) == 1
                      else "those control planes")
            data = {"l2_iid": iid, "mac": mac,
                    "acked": [cp for cp, _ in acked], "missing": names}

            # Some control plane still holds the registration, so the fabric
            # can locate the AP -- map-requests are answered by whichever CP
            # acked. That is a degraded state worth surfacing, not a broken
            # one, and failing here would stop a run that has more to say.
            if acked:
                return CheckResult(
                    CheckStatus.WARN,
                    body + f"\n\nThe AP is registered, but {', '.join(names)} "
                    f"never acknowledged it. The fabric can still locate the "
                    f"AP through {', '.join(cp for cp, _ in acked)}, so this "
                    f"is a loss of redundancy rather than an outage. A LISP "
                    f"session check from {hostname} to {', '.join(names)} "
                    f"would say why {plural} did not acknowledge.",
                    data=data,
                )

            # Nothing acked: the registration was sent and no control plane
            # confirmed it, so no other fabric node can learn where the AP is.
            # Graded WARN rather than FAIL deliberately: the LISP session
            # troubleshooting that explains WHY no CP acknowledged is not
            # wired in yet, and a FAIL here sets `ap_stop` and halts the run
            # before the remaining checks get to say anything. Restore FAIL
            # once that follow-up exists to act on `ap_l2_reg_missing`.
            return CheckResult(
                CheckStatus.WARN,
                body + f"\n\nThe AP is in this switch's database and its "
                f"registration was sent, but no control plane acknowledged "
                f"it. The rest of the fabric cannot learn where the AP is, so "
                f"the next step is a LISP session check from {hostname} to "
                f"{', '.join(names)}.",
                data=data,
            )

        return CheckResult(
            CheckStatus.OK,
            body + f"\n\nEvery control plane has acknowledged the AP's "
            f"registration, so the fabric can locate it.",
            data={"l2_iid": iid, "mac": mac,
                  "acked": [cp for cp, _ in acked]},
        )


def _site_map_servers(ctx, hostname, iid, af):
    """The map-servers this instance registers to, from the statistics parser.

    Deliberately not read from `show lisp instance-id {id} {af}`: that command
    prints additional map-servers on unlabelled continuation lines, and Genie's
    parser for it splits the first line on commas, so the second map-server is
    lost -- it lands under `prefix_list` instead. A two-CP site then looks like
    a one-CP site. The statistics parser keys each map-server separately and
    gets this right, and is the same source the CLI modules use.

    This is also why the database ACK table is not used to enumerate CPs: in a
    deployment with SDA transit, an EID can be registered to transit control
    planes as well as the site's own, so the ACK rows are a superset of the
    CPs whose health this site depends on.
    """
    from radkit_cli import get_single_output_genie
    cmd = f"show lisp instance-id {iid} {af} statistics"
    parsed = _as_mapping(get_single_output_genie(hostname, cmd, ctx.service))
    try:
        path = parsed["lisp_id"][0]["instance_id"][iid]
    except (KeyError, IndexError, TypeError):
        return []
    return sorted(_as_mapping(path.get("etr_map_servers")).keys())


def _fmt_reg_age(value):
    """How long ago a registration was refreshed, in words.

    The control plane reports this two ways depending on age: a clock time
    ("13:49:57") while it is recent, and an elapsed duration ("1d12h") once it
    is older. Reading the second as a time of day is wrong, so each form is
    phrased for what it actually is.
    """
    if not value:
        return "at an unknown time"
    text = str(value).strip()
    if ":" in text:
        return f"at {text}"
    return f"{text} ago"


def _fmt_lease(seconds):
    """A DHCP lease in days and hours, for a reader rather than a parser.

    `lease 458754s` is precise and unreadable; "5d 7h remaining" is the same
    fact in the form an engineer actually uses it. Falls back to the raw value
    when it is not a number, so a parser change degrades to the old output
    instead of hiding the lease entirely.
    """
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return f"{seconds}s" if seconds is not None else "unknown"
    if total < 3600:
        return f"{max(total // 60, 1)}m"
    days, rem = divmod(total, 86400)
    hours = rem // 3600
    if days and hours:
        return f"{days}d {hours}h"
    if days:
        return f"{days}d"
    return f"{hours}h"


def _ap_tracking_entries(ctx, hostname, mac):
    """The AP's device-tracking entries, IPv4 and IPv6 kept separate.

    Reuses SISF.device_tracking_database_mac as-is. The IPv6 split matters:
    an AP that has only formed a link-local address has two entries in this
    table and neither is usable for CAPWAP, so counting rows would report a
    working address where there is none.
    """
    from switchingmodules.sisf import SISF
    sisf = SISF(hostname)
    sisf.device_tracking_database_mac(mac, ctx.service)

    v4, v6 = [], []
    for entry in (getattr(sisf, "dbentries", None) or []):
        if normalize_mac(entry.get("link_layer_address")) != mac:
            continue
        addr = (entry.get("network_layer_address") or "").strip()
        if not addr:
            continue
        (v6 if ":" in addr else v4).append(entry)
    return v4, v6


def _ap_snooping_binding(ctx, hostname, vlan, mac):
    """The AP's DHCP snooping binding, or None.

    Reuses DHCPDevice.dhcpsnoopingbindingmac, which scopes the query to this
    MAC *and* this VLAN. Both matter: the same MAC can hold a binding in
    another VLAN, and a match from the wrong one would witness a lease that has
    nothing to do with the VLAN the AP is onboarding in.

    The MAC is passed as normalized (dotted). IOS accepts that form here and
    prints colon-separated regardless, so no conversion is needed -- verified
    live against IOS-XE 17.x.
    """
    from switchingmodules.dhcp import DHCPDevice
    dev = DHCPDevice(hostname)
    dev.dhcpsnoopingbindingmac(mac, vlan, ctx.service)

    if getattr(dev, "macbinding_error", None):
        raise RuntimeError(dev.macbinding_error)

    entry = getattr(dev, "macbinding", None)
    if not entry:
        return None
    return {"ip": (entry.get("ip") or "").strip(),
            "interface": entry.get("interface"), "vlan": entry.get("vlan"),
            "lease": entry.get("lease"), "type": entry.get("type")}


class ApIpAddress(_ApCheck):
    """Whether the AP holds a usable IPv4 address, from two sources.

    An AP with no address never reaches the controller, so this is the gate
    between "the switch sees the AP" and everything CAPWAP. Two independent
    sources are read rather than one: SISF device-tracking, which is what the
    switch believes about the endpoint, and the DHCP snooping binding, which is
    what the switch witnessed being leased. Either alone can be stale or
    cleared while the AP is perfectly healthy, so agreement between them is
    strong evidence and disagreement is worth surfacing on its own.

    An address that exists only as an IPv6 link-local is treated as no address:
    the entry is real, the AP formed it without help, and it cannot carry
    CAPWAP to the controller.

    Absence sets the trigger for the full DHCP module -- recorded in state, not
    invoked from here.
    """

    name = "AP IP Address"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        vlan = ctx.state.get("ap_vlan")
        mac = normalize_mac(ctx.payload.get("mac"))

        if not mac:
            return CheckResult(
                CheckStatus.SKIP, "Skipped — the AP's MAC is unknown.")

        try:
            v4, v6 = _ap_tracking_entries(ctx, hostname, mac)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"device-tracking database for {mac}")

        # The snooping binding is corroboration, not the primary source, so a
        # failure to read it must not sink a check that device-tracking can
        # still answer. It is recorded as unread and reported as such.
        binding, binding_error = None, None
        if vlan:
            try:
                binding = _ap_snooping_binding(ctx, hostname, vlan, mac)
            except BaseException as e:
                binding_error = f"{type(e).__name__}: {e}".strip()

        return self._grade(ctx, hostname, mac, vlan, v4, v6,
                           binding, binding_error)

    @staticmethod
    def _grade(ctx, hostname, mac, vlan, v4, v6, binding, binding_error):
        tracked = sorted({e["network_layer_address"] for e in v4})
        bound = binding["ip"] if binding and binding.get("ip") else None

        lines = []
        for e in v4:
            # "DH4" and "ARP" are how the switch learned the address; say that
            # rather than printing the code. The reader is a TAC engineer, so
            # the facts stay -- what changes is that they read as a sentence.
            code = (e.get("dev_code") or "").upper()
            learned = {"DH4": "from DHCP", "DH6": "from DHCPv6",
                       "ARP": "from ARP", "ND": "from IPv6 ND",
                       "PKT": "from data traffic",
                       "API": "by configuration"}.get(code, f"as {code}")
            state = (e.get("state") or "unknown").lower()
            port = abbrev_port(e.get("interface"))
            lines.append(
                f"• Device-tracking learned {e['network_layer_address']} "
                f"{learned} on {port}; {state}, last seen {e.get('age')} ago.")
        for e in v6:
            lines.append(
                f"• The AP also formed the IPv6 link-local address "
                f"{e['network_layer_address']}, which it does without help "
                f"from the network and cannot use to reach the controller.")
        if bound:
            port = abbrev_port(binding.get("interface"))
            lines.append(
                f"• DHCP snooping witnessed the lease for {bound} on {port}, "
                f"with {_fmt_lease(binding.get('lease'))} remaining.")
        elif binding_error:
            lines.append(
                f"• The DHCP snooping binding table could not be read, so "
                f"nothing here confirms the lease ({binding_error}).")
        elif not vlan:
            lines.append(
                "• The DHCP snooping binding table was not read, because the "
                "AP's VLAN is not known.")
        else:
            lines.append(
                f"• DHCP snooping holds no binding for this AP in VLAN "
                f"{vlan}, so no lease is witnessed for it there.")

        body = f"AP {mac} on {hostname}:\n" + "\n".join(lines)

        # Nothing IPv4 anywhere. Whether an IPv6 link-local was formed changes
        # the wording but not the verdict -- the AP cannot reach a controller
        # either way, and DHCP is where the answer lies.
        if not tracked and not bound:
            ctx.state["ap_needs_dhcp"] = True
            if v6:
                why = ("That link-local address is all the AP has.")
            else:
                why = "Neither source has any address for the AP."
            return CheckResult(
                CheckStatus.FAIL,
                body + f"\n\n{why} The AP has no usable IPv4 address, so it "
                f"cannot begin CAPWAP discovery. The next step is the full "
                f"DHCP troubleshooting flow for VLAN {vlan or 'unknown'}.",
                data={"mac": mac, "vlan": vlan, "tracked": tracked,
                      "bound": bound, "needs_dhcp": True},
            )

        agreed = bool(tracked) and bool(bound) and tracked == [bound]
        data = {"mac": mac, "vlan": vlan, "tracked": tracked, "bound": bound}

        if agreed:
            ctx.state["ap_ip"] = bound
            ctx.state["ap_ip_source"] = "device-tracking + DHCP snooping"
            return CheckResult(
                CheckStatus.OK,
                body + f"\n\nBoth sources agree the AP holds {bound}, so it "
                f"has a usable address and a witnessed DHCP lease.",
                data={**data, "ip": bound},
            )

        # From here the sources disagree in some way. An address is still
        # recorded so later checks have something to work with, preferring the
        # witnessed lease over the tracked entry when both exist.
        chosen = bound or (tracked[0] if tracked else None)
        ctx.state["ap_ip"] = chosen
        ctx.state["ap_ip_source"] = ("DHCP snooping" if bound
                                     else "device-tracking")
        ctx.state["ap_ip_disputed"] = True

        if tracked and bound:
            why = (f"The two sources disagree: device-tracking has "
                   f"{', '.join(tracked)} while the DHCP snooping binding has "
                   f"{bound}. One of them is stale, and until that is settled "
                   f"the AP's real address is uncertain.")
        elif tracked:
            why = (f"Device-tracking has {', '.join(tracked)} but no DHCP "
                   f"snooping binding witnesses that lease, so the address "
                   f"cannot be confirmed as DHCP-assigned.")
        else:
            why = (f"A DHCP snooping binding witnesses {bound} but "
                   f"device-tracking has no IPv4 entry for the AP, so the "
                   f"switch is not tracking an address it saw being leased.")

        return CheckResult(
            CheckStatus.WARN,
            body + f"\n\n{why} The AP most likely holds {chosen}.",
            data={**data, "ip": chosen, "disputed": True},
        )


def _global_lisp_instance(ctx, hostname):
    """The LISP instance bound to the global routing table, or None.

    Reuses L3Device.lispiid, which already handles this: the default VRF
    takes its regex branch over `show lisp vrf default`, since Genie does not
    parse that form. Returns the IID as an int, or None.
    """
    from routingmodules.lisp import L3Device
    dev = L3Device("default", hostname)
    dev.lispiid(ctx.service)
    return getattr(dev, "iid", None)


class ApL3LispInstance(_ApCheck):
    """Whether the AP's LISP instance is bound to the global routing table.

    The AP's address lives in the global table, so the instance carrying it
    must be bound there -- both its locator table and its EID table. An
    instance bound to a VRF instead would register the AP into an overlay the
    controller is not in, and nothing downstream would work.
    """

    name = "AP L3 LISP Instance"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")

        try:
            iid = _global_lisp_instance(ctx, hostname)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, "show lisp vrf")

        if not iid:
            return CheckResult(
                CheckStatus.FAIL,
                f"No LISP instance is mapped to the global routing table on "
                f"{hostname}, so the AP's address has no instance to be "
                f"registered in.",
            )

        from radkit_cli import get_single_output_genie
        cmd = f"show lisp instance-id {iid} ipv4"
        try:
            parsed = _as_mapping(get_single_output_genie(hostname, cmd, ctx.service))
            path = _as_mapping(parsed["lisp_id"][0]["instance_id"][iid])
        except BaseException:
            path = {}

        if not path:
            return CheckResult(
                CheckStatus.FAIL,
                f"LISP instance {iid} is mapped to the global routing table on "
                f"{hostname} but the instance itself could not be read, so it "
                f"cannot be confirmed as usable for the AP.",
                data={"l3_iid": iid},
            )

        locator = (path.get("locator_table") or "").strip()
        eid = (path.get("eid_table") or "").strip()
        wrong = [n for n, v in (("locator table", locator), ("EID table", eid))
                 if v != "default"]

        if wrong:
            return CheckResult(
                CheckStatus.FAIL,
                f"LISP instance {iid} on {hostname} is not bound to the global "
                f"routing table: its {' and '.join(wrong)} "
                f"({', '.join(v for v in (locator, eid) if v)}) is not "
                f"`default`. The AP's address would be registered into the "
                f"wrong table, where the controller cannot reach it.",
                data={"l3_iid": iid, "locator_table": locator,
                      "eid_table": eid},
            )

        ctx.state["ap_l3_iid"] = iid
        return CheckResult(
            CheckStatus.OK,
            f"LISP instance {iid} on {hostname} is bound to the global routing "
            f"table (locator table and EID table both `default`), so it "
            f"carries the AP's address.",
            data={"l3_iid": iid, "locator_table": locator, "eid_table": eid},
        )


def _l3_dyneid_lookup(ctx, hostname, iid, ip):
    """Ask the switch about ONE address: is it a dynamic EID in this instance?

    `show lisp instance-id <iid> dynamic-eid <addr>` answers directly, instead
    of pulling every learned EID with `detail` and filtering here. The device
    distinguishes the three cases for us:

        172.19.5.10, Vlan2045, uptime: 00:35:20     <- learned
          last activity: never, discovered by: Device-tracking
        % No dynamic-EID 172.19.5.99 discovered.    <- instance ok, not learned
        % Could not find EID table instance ID 9999 in LISP 0.   <- no instance

    Parsed by hand rather than through Genie. ShowLispDynamicEid exists and
    covers this command, but it raises UnboundLocalError on this output -- it
    only builds its dict after matching a "Dynamic-EID name:" line, which the
    per-address form does not print. Verified live on IOS-XE.

    Returns `(entry, err)` -- entry is {"interface", "uptime", "discovered_by"}
    when the address is a dynamic EID, else None; err is the device's own
    message when it refused the lookup, else None.
    """
    from radkit_cli import get_any_single_output
    cmd = f"show lisp instance-id {iid} dynamic-eid {ip}"
    raw = get_any_single_output(hostname, cmd, ctx.service) or ""

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("%"):
            return None, line

    # "    172.19.5.10, Vlan2045, uptime: 00:35:20"
    addr = re.compile(
        r"^" + re.escape(str(ip)) + r",\s*(?P<intf>\S+?),\s*uptime:\s*(?P<uptime>\S+)")
    # "      last activity: never, discovered by: Device-tracking"
    disc = re.compile(r"discovered by:\s*(?P<by>.+?)\s*$")

    entry = None
    for line in raw.splitlines():
        line = line.strip()
        m = addr.match(line)
        if m:
            entry = {"interface": m.group("intf"),
                     "uptime": m.group("uptime"),
                     "discovered_by": None}
            continue
        if entry is not None and entry["discovered_by"] is None:
            d = disc.search(line)
            if d:
                entry["discovered_by"] = d.group("by")
    return entry, None


class ApL3LispDynamicEid(_ApCheck):
    """Whether the AP's IP was learned as a dynamic EID in the global instance.

    The switch promotes a host address to a dynamic EID once it has learned it
    on a LISP-enabled SVI. An AP that holds an IP but never became a dynamic
    EID means the fabric was never told to treat that subnet as EID space --
    the address exists locally but will never be registered to a control
    plane, so the controller has no way to reach it.
    """

    name = "AP L3 LISP Dynamic EID"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        iid = ctx.state.get("ap_l3_iid")
        ip = ctx.state.get("ap_ip")

        if not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the global-table LISP instance is unknown (see AP "
                "L3 LISP Instance).")
        if not ip:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's IP address is unknown (see AP IP "
                "Address).")

        try:
            entry, err = _l3_dyneid_lookup(ctx, hostname, iid, ip)
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, f"show lisp instance-id {iid} dynamic-eid {ip}")

        if err:
            # The device refused the lookup. "Could not find EID table
            # instance" means the instance is absent -- a different finding
            # from an instance that simply has not learned the address.
            if "instance" in err.lower():
                return CheckResult(
                    CheckStatus.WARN,
                    f"{hostname} has no LISP instance {iid}: it answered "
                    f"\"{err}\". The AP's address {ip} cannot be a dynamic "
                    f"EID in an instance that does not exist.",
                    data={"l3_iid": iid, "ap_ip": ip, "device_error": err},
                )
            return CheckResult(
                CheckStatus.WARN,
                f"The AP's address {ip} is not a dynamic EID in LISP instance "
                f"{iid} on {hostname} -- the switch answered \"{err}\". The "
                f"switch holds the AP's IP but never learned it into a "
                f"dynamic-EID group, so it is not registered to the control "
                f"plane.",
                data={"l3_iid": iid, "ap_ip": ip, "device_error": err},
            )

        if not entry:
            return CheckResult(
                CheckStatus.WARN,
                f"{hostname} returned nothing for the AP's address {ip} in "
                f"LISP instance {iid}, so it could not be confirmed as a "
                f"dynamic EID.",
                data={"l3_iid": iid, "ap_ip": ip},
            )

        ctx.state["ap_l3_dyneid"] = entry
        by = entry.get("discovered_by")
        return CheckResult(
            CheckStatus.OK,
            f"The AP's address {ip} is a dynamic EID in LISP instance {iid} "
            f"on {hostname}, learned on {entry['interface']} and up for "
            f"{entry['uptime']}"
            + (f" (discovered by {by})." if by else "."),
            data={"l3_iid": iid, "ap_ip": ip, **entry},
        )


class ApL3LispDatabase(_ApCheck):
    """Whether the AP's address is in the ETR mapping database.

    The database is what this switch will register to the control plane. An
    address that is a dynamic EID but absent here was learned and then not
    accepted into the mapping database -- nothing is registered for it, so the
    controller has no path to the AP.

    Unlike the L2 side, the filtered form is accepted here: the device takes
    `... ipv4 database <ip>/32` (the L2 equivalent `<mac>/48` is rejected and
    has to be read unfiltered).
    """

    name = "AP L3 LISP Database"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        iid = ctx.state.get("ap_l3_iid")
        ip = ctx.state.get("ap_ip")

        if not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the global-table LISP instance is unknown (see AP "
                "L3 LISP Instance).")
        if not ip:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's IP address is unknown (see AP IP "
                "Address).")

        from radkit_cli import get_single_output_genie
        cmd = f"show lisp instance-id {iid} ipv4 database {ip}/32"
        try:
            parsed = _as_mapping(get_single_output_genie(hostname, cmd, ctx.service))
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, cmd)

        # The filtered form puts the single matched prefix flat on the
        # instance -- there is no `entries.eids` map as on the unfiltered L2
        # side. A miss yields an instance body with no `eid_prefix` at all.
        try:
            entry = _as_mapping(parsed["lisp_id"][0]["instance_id"][iid])
        except (KeyError, IndexError, TypeError):
            entry = {}

        found = None
        if str(entry.get("eid_prefix") or "").split("/")[0] == ip:
            found = entry

        if found is None:
            return CheckResult(
                CheckStatus.FAIL,
                f"The AP's address {ip} is not in the L3 LISP database for "
                f"instance {iid} on {hostname}. It was learned as a dynamic "
                f"EID but never entered the mapping database, so this switch "
                f"registers nothing for the AP and the controller cannot "
                f"reach it.",
                data={"l3_iid": iid, "ap_ip": ip},
            )

        ctx.state["ap_l3_db_entry"] = found

        # `do not register` is deliberately not graded, as on the L2 side: it
        # is routine across a healthy instance. Whether the AP is actually
        # registered is settled by the next check, against the control planes.

        return CheckResult(
            CheckStatus.OK,
            f"The AP's address {ip} is in the L3 LISP database for instance "
            f"{iid} on {hostname}, and is eligible for registration.",
            data={"l3_iid": iid, "ap_ip": ip},
        )


class ApL3LispRegistration(_ApCheck):
    """Whether every control plane has acknowledged the AP's L3 registration.

    The L3 mirror of `ApL2LispRegistration`. Having the AP's address in the
    database is not the same as the fabric knowing where that address is: the
    entry names each map-server this switch registered the prefix to and
    whether that map-server acknowledged it. A CP with ACK No cannot answer
    map-requests for the AP, so the controller may not reach it even though
    everything on this switch looks right.

    As on the L2 side, the ACK rows are a superset of the control planes this
    site depends on -- an SDA transit CP can appear among them. The rows are
    therefore intersected against `_site_map_servers`, and anything outside
    that set is reported but never graded.
    """

    name = "AP L3 LISP Registration"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        hostname = ctx.state.get("xtr_hostname")
        iid = ctx.state.get("ap_l3_iid")
        ip = ctx.state.get("ap_ip")

        if not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the global-table LISP instance is unknown (see AP "
                "L3 LISP Instance).")
        if not ip:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's IP address is unknown (see AP IP "
                "Address).")

        from radkit_cli import get_single_output_genie
        cmd = f"show lisp instance-id {iid} ipv4 database {ip}/32"
        try:
            parsed = _as_mapping(get_single_output_genie(hostname, cmd, ctx.service))
        except BaseException as e:
            from checks.shared import _legacy_fail
            return _legacy_fail(e, cmd)

        try:
            entry = _as_mapping(parsed["lisp_id"][0]["instance_id"][iid])
        except (KeyError, IndexError, TypeError):
            entry = {}

        servers = _as_mapping(entry.get("map_servers"))
        if not servers:
            return CheckResult(
                CheckStatus.FAIL,
                f"The L3 LISP database entry for {ip} on {hostname} names no "
                f"map-server, so this switch has registered the AP's address "
                f"nowhere in instance {iid} and the controller cannot learn "
                f"where the AP is.",
                data={"l3_iid": iid, "ap_ip": ip},
            )

        try:
            site_cps = _site_map_servers(ctx, hostname, iid, "ipv4")
        except BaseException:
            site_cps = []

        acked, missing, other = [], [], []
        for cp, body in servers.items():
            body = _as_mapping(body)
            is_acked = str(body.get("ack") or "").strip().lower() == "yes"
            if site_cps and cp not in site_cps:
                other.append((cp, "acknowledged" if is_acked
                              else f"ACK {str(body.get('ack') or 'none').strip()}"))
            elif is_acked:
                acked.append((cp, body.get("uptime")))
            else:
                missing.append((cp, str(body.get("ack") or "none").strip()))

        listed = set(servers.keys())
        for cp in site_cps:
            if cp not in listed:
                missing.append((cp, "not listed"))

        return self._grade(ctx, hostname, iid, ip, acked, missing, other)

    @staticmethod
    def _grade(ctx, hostname, iid, ip, acked, missing, other=()):
        total = len(acked) + len(missing)
        lines = [f"• {cp}: acknowledged (up {up})" for cp, up in acked]
        lines += [f"• {cp}: NOT acknowledged (ACK {ack})"
                  for cp, ack in missing]
        lines += [f"• {cp}: {state} — not a control plane of this site "
                  f"(transit, or registered elsewhere)"
                  for cp, state in other]
        body = (f"AP address {ip} in L3 LISP instance {iid}, across {total} "
                f"map-server(s) of this site:\n" + "\n".join(lines))

        if missing:
            names = [cp for cp, _ in missing]
            ctx.state["ap_l3_reg_missing"] = names
            plural = ("that control plane" if len(names) == 1
                      else "those control planes")
            data = {"l3_iid": iid, "ap_ip": ip,
                    "acked": [cp for cp, _ in acked], "missing": names}

            if acked:
                return CheckResult(
                    CheckStatus.WARN,
                    body + f"\n\nThe AP's address is registered, but "
                    f"{', '.join(names)} never acknowledged it. The fabric can "
                    f"still locate the AP through "
                    f"{', '.join(cp for cp, _ in acked)}, so this is a loss of "
                    f"redundancy rather than an outage. A LISP session check "
                    f"from {hostname} to {', '.join(names)} would say why "
                    f"{plural} did not acknowledge.",
                    data=data,
                )

            # As on the L2 side: WARN, not FAIL, until the LISP session
            # troubleshooting that acts on `ap_l3_reg_missing` is wired in.
            # A FAIL here sets `ap_stop` and ends the run with no explanation
            # of why the control planes stayed silent.
            return CheckResult(
                CheckStatus.WARN,
                body + f"\n\nThe AP's address is in this switch's database and "
                f"its registration was sent, but no control plane acknowledged "
                f"it. The controller cannot learn where the AP is, so the next "
                f"step is a LISP session check from {hostname} to "
                f"{', '.join(names)}.",
                data=data,
            )

        return CheckResult(
            CheckStatus.OK,
            body + f"\n\nEvery control plane has acknowledged the AP's "
            f"registration, so the fabric can locate its address.",
            data={"l3_iid": iid, "ap_ip": ip,
                  "acked": [cp for cp, _ in acked]},
        )


def _int0(v):
    """int(v) with 0 for anything unparseable -- counters arrive as str or None."""
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


class ApCpRegistration(_ApCheck):
    """Ask ONE control plane whether it holds the AP's L3 registration record.

    Queued once per reachable CP by `ApCpDiscovery`, and rendered on that CP's
    own node so the answer appears where the engineer is looking.

    The ETR-side check says the registration was sent and acknowledged; this
    says the control plane has it. When the two disagree the control plane is
    the authority: the fabric resolves an AP's address by asking a CP, so a CP
    without the record cannot answer for it regardless of what the switch
    believes it sent.

    A missing record is a WARN, not a FAIL: the next step is the LISP session
    troubleshooting against that CP, which explains why the registration is not
    there. Failing here would stop the run before it could say.
    """

    name = "Control Plane Registration"

    def __init__(self, idx, node_id, cp_host, cp_mgmt):
        self.idx = idx
        self.cp_host = cp_host
        self.cp_mgmt = cp_mgmt
        self.target_node_id = node_id
        self.name = f"Control Plane Registration — {cp_host}"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        ip = ctx.state.get("ap_ip")
        iid = ctx.state.get("ap_l3_iid")
        if not ip or not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's address and L3 instance are not known.",
            )

        from routingmodules.lisp import controlplane_eid
        query = controlplane_eid(ip, iid, self.cp_host)
        try:
            query.ipv4_q(ctx.service)
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the registration record for {ip} from "
                f"{self.cp_host} ({type(e).__name__}: {e}).",
            )

        data = {
            "cp": self.cp_host,
            "ap_ip": ip,
            "l3_iid": iid,
            "registered": bool(query.registered),
            "auth_failures": query.auth_failures,
            "allowed_locators_mismatch": query.allowed_locators_mismatch,
        }

        # A read that failed is not a registration that is missing. When the
        # transport or the credentials are the problem every CP answers "no
        # record", which reads as a fabric-wide outage and sends the engineer
        # after the wrong thing entirely.
        if getattr(query, "query_failed", False):
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the registration record for {ip} from "
                f"{self.cp_host}: the control plane returned nothing. This is "
                f"a problem reading the device, not a finding about the AP -- "
                f"whether {self.cp_host} holds the registration is still "
                f"unknown.",
                data=dict(data, query_failed=True),
            )

        if not query.registered:
            missing = list(ctx.state.get("ap_cp_reg_missing") or [])
            missing.append(self.cp_host)
            ctx.state["ap_cp_reg_missing"] = missing

            auth = _int0(getattr(query, "auth_failures", 0))
            covering = getattr(query, "eid_prefix", None)
            data["auth_failures"] = auth
            data["eid_prefix"] = covering

            # The counters live on the record that COVERS the AP -- the site's
            # configured prefix. They are the difference between "the switch is
            # not registering" and "the switch is registering and the control
            # plane is throwing it away".
            if auth:
                # WARN, not FAIL: a fault in the fabric must not stop the run.
                # FAIL sets the stop key and skips every remaining check --
                # including the other control plane and the whole session flow.
                return CheckResult(
                    CheckStatus.WARN,
                    f"{self.cp_host} is rejecting the AP's registration. It "
                    f"holds no entry for {ip} in instance {iid}, and has "
                    f"recorded {auth} authentication failure(s) against "
                    f"{covering or 'the covering prefix'} -- so the switch IS "
                    f"registering and this control plane is discarding it "
                    f"because the LISP authentication key does not match. "
                    f"Correct the key between "
                    f"{ctx.state.get('xtr_hostname')} and {self.cp_host}.",
                    data=data,
                )

            locator_note = ""
            if getattr(query, "exact_prefix", False) and not getattr(
                    query, "locator_up", False):
                locator_note = (
                    f" The entry for {ip} exists but none of its locators is "
                    f"up, so the control plane cannot hand out a usable RLOC.")

            return CheckResult(
                CheckStatus.WARN,
                f"{self.cp_host} holds no registration for {ip} in instance "
                f"{iid}, and has recorded no authentication failures against "
                f"{covering or 'the covering prefix'} -- so registrations are "
                f"not being rejected for a bad key; they are not arriving."
                + locator_note,
                data=data,
            )

        lines = []
        eid_prefix = ip if "/" in str(ip) else f"{ip}/32"
        state = str(query.state or "").lower()
        if state == "complete":
            lines.append(
                f"• Registered and complete, last refreshed "
                f"{_fmt_reg_age(query.last_registered)} with a {query.ttl} "
                f"lifetime."
            )
        else:
            lines.append(
                f"• Registered, but the record is '{query.state}' rather than "
                f"complete, so the control plane has only part of what the "
                f"switch sent."
            )

        if query.origin:
            # The device's Origin line names the PARENT prefix the dynamic EID
            # fell out of ("Dynamic, more specific of 172.19.5.0/24"), not what
            # is registered. Printing it alone reads as though the control
            # plane holds the /24, so the registered prefix is stated first.
            origin = str(query.origin)
            m = re.search(r"more specific of\s+(\S+)", origin)
            if m:
                lines.append(
                    f"• The record is for {eid_prefix}, which the control "
                    f"plane learned dynamically as a more-specific of "
                    f"{m.group(1)} — the subnet configured on the switch."
                )
            else:
                lines.append(
                    f"• The record is for {eid_prefix}, learned as: {origin}."
                )

        for rloc in query.etrs:
            loc = (query.locators or {}).get(rloc) or {}
            locstate = str(loc.get("state") or "").lower()
            if locstate == "up":
                lines.append(
                    f"• It is reachable through {rloc}, whose locator is up "
                    f"at priority {loc.get('priority')}/weight {loc.get('weight')}."
                )
            else:
                lines.append(
                    f"• It is registered through {rloc}, but that locator is "
                    f"'{loc.get('state')}' rather than up, so traffic for the "
                    f"AP may not be deliverable through it."
                )

        if query.proxy_reply:
            lines.append(
                "• The control plane answers map-requests for the AP on its "
                "behalf (proxy-reply), which is what lets other nodes resolve "
                "the address without the AP's switch being asked."
            )

        # These counters are cumulative and carry no timestamp, so they say
        # THAT registrations were rejected, never WHEN. A live record does not
        # prove the key matches now: a registration stands for its TTL, so an
        # EID can be resolvable while fresh Map-Registers are being rejected.
        # Saying "this counts earlier attempts" would talk the engineer out of
        # the flapping-key case, which is the one these counters are for.
        if query.auth_failures:
            lines.append(
                f"• {query.auth_failures} registration(s) have been rejected "
                f"for a bad authentication key. The counter does not say when, "
                f"and the record standing now does not rule out rejections "
                f"still happening — re-read it and see whether the number "
                f"moves."
            )
        if query.allowed_locators_mismatch:
            lines.append(
                f"• {query.allowed_locators_mismatch} registration(s) have "
                f"been rejected because the switch offered an RLOC that is not "
                f"in the locators this site allows. As above, the counter does "
                f"not say when."
            )

        body = "\n".join(lines)
        status = CheckStatus.OK
        if state != "complete" or query.auth_failures or query.allowed_locators_mismatch:
            status = CheckStatus.WARN
        return CheckResult(status, body, data=data)


class ApLispSessionTrigger(_ApCheck):
    """Queue the LISP session flow when a control plane has no record.

    Runs after every per-CP registration check, so `ap_cp_reg_missing` is
    complete. When something is missing it queues the shared session checks
    from `checks.lisp_session` -- which explain WHY the registration is not
    there -- pointed at the CP nodes this scenario already drew.

    This check itself only decides and queues; the findings come from the
    checks it queues, each on its own node.
    """

    name = "LISP Session Troubleshooting"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        missing = ctx.state.get("ap_cp_reg_missing") or []
        if not missing:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — every reachable control plane holds the AP's "
                "registration, so there is nothing to explain.",
            )

        ip = ctx.state.get("ap_ip")
        iid = ctx.state.get("ap_l3_iid")
        cp_nodes = ctx.state.get("ap_cp_targets") or {}
        # ap_cp_targets is node_id -> hostname; the session module wants the
        # reverse, so a CP's findings land on the node already drawn for it.
        nodes_by_host = {host: node for node, host in cp_nodes.items()}

        from checks.lisp_session import LispSessionTarget, lisp_session_checks
        target = LispSessionTarget(
            eid=ip,
            xtr_hostname=ctx.state.get("xtr_hostname"),
            catc_name=ctx.state.get("catc_name"),
            iid=iid,
            af="ipv4",
            vrf=ctx.state.get("ap_vrf") or "default",
            cp_nodes=nodes_by_host,
            label=f"the AP's address {ip}",
        )

        # Only the control planes that are actually missing the record are
        # walked: a CP that holds it has already answered for itself, and
        # re-checking it would report a healthy path as though it were part of
        # the problem.
        rlocs = ctx.state.get("ap_cp_rlocs") or {}
        mgmts = ctx.state.get("ap_cp_mgmts") or {}
        pairs = []
        for host in missing:
            pairs.append((rlocs.get(host) or host, host,
                          mgmts.get(host) or host))

        checks = lisp_session_checks(target, map_servers=pairs)
        names = ", ".join(missing)
        return CheckResult(
            CheckStatus.WARN,
            f"{names} {'does' if len(missing) == 1 else 'do'} not hold a "
            f"registration for {ip}, so the LISP session flow runs to say "
            f"why: the switch's own database and map-server configuration, "
            f"its sessions, and each control plane's configuration and "
            f"counters.",
            data={"queue_checks": checks},
        )


class ApCpDiscovery(_ApCheck):
    """Draw the fabric site's reachable control planes and queue a check on each.

    `ApL3LispRegistration` reads the ETR's own view: which map-servers this
    switch says acknowledged the registration. That is the sending side. It is
    not the same fact as the control plane actually holding a registration
    record -- an ACK can be stale, and a CP the switch never registers to will
    never appear in that table at all. So the CPs are resolved independently
    from Catalyst Center and each one is asked directly.

    Only CPs Catalyst Center reports as reachable are drawn: an unreachable CP
    cannot be queried, and reporting "no record" for a box we could not talk to
    would be a false finding rather than a missing registration.
    """

    name = "Control Plane Discovery"
    target_node_id = "xtr"

    def run_ap(self, ctx: RunContext) -> CheckResult:
        ip = ctx.state.get("ap_ip")
        iid = ctx.state.get("ap_l3_iid")
        if not ip or not iid:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the AP's address and L3 instance are not known "
                "(see AP L3 LISP Registration).",
            )

        fabric_id = ctx.state.get("fabric_id")
        catc = ctx.state.get("catc_name")
        if not fabric_id or not catc:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the fabric site is not known, so its control "
                "planes cannot be listed.",
            )

        from traffic_flows.lispsessiontroubleshooting import in_site_control_Planes
        try:
            control_planes = in_site_control_Planes(fabric_id, catc, ctx.service, 0)
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not list the fabric site's control planes "
                f"({type(e).__name__}: {e}), so the AP's registration cannot "
                f"be confirmed on the control plane side.",
            )

        if not control_planes:
            return CheckResult(
                CheckStatus.FAIL,
                "Catalyst Center reports no reachable control plane for this "
                "fabric site. An AP's address has to be registered on a "
                "control plane for the fabric to locate it, so nothing can "
                "resolve the AP until at least one is reachable.",
                data={"ap_cp_none_reachable": True},
            )

        # What the ETR itself registers to, for the mismatch case below.
        try:
            etr_map_servers = set(
                _site_map_servers(ctx, ctx.state.get("xtr_hostname"), iid, "ipv4")
            )
        except BaseException:
            etr_map_servers = set()

        add_nodes, followups, lines = [], [], []
        cp_targets, cp_rlocs, cp_mgmts = {}, {}, {}
        for idx, cp in enumerate(control_planes, start=1):
            host = (
                getattr(cp, "hostname", None)
                or getattr(getattr(cp, "profiled_device", None), "hostname", None)
                or getattr(cp, "mgmtip", None)
                or f"cp{idx}"
            )
            mgmt = (getattr(cp, "mgmtip", None) or "").strip()

            node_id = f"apcp-{idx}"
            add_nodes.append({
                "id": node_id,
                "role": "control-plane",
                "label": host,
                "ip": mgmt or None,
                "connect_to": "xtr",
                "edge_label": "LISP",
            })
            cp_targets[node_id] = host

            rloc = (
                getattr(cp, "rloc", None)
                or getattr(getattr(cp, "profiled_device", None), "loopback", None)
                or mgmt
                or "—"
            )
            registers = (not etr_map_servers) or (rloc in etr_map_servers) or (
                mgmt in etr_map_servers
            )
            note = "" if registers else "  (this switch does not register to it)"
            lines.append(f"• {host} — RLOC {rloc}{note}")
            # Two different addresses: the ETR peers with the RLOC, but
            # profiling a device goes through Catalyst Center by management IP.
            cp_rlocs[host] = rloc if rloc and rloc != "—" else (mgmt or host)
            cp_mgmts[host] = mgmt or host

            followups.append(
                ApCpRegistration(idx=idx, node_id=node_id, cp_host=host,
                                 cp_mgmt=mgmt or host)
            )

        # Runs after every per-CP check queued above, so `ap_cp_reg_missing`
        # is complete when it decides whether to walk the session flow.
        followups.append(ApLispSessionTrigger())

        ctx.state["ap_cp_targets"] = cp_targets
        ctx.state["ap_cp_rlocs"] = cp_rlocs
        ctx.state["ap_cp_mgmts"] = cp_mgmts
        body = "\n".join(lines)
        return CheckResult(
            CheckStatus.OK,
            f"{len(control_planes)} reachable control plane(s) for this fabric "
            f"site:\n" + body +
            f"\n\nEach one is asked directly whether it holds a registration "
            f"record for {ip} in instance {iid}.",
            data={"add_nodes": add_nodes, "queue_checks": followups},
        )
