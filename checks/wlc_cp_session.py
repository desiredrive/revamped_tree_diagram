"""The controller's LISP session to each fabric control plane, per CP.

`fabricEnabledWirelessSession` is the flow this decomposes. It is the
WLC-to-control-plane equivalent of the edge's `singleETRProfiling`, and the
difference is not cosmetic: the controller registers from its **wireless
management interface**, its map-servers and their authentication keys come
from `show wireless fabric summary` rather than the running configuration, and
the control plane must be configured to accept a passive-open session from
that WMI. An edge reader cannot answer any of those.

Decomposed rather than wrapped, for the same reason the edge flow was: the
legacy function logs its findings to the collection logfile and returns only
the control-plane list, so wrapped it renders as one check and every finding
about an individual control plane is invisible on the canvas.

Five of the seven per-CP validations are the SAME checks the edge flow uses --
they read the control plane, which does not care whether its peer is an edge
or a controller. Only two are WLC-specific and new here:

  * the WLC locator-set and passive-open configuration (`few_lisp_configuration`)
  * the control plane's session to the WMI (`specific_lisp_session(wmi_ip)`)

Every finding is a WARN. The legacy flow calls `sys.exit` on each of them, and
under the manifest's rule a fault in the fabric must not stop the run.
"""

from checks.base import Check, CheckResult, CheckStatus, RunContext
from checks.lisp_session import (
    LispAuthenticationKey, LispControlPlaneConfiguration,
    LispMapServerSelfSession, LispSessionAccessLists, LispSessionTrustSec,
    LispControlPlaneStatistics, LispCpCpuUtilization, LispInterCpSession,
    LispSessionTarget, LispTcpSocket, _cp_device)


class WlcLocatorSet(Check):
    """Does this control plane accept a session from the controller's WMI?

    Two conditions, both configured on the control plane and both invisible
    from the controller:

      * the WMI must be in the `locator-set WLC`, or the control plane has no
        locator to match the registration against
      * `map-server session passive-open WLC` must be set, or the control
        plane never opens the TCP session the controller is waiting on

    Either one explains a session that stays down with nothing wrong on the
    controller, which is why this runs before the session state is read.

    This has no edge equivalent: an edge opens the session itself, so neither
    the locator-set nor passive-open applies to it.
    """

    def __init__(self, cp_hostname, cp_mgmt, wmi, catc_name, node_id):
        self.cp_hostname = cp_hostname
        self.cp_mgmt = cp_mgmt
        self.wmi = wmi
        self.catc_name = catc_name
        self.target_node_id = node_id
        self.name = f"WLC Locator-Set and Passive-Open — {cp_hostname}"
        self.running_note = "Reading the control plane's WLC locator-set."

    def run(self, ctx: RunContext) -> CheckResult:
        try:
            cp = _cp_device(ctx, self.cp_hostname, self.catc_name, self.cp_mgmt)
            cp.cp_configuration(ctx.state.get("wlc_cp_vnid"), ctx.service)
            cfg = cp.cp_configuration
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"Could not read the WLC locator-set from {self.cp_hostname} "
                f"({type(e).__name__}: {e}).")

        ips = [str(i).strip() for i in (getattr(cfg, "wlc_locator_ips", None)
                                        or []) if str(i).strip()]
        passive = getattr(cfg, "passive_open_configured", None)
        wmi = (self.wmi or "").strip()

        faults = []
        if not wmi or wmi not in ips:
            faults.append(
                f"The controller's wireless management address {wmi or '—'} "
                f"is not in the WLC locator-set on {self.cp_hostname}, which "
                f"holds {', '.join(ips) if ips else 'no addresses'}. The "
                f"control plane has no locator to match the registration "
                f"against.\n  Remediation: add {wmi or 'the WMI'} to "
                f"'locator-set WLC'.")
        if passive is not True:
            faults.append(
                f"'map-server session passive-open WLC' is not configured on "
                f"{self.cp_hostname}, so it never opens the session the "
                f"controller waits for.\n  Remediation: configure "
                f"'map-server session passive-open WLC'.")

        if faults:
            return CheckResult(CheckStatus.WARN, "\n\n".join(faults),
                               data={"wlc_locator_ips": ips,
                                     "passive_open": passive})
        return CheckResult(
            CheckStatus.OK,
            f"{self.cp_hostname} accepts a session from {wmi}: the address is "
            f"in the WLC locator-set and passive-open is configured.")


class WlcCpSessionState(Check):
    """The control plane's LISP session to the controller's WMI.

    Read from the CONTROL PLANE, not the controller: the controller's own
    `show wireless fabric summary` reports only Up or Down, while the control
    plane names the peer, both ports, the session type and how long it has
    held that state.

    A session that is not up leaves the radio MAC unregistered on this control
    plane no matter what the controller believes, so this is the check the
    rest of the per-CP flow exists to explain.
    """

    def __init__(self, cp_hostname, cp_mgmt, wmi, catc_name, node_id):
        self.cp_hostname = cp_hostname
        self.cp_mgmt = cp_mgmt
        self.wmi = wmi
        self.catc_name = catc_name
        self.target_node_id = node_id
        self.name = f"LISP Session to the Controller — {cp_hostname}"
        self.running_note = "Reading the session to the controller's WMI."

    def run(self, ctx: RunContext) -> CheckResult:
        try:
            cp = _cp_device(ctx, self.cp_hostname, self.catc_name, self.cp_mgmt)
            cp.specific_lisp_session(self.wmi, ctx.service)
            sess = cp.specific_lisp_session
        except BaseException as e:
            return CheckResult(
                CheckStatus.WARN,
                f"Could not read the session to {self.wmi} from "
                f"{self.cp_hostname} ({type(e).__name__}: {e}).")

        # The legacy flow reads these through a try/except: a session that
        # never came up leaves the attributes unset rather than reporting a
        # down state, so their ABSENCE is the finding.
        state = getattr(sess, "session_state", None)
        peer = getattr(sess, "peer_addr", None)
        peer_port = getattr(sess, "peer_port", None)
        local = getattr(sess, "local_address", None)
        local_port = getattr(sess, "local_port", None)
        stype = getattr(sess, "session_type", None)
        held = getattr(sess, "session_state_time", None)

        ctx.state.setdefault("wlc_cp_session_states", {})[
            self.cp_hostname] = state

        if (state or "").strip().lower() == "up":
            return CheckResult(
                CheckStatus.OK,
                f"• {self.cp_hostname} holds a LISP session to the "
                f"controller at {peer}:{peer_port}, from "
                f"{local}:{local_port}.\n"
                f"• Type {stype or '—'}, up {held or '—'}.",
                data={"session_state": state})

        return CheckResult(
            CheckStatus.WARN,
            f"{self.cp_hostname} has no LISP session up to the controller at "
            f"{self.wmi} (state {state or 'not reported'}, held "
            f"{held or '—'}). The radio MAC cannot be registered here while "
            f"this session is down.\n\n"
            f"The checks on this control plane say why: the locator-set and "
            f"passive-open configuration above, then its authentication key, "
            f"counters, socket and CPU below.",
            data={"session_state": state})


def wlc_cp_session_checks(wmi, vnid, radio_mac, control_planes, catc_name,
                          wlc_hostname, wlc_node_id="wlc", cp_nodes=None,
                          wlc_mgmtip=None):
    """The per-control-plane flow, one chain of checks per CP.

    `control_planes` is what `show wireless fabric summary` reported, as
    (address, hostname, mgmt_ip) triples -- the address the controller
    registers to, the name the output uses, and the management IP that
    profiles the device.

    Order follows the legacy flow: the control plane's own configuration
    first, because a locator-set or passive-open fault explains a down session
    without anything being wrong on the controller; then the session itself;
    then the things that fail while the session is up -- the authentication
    key, the counters, the socket and the CPU.
    """
    # The carrier the five reused checks read: the EID is the radio MAC, the
    # instance is the INFRA_VN L2 VNID, and the RLOC is the WMI rather than a
    # loopback, because that is the address the controller registers from.
    target = LispSessionTarget(
        eid=radio_mac, xtr_hostname=wlc_hostname, catc_name=catc_name,
        iid=vnid, af="ethernet", cp_nodes=cp_nodes or {},
        xtr_node_id=wlc_node_id, label=f"the AP's radio MAC {radio_mac}",
        xtr_loopback=wmi,
        # Without it `_profile_xtr` falls back to the AP chain's `xtr_mgmtip`
        # and profiles the EDGE: every check keyed on the xTR then answers
        # for the wrong box, and does so plausibly -- the socket check
        # reported the edge's LISP session to the control plane as though it
        # were the controller's.
        xtr_mgmtip=wlc_mgmtip,
        # The map-servers the controller registers this radio MAC to. The
        # edge's flow learns these from the EID identification phase, which
        # the controller has none of -- so `LispAuthenticationKey` has no
        # other source for which map-servers to restrict its comparison to.
        control_planes=[
            cp[0] if isinstance(cp, (tuple, list)) else cp
            for cp in control_planes])
    # Keyed by BOTH the address and the hostname: `show wireless fabric
    # summary` names control planes by address and the canvas nodes follow it,
    # while `node_for` looks up by hostname. Keyed one way only, the five
    # reused checks fall back to the controller's node and every per-control-
    # plane finding renders on the wrong device.
    for cp in control_planes:
        addr, host, _m = cp if isinstance(cp, (tuple, list)) else (cp, cp, cp)
        node = (cp_nodes or {}).get(addr) or (cp_nodes or {}).get(host)
        if node:
            target.cp_nodes[addr] = node
            target.cp_nodes[host] = node

    checks = []
    rlocs = []
    for cp in control_planes:
        addr, host, mgmt = cp if isinstance(cp, (tuple, list)) else (cp, cp, cp)
        node = (cp_nodes or {}).get(addr) or (cp_nodes or {}).get(host) \
            or wlc_node_id
        rlocs.append(addr)

        # WLC-specific, and first: the control plane has to be configured to
        # accept a passive-open session from the WMI before the session state
        # below means anything.
        checks.append(WlcLocatorSet(host, mgmt, wmi, catc_name, node))
        checks.append(WlcCpSessionState(host, mgmt, wmi, catc_name, node))

        # Read the control plane, so they apply unchanged whether its peer is
        # an edge or a controller. Each runs whatever the session state is: an
        # Up session is not evidence that registrations are getting through.
        checks.append(LispControlPlaneConfiguration(target, host, mgmt))
        checks.append(LispAuthenticationKey(target, host, mgmt))
        checks.append(LispControlPlaneStatistics(target, host, mgmt))
        checks.append(LispTcpSocket(target, host, mgmt))
        checks.append(LispCpCpuUtilization(target, host, mgmt))
        # The control plane's own session to the map-server address, which
        # can be down while the controller's session to it is Up.
        checks.append(LispMapServerSelfSession(target, addr, host, mgmt))
        # Path policy, read ON the control plane, towards the WMI: the
        # controller sits outside the fabric, so its LISP traffic crosses a
        # border and an ACL or an SGT policy there blocks registrations while
        # every other check on this control plane passes.
        #
        # Only the control-plane side. The near side would read CEF, ACLs and
        # CTS policy on the C9800 with IOS-XE switch commands, which is the
        # same wrong-device mistake the edge readers made earlier.
        checks.append(LispSessionAccessLists(target, addr, host, True, mgmt))
        checks.append(LispSessionTrustSec(target, addr, host, True, mgmt))

    # Site-wide, after each control plane has been looked at on its own.
    for cp in control_planes:
        addr, host, mgmt = cp if isinstance(cp, (tuple, list)) else (cp, cp, cp)
        checks.append(LispInterCpSession(target, host, mgmt, peers=rlocs))

    return checks
