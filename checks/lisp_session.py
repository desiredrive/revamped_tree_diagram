"""LISP session troubleshooting, as reusable streamable checks.

Explains why an EID is not registered on its control planes. Built to be called
from any flow that reaches that question -- AP onboarding, east-west L2LISP,
DHCP, IP transit -- rather than being specific to one of them.

Relationship to `traffic_flows/lispsessiontroubleshooting.py`
------------------------------------------------------------
That module is the CLI implementation and stays the reference for WHAT to
validate. This one reuses its readers (`ETRDevice`, `controlplane_eid`, the
`routingmodules.lisp` classes) but differs in two ways that matter on a canvas:

  * It does not call `sys.exit`. The CLI flow ends on its first fatal finding,
    which in a streamed run throws away every other step it would have
    reported. Here a fatal finding records a reason, later checks SKIP citing
    it, and everything already found still renders.

  * It fans out per control plane. Findings about a CP belong on that CP's
    node, not on the edge's.

Use `lisp_session_checks()` to get the list of checks for one EID; the caller
queues them through `data["queue_checks"]` and supplies the node ids it has
already drawn for its control planes.
"""

import types

from checks.base import Check, CheckResult, CheckStatus, RunContext
from checks.shared import (_cef_interfaces, _evaluate_acls,
                           render_acl_section)


# State key holding the reason the session flow cannot usefully continue. Set by
# the first check that finds something later steps depend on, read by the rest.
STOP_KEY = "lisp_session_stop"


class LispSessionTarget:
    """What one run of the session flow is about.

    Carries the EID and the devices involved so each check does not re-derive
    them, and so a caller that already knows the instance (AP onboarding knows
    the L3 IID) does not pay to look it up again.

    `cp_nodes` maps a control plane's hostname to the canvas node the caller
    drew for it, so per-CP findings render there. A CP with no entry falls back
    to the XTR node rather than being dropped.
    """

    def __init__(self, eid, xtr_hostname, catc_name, iid=None, af=None,
                 vrf="default", vlan=None, control_planes=None, cp_nodes=None,
                 xtr_node_id="xtr", label=None, xtr_mgmtip=None,
                 xtr_loopback=None):
        self.eid = eid
        self.xtr_hostname = xtr_hostname
        # Which device this flow reads. The AP chain's xtr_* state keys name
        # the edge, so a flow about a different xTR -- the controller
        # registers the radio MAC to the same control planes -- has to carry
        # its own device or it would profile the edge and report its fabric
        # under the controller's name. None means "the chain's xTR".
        self.xtr_mgmtip = xtr_mgmtip
        self.xtr_loopback = xtr_loopback
        self.catc_name = catc_name
        self.iid = iid
        self.af = af                      # "ipv4" | "ethernet", None = derive
        self.vrf = vrf
        self.vlan = vlan
        self.control_planes = control_planes or []
        self.cp_nodes = cp_nodes or {}
        self.xtr_node_id = xtr_node_id
        # How to name the EID in output ("the AP's address", "the client").
        self.label = label or f"EID {eid}"
        # Everything this flow caches in ctx.state is scoped to the device
        # whose sessions are being walked. The flow runs more than once in a
        # single AP run -- the edge registers the AP's address, the
        # controller registers its radio MAC -- and without this the second
        # run reads the first's profiled device, its session states and its
        # stop reason, and reports the wrong box's fabric.
        self.scope = xtr_hostname or "xtr"

    def key(self, name):
        """A ctx.state key private to this target's device."""
        return f"{name}::{self.scope}"

    def rloc(self, ctx, etr):
        """This target's own RLOC.

        `xtr_loopback` in ctx.state is the AP chain's edge. A flow about a
        different xTR must not read it -- doing so compares this device's
        sessions against the edge's address, and every check keyed on the
        RLOC silently answers for the wrong box. The profiled device is the
        authority whenever the target names its own.
        """
        if self.xtr_mgmtip:
            return self.xtr_loopback or getattr(
                getattr(etr, "profiled_device", None), "loopback", None)
        return ctx.state.get("xtr_loopback") or getattr(
            getattr(etr, "profiled_device", None), "loopback", None)

    @property
    def isl3(self):
        return self.af == "ipv4"

    def node_for(self, cp_hostname):
        return self.cp_nodes.get(cp_hostname) or self.xtr_node_id


class _SessionCheck(Check):
    """Base for the session-flow checks.

    Holds the target, and enforces the stop rule: once a check has recorded a
    reason the flow cannot continue, the rest skip citing it instead of failing
    again for the same underlying cause. Subclasses implement `run_session`.
    """

    def __init__(self, target: LispSessionTarget):
        self.target = target
        # Set here, not in run_session: the runner routes check_started
        # before run() is called, so a check that only assigns its node
        # while running is announced against the previous default -- the
        # edge -- and appears on the wrong node until it finishes.
        self.target_node_id = target.xtr_node_id

    def run(self, ctx: RunContext) -> CheckResult:
        stop = ctx.state.get(self.target.key(STOP_KEY))
        if stop:
            return CheckResult(CheckStatus.SKIP, f"Skipped — {stop}")
        return self.run_session(ctx)

    def run_session(self, ctx: RunContext) -> CheckResult:
        raise NotImplementedError

    def _stop(self, ctx: RunContext, reason: str, message: str, data=None):
        """Record why the flow cannot continue, and fail with the explanation."""
        ctx.state[self.target.key(STOP_KEY)] = reason
        return CheckResult(CheckStatus.FAIL, message, data=data or {})


def peer_session_states(etr):
    """This ETR's LISP peers as (up, down), each a list of (peer, state).

    The single reader of session state for the whole flow. The trigger that
    decides whether to run the flow and the check that reports session state
    inside it have to agree -- if they drift, the flow runs saying every
    session is down and then reports them up, or declines to run on state it
    would have reported as a fault.

    The switch's session to its own RLOC is not a peer and is skipped; a row
    whose state cannot be read counts as not up, because an unreadable
    session is not evidence of a healthy one.
    """
    peers = getattr(
        getattr(etr, "global_lisp_sessions", None), "peers", None) or {}
    own_rloc = getattr(getattr(etr, "profiled_device", None), "loopback", None)
    up, down = [], []
    for peer, rows in peers.items():
        if peer == own_rloc:
            continue
        try:
            state = rows[0]["state"]
        except (KeyError, IndexError, TypeError):
            state = "unknown"
        (up if str(state).strip().lower() == "up" else down).append(
            (peer, state))
    return up, down


def _profile_xtr(ctx: RunContext, target: LispSessionTarget):
    """The profiled ETR, built once per run and cached in ctx.state.

    `ETRDevice.eid_identification` and everything after it need a profiled
    device. Profiling costs a Catalyst Center roundtrip plus CLI, so it is done
    once and reused rather than per check.
    """
    cached = ctx.state.get(target.key("_lisp_session_etr"))
    if cached is not None:
        return cached
    from traffic_flows.lispsessiontroubleshooting import ETRDevice
    mgmt = target.xtr_mgmtip or ctx.state.get("xtr_mgmtip")
    etr = ETRDevice(mgmt, 0)
    # The web flow does not keep a device_profiler.Device around -- it spreads
    # the profile across ctx.state keys -- but `_build_src_xtr_shim` composes
    # exactly the attribute surface `existing_profiled` reads. Using it avoids
    # a second Catalyst Center roundtrip for a device already profiled.
    # The AP chain never runs CpLoopback/RlocDefinition, so xtr_loopback is
    # unset there and the shim would carry loopback=None -- which surfaces as
    # "no TCP socket ... to None" in the socket check, and silently breaks any
    # comparison keyed on the ETR RLOC. Resolve it from Catalyst Center the
    # same way the SGT check does, and cache it for everything downstream.
    # Only for the chain's own xTR: xtr_uuid and xtr_loopback both name the
    # edge, so resolving them for a different device would cache that
    # device's loopback under the edge's key.
    if not target.xtr_mgmtip \
            and not ctx.state.get("xtr_loopback") and ctx.state.get("xtr_uuid") \
            and ctx.state.get("catc_name") and ctx.service:
        try:
            from checks.lisp import _query_loopback0
            ip, mask, _err = _query_loopback0(ctx)
            if ip:
                ctx.state["xtr_loopback"] = ip
                if mask:
                    ctx.state["xtr_loopback_mask"] = mask
        except Exception:
            # Best effort: a failure here leaves loopback None, which the
            # callers already report rather than crash on.
            pass
    # The shim is composed from the chain's xtr_* state keys, so it only
    # describes the chain's own xTR. A target naming a different device must
    # be profiled through Catalyst Center instead -- reusing the shim would
    # read the edge and file its fabric under this target's name.
    if target.xtr_mgmtip and target.xtr_mgmtip != ctx.state.get("xtr_mgmtip"):
        etr.device_profiler(target.catc_name, ctx.service)
    else:
        from checks.ew_shared import _build_src_xtr_shim
        shim = _build_src_xtr_shim(ctx)
        if getattr(shim, "hostname", None):
            etr.existing_profiled(shim)
        else:
            etr.device_profiler(target.catc_name, ctx.service)
    ctx.state[target.key("_lisp_session_etr")] = etr
    return etr


class LispEidIdentification(_SessionCheck):
    """Is the EID known to this switch, and by what method?

    The first question: before asking why the control planes have no record,
    establish that the switch itself has the EID in its LISP database. A switch
    that never learned the address has nothing to register, and every later
    check would be reporting consequences of that.

    Reuses `EIDIdentification`, which walks instance -> dynamic-EID ->
    database-mapping -> database entry, and on a miss descends into the
    database limits and the SISF EID-watch state.
    """

    name = "LISP EID Identification"
    running_note = "Reading the LISP database and dynamic-EID state."

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        self.target_node_id = t.xtr_node_id
        try:
            etr = _profile_xtr(ctx, t)
            etr.eid_identification(t.eid, t.vlan, t.vrf, 0, ctx.service)
        except SystemExit as e:
            # The legacy readers still exit on their own fatal findings. That
            # reason is a real diagnosis, so it is surfaced rather than lost.
            return self._stop(ctx, f"LISP EID identification stopped: {e}",
                              f"The EID could not be identified on "
                              f"{t.xtr_hostname}:\n\n{e}")
        except BaseException as e:
            return self._stop(ctx, f"the EID could not be identified "
                                   f"({type(e).__name__})",
                              f"Could not identify {t.label} on "
                              f"{t.xtr_hostname} ({type(e).__name__}: {e}).")

        props = etr.eid_properties
        ctx.state["_lisp_session_eid_props"] = props

        # The flow derives the service from the EID type; a caller that already
        # knows it (AP onboarding knows it is an L3 address) still gets the
        # derived value checked against what the device says.
        eid_type = getattr(props, "eid_type", None)
        if eid_type == "MAC":
            t.af = "ethernet"
        elif eid_type in ("IPv4Subnet", "IPv4Host"):
            t.af = "ipv4"
        t.iid = getattr(props, "iid", None) or t.iid

        db_status = getattr(props, "db_status", None)
        mapservers = getattr(props, "mapservers", None) or []

        if db_status is False:
            return self._stop(
                ctx,
                f"{t.label} is not in the LISP database on {t.xtr_hostname}",
                f"{t.label} is not in this switch's LISP database for instance "
                f"{t.iid}. Nothing is registered to the control planes because "
                f"there is nothing to register — the address has to be in the "
                f"local database first. The checks above this one say why it "
                f"is not.",
                data={"lisp_db_status": False, "iid": t.iid},
            )

        lines = [
            f"• {t.label} is in the LISP database on {t.xtr_hostname} for "
            f"instance {t.iid}, learned by {getattr(props, 'db_method', None) or 'an unknown method'}."
        ]
        acked, unacked = [], []
        if mapservers:
            acked = [m.get("map_server") for m in mapservers
                     if str(m.get("ack", "")).lower() == "yes"]
            unacked = [m.get("map_server") for m in mapservers
                        if str(m.get("ack", "")).lower() != "yes"]
            if acked:
                lines.append(
                    f"• The switch has registered it to {', '.join(acked)}, "
                    f"which acknowledged.")
            if unacked:
                lines.append(
                    f"• {', '.join(unacked)} did not acknowledge the "
                    f"registration.")
        else:
            lines.append(
                "• The database entry names no map-server, so this switch is "
                "not registering the address anywhere.")

        # Grading is about the ACKs, not about whether map-servers are listed.
        # An entry naming two map-servers that both stay silent is the failure
        # this flow exists to explain, so it must not read as OK.
        if not mapservers:
            status = CheckStatus.WARN
        elif not acked:
            status = CheckStatus.WARN
        elif unacked:
            status = CheckStatus.WARN
        else:
            status = CheckStatus.OK
        return CheckResult(
            status,
            "\n".join(lines),
            data={"iid": t.iid, "af": t.af, "mapservers": mapservers,
                  "acked": acked if mapservers else [],
                  "unacked": unacked if mapservers else []},
        )


class LispMapServerConfiguration(_SessionCheck):
    """The map-server configuration on the ETR: proxy-reply flag and auth key.

    Registration can fail for reasons that never appear as a session problem:
    a map-server configured without proxy-reply, or with a key the control
    plane does not share. Both live only in the running configuration.

    Reuses `ETRConfiguration.etr_map_servers`, which reads
    `show run | section service <af>` and restricts what it grades to the
    map-servers this EID actually registers to.
    """

    name = "LISP Map-Server Configuration"
    running_note = "Reading the running configuration."

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        self.target_node_id = t.xtr_node_id
        props = ctx.state.get("_lisp_session_eid_props")
        if props is None:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — the EID was not identified, so the map-servers it "
                "registers to are not known.")
        try:
            etr = _profile_xtr(ctx, t)
            # Same self-overwriting hazard as cp_configuration; the reader is
            # called directly so a second run on the cached ETR still works.
            from traffic_flows.lispsessiontroubleshooting import ETRConfiguration
            etr_cfg = ETRConfiguration(etr.profiled_device.hostname)
            etr_cfg.etr_map_servers(props, t.af or "ipv4", ctx.service)
        except SystemExit as e:
            return self._stop(ctx, f"map-server configuration: {e}",
                              f"The map-server configuration on "
                              f"{t.xtr_hostname} stops the registration:"
                              f"\n\n{e}")
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the map-server configuration from "
                f"{t.xtr_hostname} ({type(e).__name__}: {e}).")

        cfg = getattr(etr_cfg, "mapserverconfiguration", None) or []
        ips = sorted({c.get("map_server_ip") for c in cfg if c.get("map_server_ip")})
        if not ips:
            return CheckResult(
                CheckStatus.WARN,
                f"No map-server is configured for the {t.af} service on "
                f"{t.xtr_hostname}, so nothing registers {t.label} anywhere.")

        undecryptable = sorted({
            c.get("map_server_ip") for c in cfg if not c.get("decrypted")})
        lines = [
            f"• {t.xtr_hostname} is configured to register to "
            f"{', '.join(ips)}, each with proxy-reply set and an "
            f"authentication key."
        ]
        if undecryptable:
            lines.append(
                f"• The key for {', '.join(undecryptable)} is type 6 "
                f"(AES-encrypted), which cannot be decrypted off the device, "
                f"so it cannot be compared against the control plane's. If "
                f"registration is failing on authentication, the Map-Server's "
                f"authentication-failure counter is what confirms it.")
        return CheckResult(CheckStatus.OK, "\n".join(lines),
                           data={"map_servers": ips})


class LispGlobalSession(_SessionCheck):
    """Is at least one LISP session from this switch up?

    The ETR keeps a session to each map-server. If every one is down, no
    registration can leave the switch regardless of what the database holds,
    and the per-map-server checks that follow would each repeat the same news.
    """

    name = "LISP Session — Global"
    running_note = "Reading LISP session state."

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        self.target_node_id = t.xtr_node_id
        try:
            etr = _profile_xtr(ctx, t)
            etr.global_lisp_session(ctx.service)
        except SystemExit as e:
            return self._stop(ctx, f"global LISP session: {e}",
                              f"The LISP sessions on {t.xtr_hostname} could "
                              f"not be read:\n\n{e}")
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the LISP session state from "
                f"{t.xtr_hostname} ({type(e).__name__}: {e}).")

        etr_rloc = getattr(etr.profiled_device, "loopback", None)
        ctx.state[t.key("_lisp_session_etr_rloc")] = etr_rloc
        up, down = peer_session_states(etr)

        if not up:
            listed = ", ".join(f"{p} ({s})" for p, s in down) or "none"
            # Reported, NOT stopped. Every session being down is the case
            # where the per-control-plane checks below matter most: the
            # underlay, the path MTU, the authentication key, the TCP socket
            # and the access lists are what say WHY none of them came up, and
            # a cause common to all three shows up there. Stopping here
            # skipped exactly those checks, so the worse fault produced less
            # diagnostic output than a single down session did. The verdict
            # stops the flow at the end, once that troubleshooting has run.
            return CheckResult(
                CheckStatus.WARN,
                f"No LISP session from {t.xtr_hostname} is up — {listed}. "
                f"Registrations cannot leave the switch at all, which is why "
                f"no control plane has {t.label}. The checks that follow "
                f"examine each control plane's path, configuration and "
                f"counters to say why none of them is up.",
                data={"lisp_sessions_up": [], "lisp_sessions_down": down},
            )

        lines = [f"• {len(up)} LISP session(s) up from {t.xtr_hostname}: "
                 f"{', '.join(p for p, _ in up)}."]
        status = CheckStatus.OK
        if down:
            status = CheckStatus.WARN
            lines.append(
                f"• Not up: {', '.join(f'{p} ({s})' for p, s in down)}. A "
                f"map-server whose session is down cannot receive this "
                f"switch's registrations.")
        return CheckResult(status, "\n".join(lines),
                           data={"lisp_sessions_up": up,
                                 "lisp_sessions_down": down})


class LispPerMapServerSession(_SessionCheck):
    """The ETR's session to ONE map-server, rendered on that control plane.

    `show lisp session <ms>` gives the state and the per-session error
    counters. A session can be Up and still be failing: malformed or deferred
    messages, or fatal errors, mean the registration is leaving the switch and
    not being accepted.

    One instance per map-server, so a control plane's session problem appears
    on that control plane's node.
    """

    def __init__(self, target, map_server, cp_hostname=None):
        self.target = target
        self.map_server = map_server
        self.cp_hostname = cp_hostname or map_server
        self.name = f"LISP Session — {self.cp_hostname}"
        # Set here, NOT in run_session: the runner reads this to route the
        # check_started/check_finished events, and it does that before run().
        self.target_node_id = target.node_for(self.cp_hostname)
        self.running_note = f"Reading the session to {self.map_server}."

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        try:
            etr = _profile_xtr(ctx, t)
            # NOT etr.specific_lisp_session(): that method assigns its result
            # over its own name, so it can only ever be called once per
            # ETRDevice -- and this ETR is cached across every per-CP check.
            # The second control plane would find a LISPSession object where
            # the method used to be. The underlying reader has no such issue.
            from routingmodules.lisp import LISPSession
            sess = LISPSession(etr.profiled_device.hostname)
            sess.specificlispsession(self.map_server, ctx.service)
        except SystemExit as e:
            return self._stop(ctx, f"LISP session to {self.map_server}: {e}",
                              f"The session to {self.map_server} could not be "
                              f"read:\n\n{e}")
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the LISP session to {self.map_server} from "
                f"{t.xtr_hostname} ({type(e).__name__}: {e}).")

        state = str(getattr(sess, "session_state", "") or "unknown")
        uptime = getattr(sess, "session_state_time", None)

        def _int(attr):
            try:
                return int(getattr(sess, attr, 0) or 0)
            except (TypeError, ValueError):
                return 0

        msgs_in, msgs_out = _int("messages_in"), _int("messages_out")
        errors = {
            "fatal errors": _int("fatal_errors"),
            "malformed messages": _int("rcvd_malformed"),
            "unsupported messages": _int("rcvd_unsupported"),
            "messages for an invalid VRF": _int("rcvd_invalid_vrf"),
            "deferred sends": _int("sent_defferred"),
        }
        seen = {k: v for k, v in errors.items() if v}

        data = {"map_server": self.map_server, "state": state,
                "messages_in": msgs_in, "messages_out": msgs_out,
                "errors": seen}
        # Recorded so the verdict at the end of the flow can see every
        # map-server at once. Each check only ever knows about its own.
        ctx.state.setdefault(
            t.key("lisp_session_states"), {})[self.map_server] = state

        if state.lower() != "up":
            # WARN, not FAIL: a down session is a finding about the fabric, and
            # the checks after it (CP config, counters, socket) are exactly what
            # explain WHY it is down. Stopping here would discard them.
            return CheckResult(
                CheckStatus.WARN,
                f"The LISP session from {t.xtr_hostname} to "
                f"{self.map_server} is {state}, so this control plane never "
                f"receives the registration for {t.label}. Until the session "
                f"comes up, nothing else about this control plane matters.",
                data=data,
            )

        lines = [
            f"• The session to {self.map_server} is up"
            + (f" and has been for {uptime}" if uptime else "")
            + f", with {msgs_out} message(s) sent and {msgs_in} received."
        ]
        status = CheckStatus.OK
        if seen:
            status = CheckStatus.WARN
            lines.append(
                "• The session reports "
                + ", ".join(f"{v} {k}" for k, v in seen.items())
                + ". A session can be up and still not carry a registration "
                  "successfully, and these counters are where that shows.")
        return CheckResult(status, "\n".join(lines), data=data)


def _cp_device(ctx, cp_hostname, catc_name, cp_mgmt=None):
    """A profiled ControlPlaneDevice, cached per control plane.

    `ControlPlaneDevice` takes a MANAGEMENT IP, not a name: it profiles through
    Catalyst Center, which is what resolves the IP to the RADKit inventory
    name. Handing it a hostname makes the lookup fail with "not in RSA
    inventory" for a device that is present.
    """
    cache = ctx.state.setdefault("_lisp_session_cps", {})
    key = cp_mgmt or cp_hostname
    if key in cache:
        return cache[key]
    # An ETRDevice, not a ControlPlaneDevice: `cp_configuration` -- the site /
    # rloc-members / domain reader these checks need -- lives on ETRDevice, and
    # the CLI flow profiles control planes the same way.
    from traffic_flows.lispsessiontroubleshooting import ETRDevice
    cp = ETRDevice(key, 0)
    cp.device_profiler(catc_name, ctx.service)
    cache[key] = cp
    return cp


class LispControlPlaneConfiguration(_SessionCheck):
    """The site configuration on ONE control plane.

    A control plane only accepts a registration for an EID that its site
    configuration covers, from an RLOC its locator set allows. When the ETR is
    registering and the CP holds nothing, this is where the reason usually is.

    `cp_configuration_validation` takes `isl3`, which decides whether the
    site_uci check applies -- on an L3 instance it does not.
    """

    def __init__(self, target, cp_hostname, cp_mgmt=None):
        self.target = target
        self.cp_hostname = cp_hostname
        self.cp_mgmt = cp_mgmt or cp_hostname
        self.name = f"Control Plane Configuration — {cp_hostname}"
        self.target_node_id = target.node_for(cp_hostname)
        self.running_note = "Reading the site configuration — five CLI reads, takes ~25s."

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        from traffic_flows.lispsessiontroubleshooting import cp_configuration_validation
        try:
            cp = _cp_device(ctx, self.cp_hostname, t.catc_name, self.cp_mgmt)
            # Built directly rather than via cp.cp_configuration(): that method
            # assigns its result over its own name, so on a cached device the
            # second control plane finds an object where the method was.
            from routingmodules.lisp import L2LISPControlPlane
            cfg = L2LISPControlPlane(cp.profiled_device.hostname)
            cfg.lisp_service_ethernet(ctx.service)
            cfg.site_uci(t.iid, ctx.service)
            cfg.rloc_members(ctx.service)
            cfg.domains(ctx.service)
            cfg.fewparameters(ctx.service)
            cp_configuration_validation(0, cfg, t.iid, t.isl3)
        except SystemExit as e:
            # Reported against this control plane, and NOT set as a global
            # stop: another control plane may be configured correctly, and its
            # findings are still worth having.
            # WARN, not FAIL: a site configuration that rejects this
            # registration is a statement about the fabric, and the manifest's
            # rule is that those must not stop the run -- the remaining
            # control planes and every later check still have diagnostic
            # value. FAIL is for when the tool cannot continue.
            return CheckResult(
                CheckStatus.WARN,
                f"The site configuration on {self.cp_hostname} does not "
                f"accept this registration:\n\n{e}",
                data={"cp": self.cp_hostname},
            )
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the site configuration from "
                f"{self.cp_hostname} ({type(e).__name__}: {e}).",
                data={"cp": self.cp_hostname},
            )

        # `domains` is read above and was never graded: the five checks in
        # `cp_configuration_validation` cover the site and the roles, and stop
        # there. Not fatal on its own, so it is reported alongside the pass
        # rather than raised through it.
        #
        # `rloc_members` is read too and is deliberately NOT graded: a fabric
        # runs correctly without `map-server rloc members distribute`, and
        # Border2 in this lab does.
        notes = []
        domain = getattr(cfg, "domainid", 0)
        multihoming = getattr(cfg, "multihomingid", 0)
        if not domain:
            notes.append(
                f"• No LISP domain ID is set on {self.cp_hostname}. Publish "
                f"and subscribe between map-servers is keyed on it, so "
                f"without one this control plane cannot share registrations "
                f"with its peers.")

        lines = [
            f"• The site configuration on {self.cp_hostname} covers instance "
            f"{t.iid}: it is a map-server and map-resolver, site_uci is "
            f"defined, and the instance is configured under it."
        ]
        if domain:
            lines.append(f"• Domain ID {domain}, multihoming ID "
                         f"{multihoming}.")
        if notes:
            return CheckResult(
                CheckStatus.WARN, "\n".join(lines + [""] + notes),
                data={"cp": self.cp_hostname, "domain_id": domain})
        return CheckResult(
            CheckStatus.OK, "\n".join(lines),
            data={"cp": self.cp_hostname, "domain_id": domain},
        )


class LispControlPlaneStatistics(_SessionCheck):
    """The LISP counters on ONE control plane, for this instance.

    Where a rejected registration actually shows up. A Map-Register that is
    sent, received and then discarded leaves no record and no session error --
    only a counter here moves.
    """

    def __init__(self, target, cp_hostname, cp_mgmt=None):
        self.target = target
        self.cp_hostname = cp_hostname
        self.cp_mgmt = cp_mgmt or cp_hostname
        self.name = f"Control Plane Statistics — {cp_hostname}"
        self.target_node_id = target.node_for(cp_hostname)
        self.running_note = "Reading the LISP counters."

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        from routingmodules.lisp import LISPInstanceStatus
        try:
            # CLI is issued against the RADKit inventory name, which the
            # profiler resolves from the management IP -- see _cp_device.
            cp = _cp_device(ctx, self.cp_hostname, t.catc_name, self.cp_mgmt)
            stats = LISPInstanceStatus(cp.profiled_device.hostname, t.iid)
            stats.eidStatistics(t.af or "ipv4", ctx.service)
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading the LISP counters on {self.cp_hostname} stopped:"
                f"\n\n{e}", data={"cp": self.cp_hostname})
        except KeyError as e:
            # The parsed output carried no LISP instance -- `lisp_id` is the
            # key the statistics walk indexes by. That is a statement about
            # the device, not a tool failure: this control plane has no LISP
            # instance matching the one the AP registers into. A fabric fault
            # is a warning, so the remaining control planes still get walked.
            return CheckResult(
                CheckStatus.WARN,
                f"{self.cp_hostname} returned no LISP instance {t.iid} when "
                f"its counters were read (missing {e}), so it cannot be told "
                f"whether registrations for {t.label} are arriving. A control "
                f"plane with no instance {t.iid} cannot accept them at all — "
                f"check that it serves this instance.",
                data={"cp": self.cp_hostname})
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the LISP counters from {self.cp_hostname} "
                f"({type(e).__name__}: {e}).", data={"cp": self.cp_hostname})

        if not getattr(stats, "statisticscollected", False):
            return CheckResult(
                CheckStatus.WARN,
                f"{self.cp_hostname} returned no LISP statistics for instance "
                f"{t.iid}, so it cannot be told whether registrations are "
                f"arriving and being rejected.",
                data={"cp": self.cp_hostname})

        def _int(attr):
            try:
                return int(getattr(stats, attr, 0) or 0)
            except (TypeError, ValueError):
                return 0

        registers = _int("map_register")
        notifies = _int("map_notify")
        rejects = {
            "registrations dropped for an invalid source RLOC":
                _int("map_register_invalid_source_rloc_drops"),
            "EID prefixes rejected because a limit was reached":
                _int("rejected_eid_prefix_due_to_limit"),
            "packets dropped on the LISP control port":
                _int("lisp_control_port_drops"),
            "malformed packets dropped": _int("lisp_checksum_drops"),
            "unsupported LISP packets dropped":
                _int("unsupported_lisp_packet_drops"),
        }
        seen = {k: v for k, v in rejects.items() if v}

        data = {"cp": self.cp_hostname, "map_register": registers,
                "map_notify": notifies, "rejects": seen}

        lines = [f"• {self.cp_hostname} has received {registers} Map-Register "
                 f"message(s) for instance {t.iid} and sent {notifies} "
                 f"Map-Notify."]
        status = CheckStatus.OK
        if seen:
            status = CheckStatus.WARN
            for k, v in seen.items():
                lines.append(f"• {v} {k}.")
            lines.append(
                "• These counters are cumulative and carry no timestamp, so "
                "they say that registrations were discarded, not when. "
                "Re-read them to see whether they are still moving.")
        elif registers == 0:
            status = CheckStatus.WARN
            lines.append(
                f"• No Map-Register has arrived for instance {t.iid} at all. "
                f"The switch reports sending them, so they are not reaching "
                f"this control plane — the path between them is what to look "
                f"at, not the registration itself.")
        return CheckResult(status, "\n".join(lines), data=data)


def lisp_session_checks(target: LispSessionTarget, map_servers=None):
    """The session-flow checks for one EID, in the order they should run.

    The reusable entry point: a caller that has reached "this EID is not
    registered" builds a `LispSessionTarget` and queues what this returns
    through `data["queue_checks"]`.

        target = LispSessionTarget(
            eid=ap_ip, xtr_hostname=..., catc_name=..., iid=4097, af="ipv4",
            cp_nodes={"border1-x": "apcp-1"}, label="the AP's address",
        )
        return CheckResult(..., data={"queue_checks": lisp_session_checks(target)})

    `map_servers` names the control planes to fan out over. When omitted, the
    per-CP checks are built from `target.control_planes`; when that is empty
    too, only the three switch-side checks are returned -- the EID
    identification check discovers the map-servers, but too late to build
    checks from here, so a caller that wants the per-CP steps passes them in.
    """
    checks = [
        LispEidIdentification(target),
        LispMapServerConfiguration(target),
        LispGlobalSession(target),
    ]

    servers = list(map_servers or [])
    if not servers:
        for cp in target.control_planes:
            host = getattr(cp, "hostname", None) or getattr(cp, "mgmtip", None) or cp
            servers.append(host)

    rlocs = []
    for server in servers:
        # A caller may pass either "the RLOC the ETR registers to" or "the
        # control plane's hostname"; the session command needs the address,
        # the node lookup and the output need the name.
        # (rloc, hostname, mgmt_ip): the ETR peers with the RLOC, the output
        # names the host, and profiling the device needs the management IP.
        # Shorter forms are accepted and fall back to what is given.
        if isinstance(server, (tuple, list)):
            if len(server) == 3:
                ms, host, mgmt = server
            elif len(server) == 2:
                ms, host = server
                mgmt = ms
            else:
                ms = host = mgmt = server[0]
        else:
            ms = host = mgmt = server
        # Underlay first: if the route or CEF entry to this map-server is
        # wrong, the session state that follows is a symptom of it.
        checks.append(LispSessionRouting(target, ms, host))
        # Independent of session state: a path that carries small packets and
        # drops big ones loses registrations while the session stays Up.
        checks.append(LispSessionPathMtu(target, ms, host))
        checks.append(LispPerMapServerSession(target, ms, host))
        # Order follows singleETRProfiling: configuration, then the key, then
        # the counters, then the socket carrying them, then the CPU that has
        # to process them. Each runs whatever the session state is -- an Up
        # session is not evidence that registrations are getting through.
        checks.append(LispControlPlaneConfiguration(target, host, mgmt))
        checks.append(LispAuthenticationKey(target, host, mgmt))
        checks.append(LispControlPlaneStatistics(target, host, mgmt))
        checks.append(LispTcpSocket(target, host, mgmt))
        checks.append(LispCpCpuUtilization(target, host, mgmt))
        # The control plane's own session to the map-server address, which
        # can be down while the switch's session to it is Up.
        checks.append(LispMapServerSelfSession(target, ms, host, mgmt))
        # Path policy, both directions: what the switch applies towards the
        # map-server, and what the control plane applies back.
        checks.append(LispSessionAccessLists(target, ms, host, False, mgmt))
        checks.append(LispSessionAccessLists(target, ms, host, True, mgmt))
        checks.append(LispSessionTrustSec(target, ms, host, False, mgmt))
        checks.append(LispSessionTrustSec(target, ms, host, True, mgmt))
        rlocs.append(ms)

    # Site-wide, after every CP has been looked at individually: can the
    # control planes see each other. Each CP is asked about the others.
    for server in servers:
        if isinstance(server, (tuple, list)):
            ms = server[0]
            host = server[1] if len(server) > 1 else server[0]
            mgmt = server[2] if len(server) > 2 else ms
        else:
            ms = host = mgmt = server
        checks.append(LispInterCpSession(target, host, mgmt, peers=rlocs))

    # Last: the flow's own conclusion. Every session still down by here means
    # the troubleshooting is exhausted, and that is where the flow stops --
    # not at the first down session, which would discard the checks that
    # explain it.
    checks.append(LispSessionVerdict(target, map_servers=servers))

    return checks


# --------------------------------------------------------------------------
# Parity with singleETRProfiling: everything below was in the CLI flow but not
# in the first port. Two groups:
#
#   * unconditional -- runs on every reachable CP regardless of session state
#     (auth key, TCP socket/TCB, CPU, inter-CP sessions)
#   * state-gated -- the Down/Init/NoRoute tree, which fires only when a
#     map-server session is not Up
#
# The CLI flow is one linear function with a `step` counter; here each stage is
# its own Check so the canvas can show where the flow stopped.
# --------------------------------------------------------------------------


class LispAuthenticationKey(_SessionCheck):
    """Does the ETR's map-server key match the one the control plane expects.

    A wrong key does NOT bring the session down -- it causes per-registration
    authentication failures on the map-server. So an Up session is no proof
    the keys agree, which is why this runs on every CP regardless of state.

    Types 6/8/9 are AES-encrypted against a device-local primary key and
    cannot be read off-box. Those are reported as unverifiable rather than
    compared, because a false mismatch here would send someone rekeying a
    working fabric.
    """

    def __init__(self, target, cp_hostname, cp_mgmt=None):
        self.target = target
        self.cp_hostname = cp_hostname
        self.cp_mgmt = cp_mgmt or cp_hostname
        self.name = f"Authentication Key — {cp_hostname}"
        self.running_note = "Comparing the ETR and control-plane keys."
        self.target_node_id = target.node_for(cp_hostname)

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        try:
            cp = _cp_device(ctx, self.cp_hostname, t.catc_name, self.cp_mgmt)
            from routingmodules.lisp import L2LISPControlPlane
            cfg = L2LISPControlPlane(cp.profiled_device.hostname)
            cfg.site_uci(t.iid, ctx.service)
            cp_loopback = cp.profiled_device.loopback

            etr = _profile_xtr(ctx, t)
            from traffic_flows.lispsessiontroubleshooting import ETRConfiguration
            etr_cfg = ETRConfiguration(etr.profiled_device.hostname)
            # `etr_map_servers` wants one thing off this object: `.mapservers`,
            # the map-servers actually registering this EID, which restrict a
            # show-run blob covering every instance on the box.
            #
            # On the edge that comes from the EID identification phase, as
            # `eid_properties`. The controller's flow has no such phase -- its
            # map-servers come from `show wireless fabric summary` -- so
            # reading `etr.eid_properties` there raised AttributeError and the
            # key was never compared. The target knows its own map-servers in
            # both cases, so they are taken from it and the EID phase's record
            # is used only when it exists.
            props = ctx.state.get("_lisp_session_eid_props")
            if props is None or not getattr(props, "mapservers", None):
                props = types.SimpleNamespace(
                    mapservers=[{"map_server": ms} for ms in
                                (t.control_planes or [])] or None)
            etr_cfg.etr_map_servers(props, t.af or "ipv4", ctx.service)
            ms_config = getattr(etr_cfg, "mapserverconfiguration", None) or []
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading the authentication keys for {self.cp_hostname} "
                f"stopped:\n\n{e}", data={"cp": self.cp_hostname})
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not compare authentication keys for "
                f"{self.cp_hostname} ({type(e).__name__}: {e}).",
                data={"cp": self.cp_hostname})

        try:
            cp_key = cfg.authentication_key[1]
        except (AttributeError, IndexError, TypeError):
            cp_key = None
        cp_decrypted = getattr(cfg, "decrypted", False)

        if cp_decrypted is False:
            return CheckResult(
                CheckStatus.WARN,
                f"The key on {self.cp_hostname} is stored in a form that "
                f"cannot be read off the device, so it cannot be compared "
                f"with the switch's. If registration is failing, the "
                f"authentication-failure counters on this control plane are "
                f"what settle it.",
                data={"cp": self.cp_hostname, "comparable": False})

        for ms in ms_config:
            if ms.get("map_server_ip") != cp_loopback:
                continue
            try:
                etr_key = ms["authentication_key"][1]
            except (KeyError, IndexError, TypeError):
                etr_key = None
            if not ms.get("decrypted", True):
                return CheckResult(
                    CheckStatus.WARN,
                    f"The switch's key for {self.cp_hostname} (type "
                    f"{ms.get('key_type')}) cannot be read off the device, so "
                    f"the two keys cannot be compared. Check this control "
                    f"plane's authentication-failure counters if registration "
                    f"is failing.",
                    data={"cp": self.cp_hostname, "comparable": False})
            if etr_key == cp_key:
                return CheckResult(
                    CheckStatus.OK,
                    f"The switch and {self.cp_hostname} agree on the "
                    f"authentication key.",
                    data={"cp": self.cp_hostname})
            return CheckResult(
                CheckStatus.WARN,
                f"The switch and {self.cp_hostname} do not agree on the "
                f"authentication key, so registrations will be rejected: the "
                f"switch sends {etr_key!r} and the control plane expects "
                f"{cp_key!r}.",
                data={"cp": self.cp_hostname, "mismatch": True})

        return CheckResult(
            CheckStatus.WARN,
            f"The switch has no map-server entry for {cp_loopback}, so there "
            f"is no key to compare against {self.cp_hostname}.",
            data={"cp": self.cp_hostname})


class LispTcpSocket(_SessionCheck):
    """The TCP socket carrying the LISP session, from the control plane side.

    Runs whatever the session state is. A LISP session reported Up can still
    be losing Map-Registers: the retransmit counters here are the only place
    that shows it, and they are read on the CP, matching the socket by
    (CP loopback, ETR loopback, port 4342).
    """

    def __init__(self, target, cp_hostname, cp_mgmt=None):
        self.target = target
        self.cp_hostname = cp_hostname
        self.cp_mgmt = cp_mgmt or cp_hostname
        self.name = f"TCP Socket — {cp_hostname}"
        self.running_note = "Reading the TCP socket and TCB counters."
        self.target_node_id = target.node_for(cp_hostname)

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        try:
            cp = _cp_device(ctx, self.cp_hostname, t.catc_name, self.cp_mgmt)
            etr = _profile_xtr(ctx, t)
            cp_loopback = cp.profiled_device.loopback
            etr_loopback = etr.profiled_device.loopback
            # Port 4342 is the LISP control port; the CLI flow matches on the
            # CP's own loopback as source, so the socket found is the one this
            # control plane opened towards this ETR.
            if not etr_loopback:
                # Without the ETR RLOC there is nothing to match the socket
                # against, and every entry would fail the comparison -- which
                # reads as "no socket" and blames the control plane.
                return CheckResult(
                    CheckStatus.WARN,
                    f"The switch's RLOC (Loopback0) could not be resolved, so "
                    f"the LISP socket on {self.cp_hostname} cannot be "
                    f"identified. Nothing is known about the socket either "
                    f"way.",
                    data={"cp": self.cp_hostname, "etr_loopback": None})
            cp.tcp_tcb_statistics(cp_loopback, etr_loopback, 4342, ctx.service)
            sockets = getattr(cp, "tcb_statistics", None) or []
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading the TCP socket on {self.cp_hostname} stopped:"
                f"\n\n{e}", data={"cp": self.cp_hostname})
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the TCP socket from {self.cp_hostname} "
                f"({type(e).__name__}: {e}).", data={"cp": self.cp_hostname})

        if not sockets:
            return CheckResult(
                CheckStatus.WARN,
                f"{self.cp_hostname} has no TCP socket from {cp_loopback} to "
                f"{etr_loopback} on port 4342. The LISP session rides this "
                f"socket, so without it nothing can be registered to this "
                f"control plane.",
                data={"cp": self.cp_hostname, "sockets": 0})

        lines, problems = [], []
        for s in sockets:
            local = f"{getattr(s, 'local_host', '?')}:{getattr(s, 'local_port', '?')}"
            foreign = f"{getattr(s, 'foreign_host', '?')}:{getattr(s, 'foreign_port', '?')}"
            lines.append(f"• {local} → {foreign}, MSS {getattr(s, 'mss', '?')}")
            # Same three counters the CLI parser warns on. Any non-zero value
            # means segments had to be sent again -- packet loss on the path
            # between this CP and the ETR.
            for attr, label in (
                    ("retransmitqueue", "segments waiting in the retransmit queue"),
                    ("retransmitcounter", "retransmissions"),
                    ("fastretransmitcounter", "fast retransmissions")):
                try:
                    n = int(getattr(s, attr, 0) or 0)
                except (TypeError, ValueError):
                    n = 0
                if n:
                    problems.append(f"{n} {label} on {local} → {foreign}")

        detail = "\n".join(lines)
        if problems:
            return CheckResult(
                CheckStatus.WARN,
                f"The LISP socket on {self.cp_hostname} is up but showing "
                f"retransmissions, so Map-Registers are being lost on the path "
                f"and re-sent:\n\n" + "\n".join(f"• {p}" for p in problems)
                + f"\n\n{detail}",
                data={"cp": self.cp_hostname, "problems": problems})

        return CheckResult(
            CheckStatus.OK,
            f"{self.cp_hostname} holds the LISP socket to {etr_loopback} with "
            f"no retransmissions:\n\n{detail}",
            data={"cp": self.cp_hostname})


class LispCpCpuUtilization(_SessionCheck):
    """CPU on the control plane.

    A control plane under CPU pressure can accept a session and still fail to
    process Map-Registers in time, which looks like a registration problem
    everywhere except here. Runs regardless of session state.
    """

    def __init__(self, target, cp_hostname, cp_mgmt=None):
        self.target = target
        self.cp_hostname = cp_hostname
        self.cp_mgmt = cp_mgmt or cp_hostname
        self.name = f"Control Plane CPU — {cp_hostname}"
        self.running_note = "Reading CPU utilization."
        self.target_node_id = target.node_for(cp_hostname)

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        try:
            cp = _cp_device(ctx, self.cp_hostname, t.catc_name, self.cp_mgmt)
            cp.cpu_utilization(ctx.service)
            stats = cp.cpu_statistics
            procs = list(getattr(stats, "high_cpu_processes", None) or [])
            plat = list(getattr(stats, "plat_high_cpu_processes", None) or [])
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading CPU on {self.cp_hostname} stopped:\n\n{e}",
                data={"cp": self.cp_hostname})
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read CPU from {self.cp_hostname} "
                f"({type(e).__name__}: {e}).", data={"cp": self.cp_hostname})

        def _fmt(entries, pid_key):
            out = []
            for e in entries:
                try:
                    out.append(f"• {e.get('process')} (PID {e.get(pid_key)}) "
                               f"at {e.get('five_sec_cpu')}%")
                except AttributeError:
                    out.append(f"• {e}")
            return out

        # The IOS-XE process and platform tables name the pid column
        # differently -- 'pid' vs 'ppid'. Reading the wrong one prints None.
        busy = _fmt(procs, "pid") + _fmt(plat, "ppid")
        if busy:
            return CheckResult(
                CheckStatus.WARN,
                f"{self.cp_hostname} has processes at high CPU, which can delay "
                f"or drop LISP registration processing:\n\n" + "\n".join(busy),
                data={"cp": self.cp_hostname, "high_cpu": len(busy)})

        return CheckResult(
            CheckStatus.OK,
            f"No process on {self.cp_hostname} is at high CPU.",
            data={"cp": self.cp_hostname})


class LispInterCpSession(_SessionCheck):
    """LISP session state from one control plane to the others.

    The CLI flow runs this site-wide after the per-CP work: each reachable CP
    is asked about its sessions to every OTHER map-server, with its own RLOC
    removed from the list (a CP does not peer with itself). A site whose CPs
    cannot talk to each other can still register an EID on one of them and
    then behave inconsistently depending on which CP is asked.
    """

    def __init__(self, target, cp_hostname, cp_mgmt=None, peers=None):
        self.target = target
        self.cp_hostname = cp_hostname
        self.cp_mgmt = cp_mgmt or cp_hostname
        self.peers = list(peers or [])
        self.name = f"Inter-CP Sessions — {cp_hostname}"
        self.running_note = "Reading sessions to the other control planes."
        self.target_node_id = target.node_for(cp_hostname)

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        try:
            cp = _cp_device(ctx, self.cp_hostname, t.catc_name, self.cp_mgmt)
            cp_rloc = cp.profiled_device.loopback
            # A control plane does not peer with itself; the CLI flow strips
            # its own RLOC from the map-server list before asking.
            peers = [p for p in self.peers if p and p != cp_rloc]
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading {self.cp_hostname} stopped:\n\n{e}",
                data={"cp": self.cp_hostname})
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read {self.cp_hostname} "
                f"({type(e).__name__}: {e}).", data={"cp": self.cp_hostname})

        if not peers:
            return CheckResult(
                CheckStatus.OK,
                f"{self.cp_hostname} is the only control plane in this fabric "
                f"site, so there is no inter-CP session to check.",
                data={"cp": self.cp_hostname})

        from routingmodules.lisp import LISPSession
        lines, bad = [], []
        for peer in peers:
            try:
                sess = LISPSession(cp.profiled_device.hostname)
                sess.specificlispsession(peer, ctx.service)
                state = str(getattr(sess, "session_state", "") or "unknown")
            except BaseException as e:
                lines.append(f"• {peer}: could not be read "
                             f"({type(e).__name__})")
                bad.append(peer)
                continue
            lines.append(f"• {peer}: {state}")
            if state != "Up":
                bad.append(peer)

        detail = "\n".join(lines)
        if bad:
            return CheckResult(
                CheckStatus.WARN,
                f"{self.cp_hostname} does not have an established LISP session "
                f"to every other control plane in the site, so the control "
                f"planes can disagree about what is registered:\n\n{detail}",
                data={"cp": self.cp_hostname, "down_peers": bad})

        return CheckResult(
            CheckStatus.OK,
            f"{self.cp_hostname} has an established session to every other "
            f"control plane:\n\n{detail}",
            data={"cp": self.cp_hostname})


class LispSessionRouting(_SessionCheck):
    """Route, CEF and IGP recursion from the switch to one map-server.

    Independent of session state. The CLI flow only reaches this when a
    session is Down/Init/NoRoute, but the underlay can be degraded -- a
    default route standing in for a specific one, a nexthop that has gone
    Null0 -- while the session is still Up, and that is worth seeing before
    it breaks.
    """

    def __init__(self, target, map_server, cp_hostname=None):
        self.target = target
        self.map_server = map_server
        self.cp_hostname = cp_hostname or map_server
        self.name = f"Underlay Routing — {self.cp_hostname}"
        self.running_note = "Reading route, CEF and IGP neighbors."
        self.target_node_id = target.node_for(self.cp_hostname)

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        from routingmodules.iprouting import IPRoute
        from routingmodules.cef import IPCef
        try:
            etr = _profile_xtr(ctx, t)
            host = etr.profiled_device.hostname
            route = IPRoute(self.map_server, None, host)
            route.iproute_prefix(ctx.service, 0)
            cef = IPCef(self.map_server, None, host)
            cef.get_cef_internal(ctx.service)
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading the route to {self.map_server} stopped:\n\n{e}",
                data={"cp": self.cp_hostname})
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the route to {self.map_server} "
                f"({type(e).__name__}: {e}).", data={"cp": self.cp_hostname})

        lines, problems = [], []
        data = {"cp": self.cp_hostname, "map_server": self.map_server}

        # A default route is not a route TO the map-server -- it is the
        # absence of one, and the session will follow whatever the default
        # happens to reach.
        if str(getattr(route, "mask", "")) == "0":
            problems.append(
                f"the only route to {self.map_server} is a default route, "
                f"not a specific one")
        else:
            lines.append(f"• Route via {getattr(route, 'nexthop', '?')} "
                         f"({getattr(route, 'protocol', '?')})")

        nexthops = list(getattr(cef, "nexthops", None) or [])
        for entry in nexthops:
            oif = entry.get("oif") if isinstance(entry, dict) else None
            if oif == "Null0":
                problems.append(
                    f"the CEF entry for {self.map_server} points at Null0, so "
                    f"the traffic is dropped on this switch")
        if nexthops:
            lines.append(f"• CEF nexthops: {nexthops}")

        data["nexthops"] = nexthops
        detail = "\n".join(lines)
        if problems:
            return CheckResult(
                CheckStatus.WARN,
                f"The underlay path from {t.xtr_hostname} to "
                f"{self.map_server} is not sound:\n\n"
                + "\n".join(f"• {p}" for p in problems)
                + (f"\n\n{detail}" if detail else ""),
                data=data)

        return CheckResult(
            CheckStatus.OK,
            f"{t.xtr_hostname} has a specific route and a valid CEF entry to "
            f"{self.map_server}:\n\n{detail}",
            data=data)


class LispSessionPathMtu(_SessionCheck):
    """Reachability and MTU from the switch's RLOC to one map-server.

    Independent of session state, and deliberately so: a path that only fails
    at full MTU carries the small LISP control packets fine and drops the
    large ones, which looks like an intermittent registration problem rather
    than a broken link. The session can be Up throughout.

    The size tested is the lowest MTU among the underlay interfaces towards
    the map-server, matching the CLI flow.
    """

    def __init__(self, target, map_server, cp_hostname=None):
        self.target = target
        self.map_server = map_server
        self.cp_hostname = cp_hostname or map_server
        self.name = f"Path MTU — {self.cp_hostname}"
        self.running_note = "Pinging the map-server at low and full MTU."
        self.target_node_id = target.node_for(self.cp_hostname)

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        data = {"cp": self.cp_hostname, "map_server": self.map_server}
        try:
            etr = _profile_xtr(ctx, t)
            host = etr.profiled_device.hostname
            rloc = t.rloc(ctx, etr)
            if not rloc:
                return CheckResult(
                    CheckStatus.WARN,
                    f"The switch's RLOC could not be resolved, so the path to "
                    f"{self.map_server} cannot be tested from it.", data=data)

            # The interfaces towards the map-server come from the IGP the
            # route to it was learned by; a directly-connected map-server has
            # no IGP recursion to do.
            from routingmodules.iprouting import IPRoute, IGPInfo
            route = IPRoute(self.map_server, None, host)
            route.iproute_prefix(ctx.service, 0)
            protocol = str(getattr(route, "protocol", "") or "")
            interfaces = []
            if "onnected" not in protocol:
                phys = IGPInfo(host)
                phys.igp_neighbors(protocol, ctx.service)
                # igp_neighbors leaves neighbor_interfaces unset for an IGP it
                # does not handle, or when the parse returns nothing.
                interfaces = list(getattr(phys, "neighbor_interfaces", None) or [])
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading the path to {self.map_server} stopped:\n\n{e}",
                data=data)
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not work out the path to {self.map_server} "
                f"({type(e).__name__}: {e}).", data=data)

        # Lowest MTU across those interfaces is what the path can actually
        # carry; anything larger is what would be dropped.
        mtus = []
        from switchingmodules.interfaces import Interfaces
        for intf in interfaces:
            try:
                info = Interfaces(intf, host)
                info.show_interface(ctx.service)
                mtu = getattr(info, "mtu", None)
                if mtu:
                    mtus.append(int(mtu))
            except BaseException:
                # One unreadable interface must not cost us the ping tests.
                continue
        minimum = min(mtus) if mtus else None
        data["interfaces"] = interfaces
        data["min_mtu"] = minimum

        from traffic_flows.operational_tests import Ping

        def _ping(size, dfbit):
            p = Ping(self.map_server, host)
            p.ping_with_source(None, rloc, size, dfbit, ctx.service)
            try:
                return int(p.result)
            except (TypeError, ValueError):
                return None

        try:
            low = _ping(None, False)
            big = _ping(minimum, True) if minimum else None
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not ping {self.map_server} from {rloc} "
                f"({type(e).__name__}: {e}).", data=data)

        data["success_low"] = low
        data["success_mtu"] = big

        lines = [f"• Small packets: {low}% success" if low is not None
                 else "• Small packets: no result"]
        if minimum:
            lines.append(
                f"• {minimum}-byte packets, do-not-fragment: "
                + (f"{big}% success" if big is not None else "no result"))
        else:
            lines.append(
                "• Full-MTU test skipped: the underlay interfaces towards "
                "this map-server could not be determined.")
        detail = "\n".join(lines)

        # 70% is the CLI flow's threshold.
        if low is not None and low <= 70:
            return CheckResult(
                CheckStatus.WARN,
                f"{t.xtr_hostname} cannot reliably reach {self.map_server} "
                f"from its RLOC — even small packets are being lost, so the "
                f"LISP session to this control plane rests on a path that is "
                f"already failing:\n\n{detail}", data=data)

        if big is not None and big <= 70:
            return CheckResult(
                CheckStatus.WARN,
                f"The path from {t.xtr_hostname} to {self.map_server} carries "
                f"small packets but drops {minimum}-byte ones, so LISP control "
                f"traffic will fail as soon as a message is large — a session "
                f"that looks healthy can still lose registrations:\n\n{detail}",
                data=data)

        return CheckResult(
            CheckStatus.OK,
            f"{t.xtr_hostname} reaches {self.map_server} from its RLOC at "
            f"both small and full packet size:\n\n{detail}", data=data)


class LispMapServerSelfSession(_SessionCheck):
    """The control plane's own LISP session to the map-server address.

    Independent of the switch's session state. Every check before this asks
    the ETR what it sees; this asks the control plane. A map-server whose own
    session is not Up cannot distribute what it is registered, so the switch
    can hold a healthy session to a CP that is itself cut off from the site.
    """

    def __init__(self, target, map_server, cp_hostname=None, cp_mgmt=None):
        self.target = target
        self.map_server = map_server
        self.cp_hostname = cp_hostname or map_server
        self.cp_mgmt = cp_mgmt or self.cp_hostname
        self.name = f"Map-Server Self Session — {self.cp_hostname}"
        self.running_note = "Reading the control plane's own LISP session."
        self.target_node_id = target.node_for(self.cp_hostname)

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        data = {"cp": self.cp_hostname, "map_server": self.map_server}
        try:
            cp = _cp_device(ctx, self.cp_hostname, t.catc_name, self.cp_mgmt)
            from routingmodules.lisp import LISPSession
            sess = LISPSession(cp.profiled_device.hostname)
            sess.specificlispsession(self.map_server, ctx.service)
            state = str(getattr(sess, "session_state", "") or "unknown")
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading the session on {self.cp_hostname} stopped:\n\n{e}",
                data=data)
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the session on {self.cp_hostname} "
                f"({type(e).__name__}: {e}).", data=data)

        data["state"] = state
        if state.lower() != "up":
            return CheckResult(
                CheckStatus.WARN,
                f"{self.cp_hostname}'s own LISP session to {self.map_server} "
                f"is {state}. The switch may hold a healthy session to this "
                f"control plane while the control plane itself cannot "
                f"exchange registrations with the site.",
                data=data)

        return CheckResult(
            CheckStatus.OK,
            f"{self.cp_hostname}'s own LISP session to {self.map_server} is "
            f"Up.", data=data)


def _int0(v):
    """int(v) with 0 for anything unparseable -- counters arrive as str or None."""
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _igp_interfaces(ctx, host, peer_ip):
    """Underlay interfaces on `host` facing `peer_ip`, via the IGP.

    Shared by the ACL and CTS checks: both ask "what is applied on the
    interfaces this session actually traverses", and neither can answer
    without recursing the route first.
    """
    from routingmodules.iprouting import IPRoute, IGPInfo
    route = IPRoute(peer_ip, None, host)
    route.iproute_prefix(ctx.service, 0)
    protocol = str(getattr(route, "protocol", "") or "")
    if "onnected" in protocol:
        return []
    phys = IGPInfo(host)
    phys.igp_neighbors(protocol, ctx.service)
    return list(getattr(phys, "neighbor_interfaces", None) or [])


class LispSessionAccessLists(_SessionCheck):
    """ACLs on the underlay path that could block the LISP session.

    LISP control traffic is TCP/4342 and UDP/4342, both directions. The
    registration rides TCP while map-requests and map-replies ride UDP, so
    an ACL permitting only one of them breaks the session in a way the LISP
    state itself never explains -- all four combinations are evaluated.

    The interfaces come from CEF rather than the IGP: CEF is what the
    forwarding plane actually consults, so it names the port the traffic
    leaves through even where the IGP offers several or the route was not
    learned from a neighbor at all.
    """

    def __init__(self, target, map_server, cp_hostname=None, on_cp=False,
                 cp_mgmt=None):
        self.target = target
        self.map_server = map_server
        self.cp_hostname = cp_hostname or map_server
        self.cp_mgmt = cp_mgmt or self.cp_hostname
        # False: switch -> map-server. True: the reverse, run on the CP.
        self.on_cp = on_cp
        # Named by device, not by role: "switch" read as a different subject
        # rather than the same check run from the other end, and the xTR is
        # not always an edge -- the controller runs this flow too.
        side = self.cp_hostname if on_cp else (target.xtr_hostname or "switch")
        self.name = f"Session ACLs ({side}) — {self.cp_hostname}"
        self.running_note = "Evaluating ACLs on the underlay path."
        self.target_node_id = target.node_for(self.cp_hostname)

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        data = {"cp": self.cp_hostname, "map_server": self.map_server}
        try:
            etr = _profile_xtr(ctx, t)
            etr_rloc = t.rloc(ctx, etr)
            if self.on_cp:
                cp = _cp_device(ctx, self.cp_hostname, t.catc_name,
                                self.cp_mgmt)
                host = cp.profiled_device.hostname
                src, dst = self.map_server, etr_rloc
            else:
                host = etr.profiled_device.hostname
                src, dst = etr_rloc, self.map_server
            if not src or not dst:
                return CheckResult(
                    CheckStatus.WARN,
                    "The RLOCs at both ends could not be resolved, so the "
                    "ACLs on the path cannot be evaluated.", data=data)

            interfaces = _cef_interfaces(ctx, host, dst)
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading the ACLs on {self.cp_hostname} stopped:\n\n{e}",
                data=data)
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the ACLs on the path "
                f"({type(e).__name__}: {e}).", data=data)

        flows = []
        for proto in ("tcp", "udp"):
            flows.append({"label": f"{src} → {dst} {proto.upper()}/4342",
                          "sourceip": src, "destinationip": dst,
                          "protocol": proto, "srcport": 4342,
                          "dstport": 4342})
            flows.append({"label": f"{dst} → {src} {proto.upper()}/4342",
                          "sourceip": dst, "destinationip": src,
                          "protocol": proto, "srcport": 4342,
                          "dstport": 4342})

        try:
            names, denies, permits, unevaluated = _evaluate_acls(
                ctx, host, interfaces, flows)
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the ACLs on the path "
                f"({type(e).__name__}: {e}).", data=data)

        data.update({"interfaces": interfaces, "acls": names,
                     "denies": denies, "unevaluated": unevaluated})

        # `denies`, `permits` and `unevaluated` are tuples -- (flow, detail)
        # pairs and (acl, flows, reason) triples -- which the shared renderer
        # lays out. Interpolating them directly printed the Python repr.
        path = ", ".join(interfaces)
        header = (f"{src} → {dst}, LISP control (TCP/4342 and UDP/4342), "
                  f"on {host}")

        # A deny outranks an unreadable ACL: it is the actionable finding.
        if denies:
            return CheckResult(
                CheckStatus.WARN,
                "An ACL on the underlay path is blocking the LISP session:"
                "\n\n" + render_acl_section(
                    header, path, blocked=denies, permitted=permits,
                    unread=unevaluated),
                data=data)

        # An ACL that could not be parsed is applied to the path whether or
        # not we can read it, so reporting the path clear on the strength of
        # it would be a guess.
        if unevaluated:
            return CheckResult(
                CheckStatus.WARN,
                "The ACLs on the underlay path could not be fully evaluated:"
                "\n\n" + render_acl_section(
                    header, path, blocked=denies, permitted=permits,
                    unread=unevaluated),
                data=data)

        if not names:
            return CheckResult(
                CheckStatus.OK,
                f"No ACL is applied on the underlay interfaces between "
                f"{src} and {dst} (via {path}), so nothing there can block "
                f"the session.", data=data)

        return CheckResult(
            CheckStatus.OK,
            "No ACL on the underlay path blocks the LISP session:\n\n"
            + render_acl_section(header, path, blocked=denies,
                                 permitted=permits, unread=unevaluated),
            data=data)


class LispSessionTrustSec(_SessionCheck):
    """CTS/SGT policy between the two RLOCs of the LISP session.

    A TrustSec rule that denies the SGT pair drops the session's TCP/4342
    without any ACL being involved, so the SGT of each RLOC is resolved and
    the rule that governs the pair is evaluated - including every RBACL it
    carries, in both directions, and its drop counters.
    """

    def __init__(self, target, map_server, cp_hostname=None, on_cp=False,
                 cp_mgmt=None):
        self.target = target
        self.map_server = map_server
        self.cp_hostname = cp_hostname or map_server
        self.cp_mgmt = cp_mgmt or self.cp_hostname
        self.on_cp = on_cp
        # Named by device, not by role: "switch" read as a different subject
        # rather than the same check run from the other end, and the xTR is
        # not always an edge -- the controller runs this flow too.
        side = self.cp_hostname if on_cp else (target.xtr_hostname or "switch")
        self.name = f"Session TrustSec ({side}) — {self.cp_hostname}"
        self.running_note = "Evaluating the CTS policy for the session."
        self.target_node_id = target.node_for(self.cp_hostname)

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        data = {"cp": self.cp_hostname, "map_server": self.map_server}
        try:
            etr = _profile_xtr(ctx, t)
            etr_rloc = t.rloc(ctx, etr)
            if self.on_cp:
                cp = _cp_device(ctx, self.cp_hostname, t.catc_name,
                                self.cp_mgmt)
                host = cp.profiled_device.hostname
                src, dst = self.map_server, etr_rloc
            else:
                host = etr.profiled_device.hostname
                src, dst = etr_rloc, self.map_server
            if not src or not dst:
                return CheckResult(
                    CheckStatus.WARN,
                    "The RLOCs at both ends could not be resolved, so the "
                    "CTS policy for the session cannot be evaluated.",
                    data=data)

            from securitymodules.ciscotrustsec import (
                cts_endpoint_info, cts_rules)
            # A policy only matters where enforcement is actually on. Check
            # the underlay interfaces the session traverses first: VLAN SVIs
            # need per-VLAN plus global enforcement, physical L3 ports need
            # the port enabled plus global. Port-channels are not supported
            # for SGACL enforcement, so they are skipped.
            enforcing = []
            for intf in _igp_interfaces(ctx, host, dst):
                info = cts_endpoint_info(None, None, host)
                if intf.startswith("Vlan"):
                    try:
                        vlan_id = int(intf[4:])
                    except ValueError:
                        continue
                    info.cts_enforcement(vlan_id, None, ctx.service)
                    on = (getattr(info, "vlanenforcement", False) is True
                          and getattr(info, "globalenforcement", False) is True
                          and getattr(info, "enforcingvlan", False) is True)
                elif "hannel" in intf:
                    continue
                else:
                    info.cts_enforcement(None, intf, ctx.service)
                    on = (getattr(info, "ctsportenabled", False) is True
                          and getattr(info, "globalenforcement", False) is True)
                if on:
                    enforcing.append(intf)
            data["enforcing_interfaces"] = enforcing
            if not enforcing:
                return CheckResult(
                    CheckStatus.OK,
                    f"No underlay interface on {host} towards {dst} has CTS "
                    f"enforcement enabled, so no TrustSec policy is applied "
                    f"to the session.", data=data)

            srcinfo = cts_endpoint_info(src, None, host)
            srcinfo.cts_sgt_mapping(ctx.service)
            dstinfo = cts_endpoint_info(dst, None, host)
            dstinfo.cts_sgt_mapping(ctx.service)
            sgt = getattr(srcinfo, "sgt", None)
            dgt = getattr(dstinfo, "sgt", None)
            data.update({"sgt": sgt, "dgt": dgt})

            rules = cts_rules(host)
            rules.cts_rbac_permissions(sgt, dgt, ctx.service)
            rbacl = getattr(rules, "rbacl", None)
            default = bool(getattr(rules, "isdefaultrule", False))
            rules.cts_rbac_rbacls(rbacl, ctx.service)
            # The default rule is not counted per SGT pair: its counters live
            # at 0,0. Asking for the pair there returns nothing.
            if default:
                rules.cts_rbac_counters(0, 0, ctx.service)
            else:
                rules.cts_rbac_counters(sgt, dgt, ctx.service)
        except SystemExit as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Reading the CTS policy on {self.cp_hostname} stopped:"
                f"\n\n{e}", data=data)
        except BaseException as e:
            return CheckResult(
                CheckStatus.FAIL,
                f"Could not read the CTS policy on {host} "
                f"({type(e).__name__}: {e}).", data=data)

        if sgt is None or dgt is None:
            return CheckResult(
                CheckStatus.OK,
                f"{host} has no SGT binding for {src} or {dst}, so no "
                f"TrustSec policy applies to the session.", data=data)

        data["rbacl"] = rbacl
        data["is_default_rule"] = default
        kind = ("the default rule" if default
                else f"a specific rule for SGT {sgt} → SGT {dgt}")
        lines = [f"• Policy: {kind}, RBACL {rbacl}"]

        # Evaluate each RBACL both ways. Ephemeral source port on the
        # initiating side, 4342 on the listening side.
        acls = getattr(rules, "rbacl", None) or []
        if isinstance(acls, str):
            acls = [acls]
        forward = {"sourceip": src, "destinationip": dst, "protocol": "tcp",
                   "srcport": 65535, "dstport": 4342}
        reverse = {"sourceip": dst, "destinationip": src, "protocol": "tcp",
                   "srcport": 4342, "dstport": 65535}
        denies = []
        from securitymodules.accesslists import acl_evaluation
        for acl in acls:
            for label, ev in ((f"{src} → {dst}", forward),
                              (f"{dst} → {src}", reverse)):
                try:
                    hit = acl_evaluation(ctx.service, host, acl, True, ev)
                except BaseException:
                    continue
                if not hit or len(hit) < 3:
                    continue
                if hit[1] == "deny":
                    denies.append(
                        f"{acl} denies {label} at sequence {hit[2]}")
                elif hit[1] == "permit":
                    lines.append(
                        f"• {acl} permits {label} (sequence {hit[2]})")

        hw = _int0(getattr(rules, "hw_denied_count", 0))
        sw = _int0(getattr(rules, "sw_denied_count", 0))
        data.update({"denies": denies, "hw_denied": hw, "sw_denied": sw})

        if denies:
            return CheckResult(
                CheckStatus.WARN,
                f"The TrustSec policy on {host} is blocking the LISP "
                f"session (TCP/4342):\n\n"
                + "\n".join(f"• {d}" for d in denies), data=data)

        if hw or sw:
            return CheckResult(
                CheckStatus.WARN,
                f"Nothing in the TrustSec policy on {host} denies the "
                f"session, but the rule for SGT {sgt} → SGT {dgt} is "
                f"counting drops ({hw} in hardware, {sw} in software), so "
                f"some traffic between these groups is being dropped:\n\n"
                + "\n".join(lines), data=data)

        return CheckResult(
            CheckStatus.OK,
            f"The TrustSec policy on {host} permits the session between "
            f"{src} and {dst}, with no drops counted:\n\n"
            + "\n".join(lines), data=data)


class LispSessionVerdict(_SessionCheck):
    """What the session flow established, once every map-server has been walked.

    The per-map-server checks each report their own session and continue, so
    that the checks explaining *why* a session is down still run. That is
    right for each one individually, and leaves nobody looking at the whole:
    a flow where every session is still down has said everything it can say,
    and the checks below it would each report an absence caused by this.

    So this is where the flow stops -- at the end, after the troubleshooting,
    rather than at the first down session.
    """

    name = "LISP Session — Verdict"
    running_note = "Weighing up the session flow."

    def __init__(self, target, map_servers=None):
        super().__init__(target)
        self.map_servers = list(map_servers or [])

    def run_session(self, ctx: RunContext) -> CheckResult:
        t = self.target
        self.target_node_id = t.xtr_node_id
        states = ctx.state.get(t.key("lisp_session_states")) or {}
        if not states:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — no map-server session was read, so there is "
                "nothing to weigh up.")

        # The verdict is about the switch, not about the subset of control
        # planes this run happened to walk. A caller triggered by ONE down
        # session passes only that control plane, so judging on the walked
        # subset alone would read a single down peer as "every session is
        # down" and stop a flow whose registrations are still leaving through
        # the peers that are up. Read the full peer set -- the same reader
        # LispGlobalSession reports from, so the two cannot contradict each
        # other -- and fall back to the walked subset only when the switch
        # cannot be re-read.
        peer_states = dict(states)
        try:
            etr = _profile_xtr(ctx, t)
            etr.global_lisp_session(ctx.service)
            all_up, all_down = peer_session_states(etr)
        except BaseException:
            pass
        else:
            peer_states = {peer: state for peer, state in all_up + all_down}
            # A map-server that was walked but is not among the peers still
            # counts: its absence from the session table is not evidence it
            # is up.
            for ms, state in states.items():
                peer_states.setdefault(ms, state)

        up = [ms for ms, state in peer_states.items()
              if (state or "").strip().lower() == "up"]
        down = [(ms, state) for ms, state in peer_states.items()
                if (state or "").strip().lower() != "up"]

        if not up:
            listed = ", ".join(f"{ms} ({state})" for ms, state in down)
            return self._stop(
                ctx,
                f"every LISP session from {t.xtr_hostname} is still down "
                f"after the session flow",
                f"Every LISP session from {t.xtr_hostname} is still down "
                f"after troubleshooting each one — {listed}.\n\n"
                f"The flow has established what it can: no registration for "
                f"{t.label} can leave {t.xtr_hostname} while this holds, so "
                f"every check below would report an absence that this one "
                f"fault already explains. The session state is what to fix.",
                data={"lisp_sessions_down": down},
            )

        if down:
            listed = ", ".join(f"{ms} ({state})" for ms, state in down)
            return CheckResult(
                CheckStatus.WARN,
                f"{len(up)} of {len(peer_states)} LISP session(s) from "
                f"{t.xtr_hostname} came back up; still down: {listed}.\n\n"
                f"{t.label} can register through the session(s) that are up, "
                f"so the flow continues — but a control plane whose session "
                f"is down holds no record of it.",
                data={"lisp_sessions_up": up, "lisp_sessions_down": down})

        return CheckResult(
            CheckStatus.OK,
            f"Every LISP session from {t.xtr_hostname} is up "
            f"({', '.join(up)}), so the registration path for {t.label} is "
            f"not the fault.",
            data={"lisp_sessions_up": up})
