"""Standalone underlay-multicast validation chain.

Scenario-agnostic. Each check reads from a small ``ctx.state`` namespace and
SKIPs cleanly when its prerequisites aren't set, so the chain can be queued
dynamically (today: from ``EwRemoteMapCache`` when the L2VNI is in Flooding
mode) or invoked from any other entry point later.

The chain is **side-aware**: instantiate with ``side="fhr"`` (default) for the
source/first-hop XTR or ``side="lhr"`` for the destination/last-hop XTR. Each
side reads/writes its own state keys so the two chains can be queued together
without colliding.

State contract (FHR side — defaults):
    umcast_source_hostname  (required)  FHR device hostname.
    umcast_l2vni_iid        (required)  L2VNI instance ID being investigated.
    umcast_vlan             (required for L2LISP-interface check)
    umcast_broadcast_group              broadcast-underlay group IP; auto-filled
                                        by UmcastBroadcastGroup if not set.
    umcast_vrf                          underlay VRF (None = global).
    umcast_node_id                      topology node id (default "xtr").
    umcast_catc_name                    Catalyst Center name (passthrough).
    umcast_existing_device              previously-profiled `Device` to reuse.
    umcast_device                       populated by UmcastDeviceProfile.
    umcast_rp                           populated by UmcastRpIdentification.

State contract (LHR side): same shape, prefix is ``umcast_dst_``
(``umcast_dst_hostname``, ``umcast_dst_l2vni_iid``, …, default node "dxtr").
"""

from checks import Check, CheckResult, CheckStatus, RunContext


# ---------------------------------------------------------------------------
# Side machinery
# ---------------------------------------------------------------------------

_KEYS_FHR = {
    "hostname":   "umcast_source_hostname",
    "iid":        "umcast_l2vni_iid",
    "vlan":       "umcast_vlan",
    "group":      "umcast_broadcast_group",
    "vrf":        "umcast_vrf",
    "node_id":    "umcast_node_id",
    "catc":       "umcast_catc_name",
    "existing":   "umcast_existing_device",
    "device":     "umcast_device",
    "rp":         "umcast_rp",
}

_KEYS_LHR = {
    "hostname":   "umcast_dst_hostname",
    "iid":        "umcast_dst_l2vni_iid",
    "vlan":       "umcast_dst_vlan",
    "group":      "umcast_dst_broadcast_group",
    "vrf":        "umcast_dst_vrf",
    "node_id":    "umcast_dst_node_id",
    "catc":       "umcast_dst_catc_name",
    "existing":   "umcast_dst_existing_device",
    "device":     "umcast_dst_device",
    "rp":         "umcast_dst_rp",
}

_DEFAULT_NODE = {"fhr": "xtr", "lhr": "dxtr"}
_SIDE_LABEL   = {"fhr": "FHR",  "lhr": "LHR"}


def _keys_for(side: str) -> dict:
    return _KEYS_LHR if side == "lhr" else _KEYS_FHR


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _node_id(ctx: RunContext, side: str) -> str:
    return ctx.state.get(_keys_for(side)["node_id"]) or _DEFAULT_NODE.get(side, "xtr")


def _need(ctx: RunContext, *keys: str):
    """Return a SKIP CheckResult if any required state key is missing/falsy."""
    missing = [k for k in keys if ctx.state.get(k) in (None, "", [])]
    if missing:
        return CheckResult(
            CheckStatus.SKIP,
            "Skipped: required state not set ({}).".format(", ".join(missing)),
        )
    return None


def _wrap_fail(name: str, exc: BaseException) -> CheckResult:
    """Convert a legacy `sys.exit`/exception into a structured FAIL."""
    msg = str(exc) if str(exc) else exc.__class__.__name__
    return CheckResult(CheckStatus.FAIL, f"{name} raised {exc.__class__.__name__}: {msg}")


def _umcast_device(ctx: RunContext, side: str):
    """Return the cached UnderlayMulticastDevice from ctx.state or None."""
    return ctx.state.get(_keys_for(side)["device"])


def _disabled_flag(side: str) -> str:
    return f"umcast_{side}_skip_downstream"


def _mark_disabled(ctx: RunContext, side: str, reason: str) -> None:
    ctx.state[_disabled_flag(side)] = reason


def _skip_if_disabled(ctx: RunContext, side: str):
    """Return a SKIP CheckResult if this side has been gated off, else None."""
    reason = ctx.state.get(_disabled_flag(side))
    if reason:
        return CheckResult(
            CheckStatus.SKIP,
            f"Skipped — underlay multicast not validated on this side: {reason}",
        )
    return None


class _UmcastBase(Check):
    """Base for side-aware underlay-multicast checks.

    Subclasses set ``base_name`` (e.g. "profile device"); the instance ``name``
    is composed at __init__ time as ``"Underlay Mcast (<SIDE>): <base_name>"``.
    """

    base_name = "check"

    def __init__(self, side: str = "fhr"):
        self.side = side if side in ("fhr", "lhr") else "fhr"
        self._keys = _keys_for(self.side)
        self.name = f"Underlay Mcast ({_SIDE_LABEL[self.side]}): {self.base_name}"
        self.target_node_id = _DEFAULT_NODE[self.side]


def build_underlay_multicast_chain(side: str = "fhr") -> list:
    """Return the ordered list of multicast checks for the given side."""
    from checks.underlay_multicast_gates import build_pim_gates_for_side
    return [
        UmcastDeviceProfile(side),
        *build_pim_gates_for_side(side),
        UmcastGlobalEnablement(side),
        UmcastLoopbackPim(side),
        UmcastPimNeighbors(side),
        UmcastL2LispInterface(side),
        UmcastBroadcastGroup(side),
        UmcastSsmRange(side),
        UmcastMcastRange(side),
        UmcastRpIdentification(side),
        UmcastRpfToRp(side),
        UmcastPimStatistics(side),
        UmcastIgmpVerifications(side),
        UmcastLocalStarG(side),
        UmcastFloodingAcls(side),
    ]


# ---------------------------------------------------------------------------
# Checks 1-7: profile, global mcast, Lo0 PIM, neighbors, L2LISP intf,
# broadcast group, SSM
# ---------------------------------------------------------------------------

class UmcastDeviceProfile(_UmcastBase):
    """Profile the XTR (or reuse one from outer scenario state)."""

    base_name = "profile device"

    def run(self, ctx: RunContext) -> CheckResult:
        K = self._keys
        self.target_node_id = _node_id(ctx, self.side)
        miss = _need(ctx, K["hostname"])
        if miss: return miss
        try:
            from traffic_flows.underlay_multicast import UnderlayMulticastDevice
            umd = UnderlayMulticastDevice(
                ctx.state.get(K["vrf"]),
                ctx.state[K["hostname"]],
                0,
            )
            existing = ctx.state.get(K["existing"])
            if existing is not None and getattr(existing, "hostname", None):
                umd.existing_profiled(existing)
            else:
                umd.device_profiler(ctx.state.get(K["catc"]), ctx.service)
        except BaseException as e:
            _mark_disabled(
                ctx, self.side,
                f"device profiling failed ({e.__class__.__name__})"
            )
            return _wrap_fail(self.name, e)
        ctx.state[K["device"]] = umd
        host = getattr(umd.profiled_device, "hostname", "?")
        lo0 = getattr(umd.profiled_device, "loopback", None)
        body = (
            f"• Device hostname: {host}\n"
            f"• Loopback0: {lo0}\n"
            f"• Underlay VRF: {ctx.state.get(K['vrf']) or '(global)'}"
        )
        return CheckResult(CheckStatus.OK, body)


class UmcastGlobalEnablement(_UmcastBase):
    """Verify global multicast routing is enabled on the device."""

    base_name = "global enablement"

    def run(self, ctx: RunContext) -> CheckResult:
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        try:
            umd.multicast_enablement(ctx.service)
        except BaseException as e:
            _mark_disabled(ctx, self.side, "multicast_enablement raised")
            return _wrap_fail(self.name, e)
        cfg = getattr(umd, "mcastconfig", None)
        enabled = bool(getattr(cfg, "multicastenabled", False)) if cfg else False
        host = umd.profiled_device.hostname
        if not enabled:
            _mark_disabled(ctx, self.side, "global multicast routing disabled")
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n• Global multicast routing: DISABLED\n"
                f"• Configure 'ip multicast-routing' (and per-VRF as needed).\n"
                f"• Downstream underlay-multicast checks on this side will SKIP.",
            )
        body = (
            f"• Device: {host}\n"
            f"• Global multicast routing: enabled\n"
            f"• Multipath: {getattr(cfg, 'multipath', '?')}\n"
            f"• Fallback group mode: {getattr(cfg, 'fallbackmode', '?')}"
        )
        return CheckResult(CheckStatus.OK, body)


class UmcastLoopbackPim(_UmcastBase):
    """Verify Loopback0 is PIM-enabled (required for register source)."""

    base_name = "Loopback0 PIM"

    def run(self, ctx: RunContext) -> CheckResult:
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        try:
            umd.pim_interfaces(ctx.service)
            intf_list = getattr(umd.piminterfaces, "piminterfaces", []) or []
            umd.anypiminterface("Loopback0", intf_list)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        ok = bool(getattr(umd, "isinterfacepimenabled", False))
        host = umd.profiled_device.hostname
        lo0 = next((i for i in intf_list if i.get("interface_name") == "Loopback0"), None)
        if not ok:
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n• Loopback0 PIM: NOT enabled\n"
                f"• Configure 'ip pim sparse-mode' under interface Loopback0.",
            )
        body = (
            f"• Device: {host}\n"
            f"• Loopback0 PIM: enabled\n"
            f"• Mode: {lo0.get('pim_mode') if lo0 else '?'}\n"
            f"• PIM status: {lo0.get('pim_status') if lo0 else '?'}\n"
            f"• Total PIM interfaces: {len(intf_list)}"
        )
        return CheckResult(CheckStatus.OK, body)


class UmcastPimNeighbors(_UmcastBase):
    """Verify the device has at least one PIM neighbor."""

    base_name = "PIM neighbors"

    def run(self, ctx: RunContext) -> CheckResult:
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        try:
            umd.pim_neighbors(ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        nbrs = getattr(umd.pimneighbors, "pimneighbors", []) or []
        count = getattr(umd.pimneighbors, "neighborcount", 0) or 0
        host = umd.profiled_device.hostname
        if count == 0:
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n• PIM neighbors: 0\n"
                f"• No PIM adjacencies — verify PIM config on underlay-facing interfaces.",
            )
        lines = [f"• Device: {host}", f"• PIM neighbor count: {count}"]
        for n in nbrs[:8]:
            lines.append(
                f"  - {n.get('neighbor_ip')} on {n.get('interface')} (uptime {n.get('up_time')})"
            )
        if count > 8:
            lines.append(f"  …and {count - 8} more")
        return CheckResult(CheckStatus.OK, "\n".join(lines))


class UmcastL2LispInterface(_UmcastBase):
    """Validate the L2LISP interface state (parent + sub-interface) for the VLAN."""

    base_name = "L2LISP interface"

    def run(self, ctx: RunContext) -> CheckResult:
        K = self._keys
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        miss = _need(ctx, K["vlan"])
        if miss: return miss
        try:
            umd.l2lispinterface(ctx.state[K["vlan"]], ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        st = getattr(umd, "l2lispinterfacestatus", None)
        host = umd.profiled_device.hostname
        final = getattr(st, "l2lispfinalinterface", None) if st else None
        body = (
            f"• Device: {host}\n"
            f"• VLAN: {ctx.state[K['vlan']]}\n"
            f"• Final L2LISP interface: {final}\n"
        )
        if final is None:
            return CheckResult(
                CheckStatus.WARN,
                body + "• Could not resolve the L2LISP interface; downstream IGMP / *,G "
                "checks will SKIP.",
            )
        return CheckResult(CheckStatus.OK, body.rstrip())


class UmcastBroadcastGroup(_UmcastBase):
    """Confirm broadcast-underlay (multicast group) is configured for the L2VNI."""

    base_name = "broadcast-underlay group"

    def run(self, ctx: RunContext) -> CheckResult:
        K = self._keys
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        miss = _need(ctx, K["iid"])
        if miss: return miss
        try:
            umd.broadcast_underlay_properties(ctx.state[K["iid"]], ctx.service)
        except BaseException as e:
            _mark_disabled(ctx, self.side, "broadcast-underlay properties unreadable")
            return _wrap_fail(self.name, e)
        props = getattr(umd, "l2floodingproperties", None)
        bcast = getattr(props, "broadcastunderlay", None) if props else None
        host = umd.profiled_device.hostname
        if bcast is None:
            _mark_disabled(ctx, self.side, "broadcast-underlay group not configured")
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n"
                f"• L2VNI IID: {ctx.state[K['iid']]}\n"
                f"• broadcast-underlay group: NOT configured\n"
                f"• Without a broadcast-underlay group, ARP flooding cannot use multicast.\n"
                f"• Downstream underlay-multicast checks on this side will SKIP.",
            )
        ctx.state[K["group"]] = bcast
        body = (
            f"• Device: {host}\n"
            f"• L2VNI IID: {ctx.state[K['iid']]}\n"
            f"• broadcast-underlay group: {bcast}\n"
            f"• flood arp-nd: {bool(getattr(props, 'floodarpnd', False))}\n"
            f"• flood unknown-unicast: {bool(getattr(props, 'floodunknownunicast', False))}"
        )
        return CheckResult(CheckStatus.OK, body)


class UmcastSsmRange(_UmcastBase):
    """Confirm the broadcast group is NOT inside the SSM range (must be ASM)."""

    base_name = "SSM range"

    def run(self, ctx: RunContext) -> CheckResult:
        K = self._keys
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        miss = _need(ctx, K["group"])
        if miss: return miss
        try:
            umd.ssm_underlay_group(ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        ssm = getattr(umd, "ssminformation", None)
        is_ssm = bool(getattr(umd, "isssmgroup", False))
        host = umd.profiled_device.hostname
        bcast = ctx.state[K["group"]]
        ssm_enabled = bool(getattr(ssm, "ssmenabled", False)) if ssm else False
        ssm_range = getattr(ssm, "ssmrange", None) if ssm else None
        ssm_acl = getattr(ssm, "ssmacl", None) if ssm else None
        body = (
            f"• Device: {host}\n"
            f"• broadcast-underlay group: {bcast}\n"
            f"• SSM enabled: {ssm_enabled}\n"
            f"• SSM range: {ssm_range or '(default 232.0.0.0/8)'}\n"
            f"• SSM ACL: {ssm_acl or '(none)'}\n"
            f"• Broadcast group inside SSM range: {is_ssm}"
        )
        if is_ssm:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• broadcast-underlay must be ASM — narrow the SSM range so it "
                "does not cover this group.",
            )
        if not ssm_enabled:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n• SSM not enabled — recommend 'ip pim ssm default'.",
            )
        return CheckResult(CheckStatus.OK, body)


# ---------------------------------------------------------------------------
# Checks 8-14: mcast range ACL, RP, RPF, PIM stats, IGMP, *,G, flooding ACLs
# ---------------------------------------------------------------------------

class UmcastMcastRange(_UmcastBase):
    """Confirm `ip multicast group-range` ACL doesn't deny the broadcast group."""

    base_name = "multicast group-range"

    def run(self, ctx: RunContext) -> CheckResult:
        K = self._keys
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        miss = _need(ctx, K["group"])
        if miss: return miss
        try:
            umd.multicast_range(ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        host = umd.profiled_device.hostname
        bcast = ctx.state[K["group"]]
        configured = bool(getattr(umd, "mcastrangestatus", False))
        blocked = bool(getattr(umd, "isblockedbymcastrange", False))
        acl = getattr(getattr(umd, "mcastrangeinfo", None), "mcastrangeacl", None)
        body = (
            f"• Device: {host}\n"
            f"• broadcast-underlay group: {bcast}\n"
            f"• 'ip multicast group-range' configured: {configured}\n"
            f"• ACL: {acl or '(none)'}"
        )
        if blocked:
            return CheckResult(
                CheckStatus.FAIL,
                body + f"\n• ACL DENIES the broadcast group {bcast} — multicast routing "
                "for this group is suppressed.",
            )
        return CheckResult(CheckStatus.OK, body)


class UmcastRpIdentification(_UmcastBase):
    """Identify the RP for the broadcast group; check reachability and tunnel state."""

    base_name = "RP identification"

    def run(self, ctx: RunContext) -> CheckResult:
        K = self._keys
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        miss = _need(ctx, K["group"])
        if miss: return miss
        try:
            umd.rp_identification(ctx.state[K["group"]], ctx.service)
        except KeyError as e:
            # Legacy path indexes into `pimrp_op['vrf'][...]['rp']['static_rp']`
            # without first checking whether the device has any static RP
            # configured. Treat that as "no RP" rather than a hard fail and
            # gate the rest of the side off.
            _mark_disabled(ctx, self.side, "no RP configured / mapping unavailable")
            host = getattr(getattr(umd, "profiled_device", None), "hostname", "?")
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n"
                f"• Group: {ctx.state[K['group']]}\n"
                f"• RP: NOT FOUND (no static RP / no rp-mapping for this group, "
                f"missing key: {e}).\n"
                f"• Configure a static RP (or BSR/Auto-RP) covering this group.\n"
                f"• Downstream RP / *,G / IGMP / flooding-ACL checks will SKIP.",
            )
        except BaseException as e:
            _mark_disabled(ctx, self.side, "RP identification raised")
            return _wrap_fail(self.name, e)
        rpinfo = getattr(umd, "rpinformation", None)
        rp = getattr(rpinfo, "rp", None) if rpinfo else None
        host = umd.profiled_device.hostname
        bcast = ctx.state[K["group"]]
        if rp is None:
            _mark_disabled(ctx, self.side, "no RP found for broadcast group")
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n"
                f"• Group: {bcast}\n"
                f"• RP: NOT FOUND\n"
                f"• Configure a static RP (or BSR/Auto-RP) covering this group.\n"
                f"• Downstream RP / *,G / IGMP / flooding-ACL checks will SKIP.",
            )
        ctx.state[K["rp"]] = rp
        ping = getattr(rpinfo, "pingstatus", None)
        ping_pct = getattr(ping, "result", None) if ping else None
        tunnels = getattr(rpinfo, "pimtunnels", []) or []
        main_tun = getattr(rpinfo, "maintunnel", None)
        is_local = getattr(rpinfo, "isrplocal", None)
        tun_state = None
        tun_source = None
        for t in tunnels:
            if t.get("tunnel_interface") == main_tun:
                tun_state = t.get("tunnel_state")
                tun_source = t.get("tunnel_source")
                break
        lo0 = getattr(umd.profiled_device, "loopback", None)
        body_lines = [
            f"• Device: {host}",
            f"• Group: {bcast}",
            f"• RP: {rp}" + (" (local)" if is_local else ""),
            f"• Reachability (ping): {ping_pct}%" if ping_pct is not None else "• Reachability: unknown",
            f"• PIM register tunnel: {main_tun} state={tun_state} source={tun_source}",
        ]
        warns = []
        try:
            if ping_pct is not None and int(ping_pct) <= 70:
                warns.append(f"• Reachability ≤70% — PIM register to RP {rp} may fail.")
        except (TypeError, ValueError):
            pass
        if tun_source and lo0 and tun_source != lo0:
            warns.append(
                f"• Register-source ({tun_source}) is not Loopback0 ({lo0}) — recommend "
                f"'ip pim register-source Loopback0'."
            )
        if tun_state and str(tun_state).lower() != "up":
            warns.append(f"• PIM register tunnel state is {tun_state} (not UP).")
        body = "\n".join(body_lines + warns)
        return CheckResult(
            CheckStatus.WARN if warns else CheckStatus.OK,
            body,
        )


class UmcastRpfToRp(_UmcastBase):
    """Report RPF neighbor / interface for reaching the RP."""

    base_name = "RPF to RP"

    def run(self, ctx: RunContext) -> CheckResult:
        K = self._keys
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        rp = ctx.state.get(K["rp"])
        if umd is None or rp is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device or RP not available.")
        try:
            umd.rpf_to_rp(rp, ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        rpf = getattr(umd, "rpfinformation", None)
        host = umd.profiled_device.hostname
        body = (
            f"• Device: {host}\n"
            f"• RP: {rp}\n"
            f"• RPF neighbor: {getattr(rpf, 'rpfneighbor', '?')}\n"
            f"• RPF interface: {getattr(rpf, 'rpfinterface', '?')}"
        )
        return CheckResult(CheckStatus.OK, body)


class UmcastPimStatistics(_UmcastBase):
    """Collect global PIM statistics; warn on errors / drops."""

    base_name = "PIM statistics"

    def run(self, ctx: RunContext) -> CheckResult:
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        try:
            umd.pim_statistics(ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        st = getattr(umd, "pimstatistics", None)
        host = umd.profiled_device.hostname
        cks = int(getattr(st, "pimchecksum_errors", 0) or 0)
        fmt = int(getattr(st, "pimformat_errors", 0) or 0)
        drp = int(getattr(st, "pimqueuedrops", 0) or 0)
        body = (
            f"• Device: {host}\n"
            f"• PIM checksum errors: {cks}\n"
            f"• PIM format errors: {fmt}\n"
            f"• PIM queue drops: {drp}"
        )
        if cks or fmt or drp:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n• Non-zero counters — verify they aren't increasing via "
                "'show ip traffic'.",
            )
        return CheckResult(CheckStatus.OK, body)


class UmcastIgmpVerifications(_UmcastBase):
    """Report IGMP groups joined on the L2LISP interface."""

    base_name = "IGMP on L2LISP intf"

    def run(self, ctx: RunContext) -> CheckResult:
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        st = getattr(umd, "l2lispinterfacestatus", None)
        intf = getattr(st, "l2lispfinalinterface", None) if st else None
        if not intf:
            return CheckResult(CheckStatus.SKIP, "Skipped: L2LISP interface not resolved.")
        try:
            umd.igmp_verifications(ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        igmp = getattr(umd, "igmpinterfaceinfo", None)
        groups = getattr(igmp, "igmpgroups", None) or getattr(igmp, "groups", None) or []
        host = umd.profiled_device.hostname
        lines = [f"• Device: {host}", f"• Interface: {intf}", f"• IGMP groups: {len(groups)}"]
        for g in groups[:8] if isinstance(groups, list) else []:
            if isinstance(g, dict):
                lines.append(f"  - {g.get('group') or g.get('group_address') or g}")
            else:
                lines.append(f"  - {g}")
        return CheckResult(CheckStatus.OK, "\n".join(lines))


class UmcastLocalStarG(_UmcastBase):
    """Verify a local *,G mroute exists for the broadcast-underlay group."""

    base_name = "local *,G"

    def run(self, ctx: RunContext) -> CheckResult:
        K = self._keys
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        miss = _need(ctx, K["group"])
        if miss: return miss
        try:
            umd.local_star_g(ctx.service)
        except TypeError as e:
            # Legacy iterates over `mrouteinfo` without a None-guard. A None
            # there means the genie parser returned nothing — typically because
            # there's no mroute table on this device for the underlay group.
            host = getattr(getattr(umd, "profiled_device", None), "hostname", "?")
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n"
                f"• Group: {ctx.state[K['group']]}\n"
                f"• *,G mroute: NOT FOUND (mroute table empty for this group, "
                f"underlying error: {e}).\n"
                f"• Without (*,{ctx.state[K['group']]}) the device cannot forward "
                f"flooded ARP traffic.",
            )
        except BaseException as e:
            return _wrap_fail(self.name, e)
        starg = getattr(umd, "stargmroute", None)
        host = umd.profiled_device.hostname
        bcast = ctx.state[K["group"]]
        if not starg:
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n• Group: {bcast}\n• *,G mroute: NOT FOUND\n"
                f"• Without (*,{bcast}) the device cannot forward flooded ARP traffic.",
            )
        body = (
            f"• Device: {host}\n"
            f"• Group: {bcast}\n"
            f"• Source: {starg.get('source')}\n"
            f"• Flags: {starg.get('flags')}\n"
            f"• IIF: {starg.get('incominginterface') or starg.get('iif') or starg.get('incoming_interface')}\n"
            f"• OIL count: {len(starg.get('outgoinginterfacelist') or starg.get('oil') or starg.get('outgoing_interface_list') or [])}"
        )
        return CheckResult(CheckStatus.OK, body)


class UmcastFloodingAcls(_UmcastBase):
    """Inspect L2LISP0 / Tunnel0 ACLs that gate fabric flooding."""

    base_name = "flooding ACLs"

    def run(self, ctx: RunContext) -> CheckResult:
        self.target_node_id = _node_id(ctx, self.side)
        if (skip := _skip_if_disabled(ctx, self.side)): return skip
        umd = _umcast_device(ctx, self.side)
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: device not profiled.")
        host = umd.profiled_device.hostname
        sections = []
        for intf in ("L2LISP0", "Tunnel0"):
            try:
                umd.floodingacls(intf, ctx.service)
            except BaseException as e:
                sections.append(f"• {intf}: error reading ACLs ({e.__class__.__name__})")
                continue
            acls = getattr(umd, "l2floodacls", []) or []
            if not acls:
                sections.append(f"• {intf}: no ACLs applied")
                continue
            for a in acls:
                name = a.get("aclname") if isinstance(a, dict) else None
                aces = (a.get("aces") if isinstance(a, dict) else None) or []
                sections.append(f"• {intf} → ACL {name} ({len(aces)} ACEs)")
        body = f"• Device: {host}\n" + "\n".join(sections)
        return CheckResult(CheckStatus.OK, body)
