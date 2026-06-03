"""Stage 5a: register / join state and active S,G traversal.

Runs after the FHR + LHR underlay-multicast chains. Confirms:
  * FHR has a local (Lo0_FHR, group) S,G with RPF=Null0 and the F flag set.
  * LHR has a (Lo0_FHR, group) S,G with RPF on a PIM neighbor, J+T flags,
    and the L2LISP interface in the OIL.
  * MFIB hardware counters dominate software counters on the LHR (sanity).
  * A summary verdict that distinguishes "wired correctly but no traffic yet"
    (WARN) from "broken state" (FAIL) from "actively forwarding" (OK).

State reads (FHR side): ``umcast_device``, ``umcast_broadcast_group``.
State reads (LHR side): ``umcast_dst_device``, ``umcast_dst_broadcast_group``.

Writes:
    umcast_fhr_sg            — FHR mroute dict or None.
    umcast_lhr_sg            — LHR mroute dict or None.
    umcast_lhr_sg_active     — bool: HW counters > 0.
"""

from checks import Check, CheckResult, CheckStatus, RunContext


def _wrap_fail(name: str, exc: BaseException) -> CheckResult:
    msg = str(exc) if str(exc) else exc.__class__.__name__
    return CheckResult(CheckStatus.FAIL, f"{name} raised {exc.__class__.__name__}: {msg}")


def _fhr_loopback(ctx: RunContext):
    """Loopback0 of the FHR — the multicast source for the broadcast group."""
    fhr = ctx.state.get("umcast_device")
    if fhr is None:
        return None
    return getattr(fhr.profiled_device, "loopback", None)


class UmcastFhrSg(Check):
    """FHR (S,G) for (Lo0_FHR, group): exists, RPF=Null0, F flag, OILs present."""

    name = "Underlay Mcast (S,G): FHR local S,G"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        fhr = ctx.state.get("umcast_device")
        group = ctx.state.get("umcast_broadcast_group")
        src = _fhr_loopback(ctx)
        if fhr is None or not group or not src:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: FHR device / group / Lo0 not available.",
            )
        host = fhr.profiled_device.hostname
        try:
            from routingmodules.multicastrouting import MulticastRoutes
            mr = MulticastRoutes(None, host)
            mr.mroute_get(group, src, ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        info = getattr(mr, "mrouteinfo", None)
        if not info or info[0].get("source") in (None, "*"):
            ctx.state["umcast_fhr_sg"] = None
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n• Expected S,G: ({src}, {group})\n"
                f"• Local S,G NOT FOUND. Verify CSCwf12353; try reconfiguring "
                f"`broadcast-underlay {group}` on the L2LISP instance.",
            )
        entry = info[0]
        ctx.state["umcast_fhr_sg"] = entry
        rpf = entry.get("incominginterface")
        flags = entry.get("flags") or ""
        oils = entry.get("outgoinginterfacelist") or []
        problems = []
        if rpf != "Null0":
            problems.append(f"RPF is {rpf}, expected Null0 (static mroute interfering?)")
        if "F" not in flags:
            problems.append(f"F flag missing — registration may be stuck (flags={flags})")
        body = (
            f"• Device: {host}\n"
            f"• S,G: ({src}, {group})\n"
            f"• RPF interface: {rpf}\n"
            f"• Flags: {flags}\n"
            f"• OIL count: {len(oils)}"
        )
        if not oils:
            problems.append("OIL is empty — no receivers known yet")
        if problems:
            return CheckResult(
                CheckStatus.WARN if not any("missing" in p or "RPF" in p for p in problems)
                else CheckStatus.FAIL,
                body + "\n• " + "; ".join(problems),
            )
        return CheckResult(CheckStatus.OK, body)


class UmcastLhrSg(Check):
    """LHR (S,G): exists, RPF on PIM neighbor, J+T flags, L2LISP interface in OIL."""

    name = "Underlay Mcast (S,G): LHR remote S,G"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        lhr = ctx.state.get("umcast_dst_device")
        group = ctx.state.get("umcast_dst_broadcast_group")
        src = _fhr_loopback(ctx)  # the FHR's Lo0 is the multicast source
        if lhr is None or not group or not src:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: LHR device / group / FHR Lo0 not available.",
            )
        host = lhr.profiled_device.hostname
        try:
            from routingmodules.multicastrouting import MulticastRoutes
            mr = MulticastRoutes(None, host)
            mr.mroute_get(group, src, ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        info = getattr(mr, "mrouteinfo", None)
        if not info or info[0].get("source") in (None, "*"):
            ctx.state["umcast_lhr_sg"] = None
            return CheckResult(
                CheckStatus.WARN,
                f"• Device: {host}\n• Expected S,G: ({src}, {group})\n"
                f"• Remote S,G not present yet — either no traffic has triggered "
                f"the SPT switch, or the *,G shared-tree path needs review.",
            )
        entry = info[0]
        ctx.state["umcast_lhr_sg"] = entry
        rpf = entry.get("incominginterface")
        flags = entry.get("flags") or ""
        oils = entry.get("outgoinginterfacelist") or []
        # RPF must match a PIM neighbor.
        nbrs = getattr(getattr(lhr, "pimneighbors", None), "pimneighbors", []) or []
        rpf_is_pim = any(n.get("interface") == rpf for n in nbrs)
        # OIL should contain the L2LISP interface.
        l2intf = getattr(getattr(lhr, "l2lispinterfacestatus", None),
                         "l2lispfinalinterface", None)
        oil_has_l2 = any(o.get("interface") == l2intf for o in oils)
        spt_ok = "J" in flags and "T" in flags
        body_lines = [
            f"• Device: {host}",
            f"• S,G: ({src}, {group})",
            f"• RPF interface: {rpf} (PIM neighbor: {rpf_is_pim})",
            f"• Flags: {flags}  (J+T expected: {spt_ok})",
            f"• L2LISP interface in OIL: {oil_has_l2} (expected: {l2intf})",
        ]
        problems = []
        if not rpf_is_pim:
            problems.append(f"RPF interface {rpf} is not a PIM neighbor")
        if not spt_ok:
            problems.append("missing J+T flags (not on SPT yet, or no traffic)")
        if oils and not oil_has_l2:
            problems.append(f"L2LISP interface {l2intf} missing from OIL")
        body = "\n".join(body_lines)
        if any("not a PIM" in p or "missing from OIL" in p for p in problems):
            return CheckResult(CheckStatus.FAIL, body + "\n• " + "; ".join(problems))
        if problems:
            return CheckResult(CheckStatus.WARN, body + "\n• " + "; ".join(problems))
        return CheckResult(CheckStatus.OK, body)


class UmcastLhrSgCounters(Check):
    """LHR MFIB counters: HW must dominate SW (>= SW)."""

    name = "Underlay Mcast (S,G): LHR MFIB counters"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        lhr = ctx.state.get("umcast_dst_device")
        group = ctx.state.get("umcast_dst_broadcast_group")
        src = _fhr_loopback(ctx)
        if lhr is None or not group or not src:
            return CheckResult(CheckStatus.SKIP, "Skipped: LHR / group / source missing.")
        if ctx.state.get("umcast_lhr_sg") is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: LHR S,G not present.")
        host = lhr.profiled_device.hostname
        try:
            from routingmodules.multicastrouting import MulticastRoutes
            mfib = MulticastRoutes(None, host)
            mfib.mfib_verbose(group, src, ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        sw = int(getattr(mfib, "sw_packet_count", 0) or 0)
        hw = int(getattr(mfib, "hw_packet_count", 0) or 0)
        ctx.state["umcast_lhr_sg_active"] = hw > 0
        body = (
            f"• Device: {host}\n"
            f"• S,G: ({src}, {group})\n"
            f"• HW-forwarded packets: {hw}\n"
            f"• SW-forwarded packets: {sw}"
        )
        if hw == 0 and sw == 0:
            return CheckResult(CheckStatus.WARN, body + "\n• No traffic registered yet.")
        if hw < sw:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n• SW counters exceed HW — confirm HW is the one increasing.",
            )
        return CheckResult(CheckStatus.OK, body + "\n• HW dominates — fast-path forwarding active.")


class UmcastSgVerdict(Check):
    """End-to-end S,G verdict for (FHR_Lo0, group)."""

    name = "Underlay Mcast (S,G): end-to-end verdict"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        fhr_sg = ctx.state.get("umcast_fhr_sg")
        lhr_sg = ctx.state.get("umcast_lhr_sg")
        active = ctx.state.get("umcast_lhr_sg_active")
        if fhr_sg is None and lhr_sg is None:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: neither FHR nor LHR S,G state is available.",
            )
        lines = [
            f"• FHR S,G present: {fhr_sg is not None}",
            f"• LHR S,G present: {lhr_sg is not None}",
            f"• LHR HW-forwarding active: {bool(active)}",
        ]
        body = "\n".join(lines)
        if fhr_sg is None:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• FHR has no local S,G — flooding cannot start. "
                "Resolve the FHR S,G FAIL upstream first.",
            )
        if lhr_sg is None:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n• LHR has not yet built the S,G — awaiting first packet "
                "or SPT switch. Generate ARP traffic and re-run.",
            )
        if not active:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n• Tree is built on both sides but no HW-forwarded traffic. "
                "Check if traffic is actually flowing.",
            )
        return CheckResult(
            CheckStatus.OK,
            body + "\n• End-to-end S,G is built and actively forwarding in hardware.",
        )


def build_underlay_multicast_sg_chain() -> list:
    """Return the ordered list of S,G traversal checks."""
    return [
        UmcastFhrSg(),
        UmcastLhrSg(),
        UmcastLhrSgCounters(),
        UmcastSgVerdict(),
    ]
