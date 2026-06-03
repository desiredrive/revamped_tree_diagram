"""East-West Phase B: source L2 LISP state, ETR registration, ACLs, AR/MAC.

Wraps the steps in forwardinglogic.device_flow() up to the intra/inter split.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.ew_shared import (
    _legacy_fail,
    _need,
    _skip_if_l3,
    _build_src_xtr_shim,
    _fmt_kv,
    _fmt_list,
)


class EwSourceL2LispParameters(Check):
    """Profile L2 LISP parameters for the source endpoint on the source XTR."""

    name = "Source L2 LISP parameters"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_sourceep")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        ep = ctx.state["ew_sourceep"]
        try:
            from routingmodules import lisp
            l2 = lisp.l2lisp_info()
            l2.l2_lisp_parameters(srcxtr, ep, ctx.service)
        except BaseException as e:
            return _legacy_fail(e, "Source L2 LISP parameters")
        ctx.state["ew_l2lispsrc"] = l2
        body = _fmt_kv([
            ("VLAN", getattr(l2, "sourcevlan", None)),
            ("L2 VNI / IID", getattr(l2, "l2lispiid", None)),
            ("Source MAC", getattr(l2, "sourcemac", None)),
            ("L2 DynEID state", getattr(l2, "l2dynstate", None)),
            ("L2 DB state", getattr(l2, "l2lispdbstate", None)),
            ("L2 Control Planes", getattr(l2, "l2cps", None)),
            ("Signal-Suppress", getattr(l2, "l2signalsupressstate", None)),
            ("L2LISP ACL ingress", getattr(l2, "l2lispaclin", None)),
            ("L2LISP ACL egress", getattr(l2, "l2lispaclout", None)),
        ])
        return CheckResult(CheckStatus.OK, body)


class EwSourceEtrRegistration(Check):
    """Verify the source MAC/VLAN is registered on each L2 Control Plane."""

    name = "Source ETR registration (L2 LISP)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_l2lispsrc")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        l2 = ctx.state["ew_l2lispsrc"]
        try:
            from traffic_flows.lispsessiontroubleshooting import singleETRProfiling
            singleETRProfiling(
                None, l2.sourcemac, l2.sourcevlan, None,
                srcxtr.dnac, ctx.service, 0, srcxtr,
            )
        except BaseException as e:
            return _legacy_fail(e, "Source ETR registration")
        return CheckResult(
            CheckStatus.OK,
            f"ETR registration validated for MAC {l2.sourcemac} VLAN {l2.sourcevlan} "
            f"across CPs: {_fmt_list(getattr(l2, 'l2cps', None))}",
        )


class EwL2LispAclEvaluation(Check):
    """Evaluate L2LISP ingress (src→dst) and egress (dst→src) ACL hits.

    Legacy calls AccessList.aclbyidname + hexdecimal_acl_hit and sys.exit's
    on deny. We wrap each direction independently so a single deny shows
    up as FAIL on this check while the rest of the chain decides what to do.
    """

    name = "L2 LISP ACL evaluation"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_l2lispsrc", "ew_sourceep")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        srcep = ctx.state["ew_sourceep"]
        destip = ctx.payload.get("destination_ip")
        l2 = ctx.state["ew_l2lispsrc"]
        in_name = getattr(l2, "l2lispaclin", None)
        out_name = getattr(l2, "l2lispaclout", None)

        lines = []
        worst = CheckStatus.OK
        try:
            from securitymodules.accesslists import acl_evaluation
        except BaseException as e:
            return _legacy_fail(e, "L2 LISP ACL import")

        def _eval(name: str, direction: str, src, dst):
            nonlocal worst
            if not name:
                lines.append(f"• {direction} ACL: (none — no filter applied)")
                return
            evaluation = {
                "sourceip": src,
                "destinationip": dst,
                "protocol": "ip",
                "srcport": None,
                "dstport": None,
            }
            try:
                hit = acl_evaluation(ctx.service, srcxtr.hostname, name, False, evaluation)
                action = hit[1] if (isinstance(hit, tuple) and len(hit) > 1) else "no-match"
                lines.append(f"• {direction} ACL {name}: {action}")
                if action == "deny":
                    worst = CheckStatus.FAIL
            except BaseException as e:
                lines.append(f"• {direction} ACL {name}: error — {type(e).__name__}: {e}")
                if worst != CheckStatus.FAIL:
                    worst = CheckStatus.WARN

        _eval(in_name, "Ingress (src→dst)", srcep.sourceip, destip)
        _eval(out_name, "Egress (dst→src)", destip, srcep.sourceip)
        return CheckResult(worst, "\n".join(lines))


class EwSourceArResolution(Check):
    """Resolve AR-binding and MAC→RLOC for the SOURCE endpoint (sanity)."""

    name = "Source AR / MAC resolution"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_l2lispsrc", "ew_sourceep")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        srcep = ctx.state["ew_sourceep"]
        l2 = ctx.state["ew_l2lispsrc"]
        try:
            from traffic_flows.l2_lisp_interxtr import ar_relay_resolution, mac_rloc_resolution
            ar = ar_relay_resolution(
                srcep.sourceip, l2.l2lispiid, l2.l2cps,
                ctx.service, srcxtr.dnac, srcxtr.fabric_site_hierarchy, 0,
            )
            mac_rloc = mac_rloc_resolution(ar[0], l2.l2lispiid, ar[1], ctx.service, 0)
        except BaseException as e:
            return _legacy_fail(e, "Source AR / MAC resolution")
        ctx.state["ew_src_ar"] = ar
        ctx.state["ew_src_mac_rloc"] = mac_rloc
        body = _fmt_kv([
            ("Source IP", srcep.sourceip),
            ("AR-binding MAC", ar[0]),
            ("CPs queried", ar[1]),
            ("Source RLOC (own loopback)", mac_rloc[0]),
            ("Source MAC", mac_rloc[1]),
        ])
        return CheckResult(CheckStatus.OK, body)


class EwDestArResolution(Check):
    """Resolve AR-binding and MAC→RLOC for the DESTINATION endpoint.

    This is the canonical "is the destination registered?" check. A silent
    host shows up here as a legacy sys.exit → FAIL with the legacy message.
    """

    name = "Destination AR / MAC resolution"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_l2lispsrc")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        destip = ctx.payload.get("destination_ip")
        l2 = ctx.state["ew_l2lispsrc"]
        try:
            from traffic_flows.l2_lisp_interxtr import ar_relay_resolution, mac_rloc_resolution
            ar = ar_relay_resolution(
                destip, l2.l2lispiid, l2.l2cps,
                ctx.service, srcxtr.dnac, srcxtr.fabric_site_hierarchy, 0,
            )
            mac_rloc = mac_rloc_resolution(ar[0], l2.l2lispiid, ar[1], ctx.service, 0)
        except BaseException as e:
            return _legacy_fail(e, "Destination AR / MAC resolution")
        ctx.state["ew_dst_ar"] = ar
        ctx.state["ew_dst_mac_rloc"] = mac_rloc
        ctx.state["ew_dst_rloc"] = mac_rloc[0]
        ctx.state["ew_dst_mac"] = mac_rloc[1]
        body = _fmt_kv([
            ("Destination IP", destip),
            ("AR-binding MAC", ar[0]),
            ("CPs queried", ar[1]),
            ("Destination RLOC", mac_rloc[0]),
            ("Destination MAC", mac_rloc[1]),
        ])
        return CheckResult(CheckStatus.OK, body)


class EwIntraVsInter(Check):
    """Decide Same-Edge (intra-XTR) vs Inter-XTR flow."""

    name = "Intra-XTR vs Inter-XTR"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_dst_rloc")
        if miss:
            return miss
        srcrloc = ctx.state.get("xtr_loopback")
        dstrloc = ctx.state["ew_dst_rloc"]
        is_intra = (srcrloc == dstrloc)
        ctx.state["ew_is_intra_xtr"] = is_intra
        if is_intra:
            # No separate dxtr node will be created — fold any dxtr-targeted
            # checks (dest endpoint onboarding, dest CTS, RBACL) back onto the
            # source XTR so their results land on the only edge in play.
            remap = ctx.state.setdefault("node_remap", {})
            remap["dxtr"] = "xtr"
            return CheckResult(
                CheckStatus.OK,
                f"Same-Edge flow (source and destination both behind RLOC {srcrloc}).",
            )
        return CheckResult(
            CheckStatus.OK,
            f"Inter-Edge flow.\n• Source RLOC: {srcrloc}\n• Destination RLOC: {dstrloc}",
        )
