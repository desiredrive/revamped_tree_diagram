"""Cross-device correlation between FHR and LHR underlay-multicast state.

Runs after both ``build_underlay_multicast_chain("fhr")`` and
``build_underlay_multicast_chain("lhr")`` have populated their respective
``umcast_*`` / ``umcast_dst_*`` state. Pure correlation — no device calls.

Each check SKIPs when either side's state is missing (e.g. on intra-XTR runs
where the LHR chain wasn't queued, or when an upstream FAIL prevented a
particular value from being written).
"""

from checks import Check, CheckResult, CheckStatus, RunContext


# Anchor correlation badges on the destination node — they're the end-to-end
# verdict and follow the LHR chain in time order.
_CORR_NODE = "dxtr"


def _both(ctx: RunContext, fhr_key: str, lhr_key: str):
    """Return (fhr_val, lhr_val) or None if either is missing/falsy."""
    a = ctx.state.get(fhr_key)
    b = ctx.state.get(lhr_key)
    if a in (None, "", []) or b in (None, "", []):
        return None
    return (a, b)


class UmcastCorrRp(Check):
    """RP must match between FHR and LHR (no MSDP modeled in this stage)."""

    name = "Underlay Mcast (Corr): RP consistency"
    target_node_id = _CORR_NODE

    def run(self, ctx: RunContext) -> CheckResult:
        pair = _both(ctx, "umcast_rp", "umcast_dst_rp")
        if pair is None:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: RP not resolved on one or both sides.",
            )
        fhr_rp, lhr_rp = pair
        body = (
            f"• FHR RP: {fhr_rp}\n"
            f"• LHR RP: {lhr_rp}"
        )
        if fhr_rp != lhr_rp:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• RP mismatch — without MSDP, FHR registers and LHR joins "
                "will land on different RPs and traffic will be black-holed.",
            )
        return CheckResult(CheckStatus.OK, body + "\n• RPs match on both sides.")


class UmcastCorrGroup(Check):
    """broadcast-underlay group must be identical for the same L2VNI IID."""

    name = "Underlay Mcast (Corr): broadcast group consistency"
    target_node_id = _CORR_NODE

    def run(self, ctx: RunContext) -> CheckResult:
        pair = _both(ctx, "umcast_broadcast_group", "umcast_dst_broadcast_group")
        if pair is None:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: broadcast group not resolved on one or both sides.",
            )
        fhr_g, lhr_g = pair
        body = (
            f"• FHR broadcast-underlay group: {fhr_g}\n"
            f"• LHR broadcast-underlay group: {lhr_g}"
        )
        if fhr_g != lhr_g:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• Group mismatch — both edges must use the same multicast "
                "group for the L2VNI; flooded ARP will not reach the LHR.",
            )
        return CheckResult(CheckStatus.OK, body + "\n• Groups match on both sides.")


class UmcastCorrSsm(Check):
    """The broadcast group must NOT fall in SSM range on either side."""

    name = "Underlay Mcast (Corr): SSM consistency"
    target_node_id = _CORR_NODE

    def run(self, ctx: RunContext) -> CheckResult:
        fhr_d = ctx.state.get("umcast_device")
        lhr_d = ctx.state.get("umcast_dst_device")
        if fhr_d is None or lhr_d is None:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: device profile missing on one or both sides.",
            )
        fhr_ssm = bool(getattr(fhr_d, "isssmgroup", False))
        lhr_ssm = bool(getattr(lhr_d, "isssmgroup", False))
        body = (
            f"• FHR group inside SSM range: {fhr_ssm}\n"
            f"• LHR group inside SSM range: {lhr_ssm}"
        )
        if fhr_ssm or lhr_ssm:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• broadcast-underlay must be ASM on BOTH sides — narrow the "
                "SSM range on the offending side(s).",
            )
        return CheckResult(CheckStatus.OK, body + "\n• Group is ASM on both sides.")


class UmcastCorrMcastRange(Check):
    """`ip multicast group-range` must not deny the group on either side."""

    name = "Underlay Mcast (Corr): group-range ACL consistency"
    target_node_id = _CORR_NODE

    def run(self, ctx: RunContext) -> CheckResult:
        fhr_d = ctx.state.get("umcast_device")
        lhr_d = ctx.state.get("umcast_dst_device")
        if fhr_d is None or lhr_d is None:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: device profile missing on one or both sides.",
            )
        fhr_blk = bool(getattr(fhr_d, "isblockedbymcastrange", False))
        lhr_blk = bool(getattr(lhr_d, "isblockedbymcastrange", False))
        body = (
            f"• FHR group denied by group-range ACL: {fhr_blk}\n"
            f"• LHR group denied by group-range ACL: {lhr_blk}"
        )
        if fhr_blk or lhr_blk:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• `ip multicast group-range` must permit the group on BOTH "
                "sides; loosen or correct the ACL where it denies.",
            )
        return CheckResult(CheckStatus.OK, body + "\n• ACL permits the group on both sides.")


class UmcastCorrSummary(Check):
    """End-to-end verdict: PASSes only when the four invariants above hold."""

    name = "Underlay Mcast (Corr): end-to-end verdict"
    target_node_id = _CORR_NODE

    def run(self, ctx: RunContext) -> CheckResult:
        # Re-evaluate the same invariants so the verdict is self-contained.
        fhr_rp = ctx.state.get("umcast_rp")
        lhr_rp = ctx.state.get("umcast_dst_rp")
        fhr_g = ctx.state.get("umcast_broadcast_group")
        lhr_g = ctx.state.get("umcast_dst_broadcast_group")
        fhr_d = ctx.state.get("umcast_device")
        lhr_d = ctx.state.get("umcast_dst_device")
        if not all([fhr_rp, lhr_rp, fhr_g, lhr_g, fhr_d, lhr_d]):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: missing FHR/LHR state — see upstream FAIL/SKIPs for the gap.",
            )
        problems = []
        if fhr_rp != lhr_rp:
            problems.append(f"RP mismatch ({fhr_rp} vs {lhr_rp})")
        if fhr_g != lhr_g:
            problems.append(f"group mismatch ({fhr_g} vs {lhr_g})")
        if getattr(fhr_d, "isssmgroup", False) or getattr(lhr_d, "isssmgroup", False):
            problems.append("group falls in SSM range on at least one side")
        if getattr(fhr_d, "isblockedbymcastrange", False) or \
           getattr(lhr_d, "isblockedbymcastrange", False):
            problems.append("group-range ACL denies on at least one side")
        body = (
            f"• FHR: {getattr(fhr_d.profiled_device, 'hostname', '?')}  RP={fhr_rp}  group={fhr_g}\n"
            f"• LHR: {getattr(lhr_d.profiled_device, 'hostname', '?')}  RP={lhr_rp}  group={lhr_g}"
        )
        if problems:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• End-to-end flooding will NOT work — issues: "
                + "; ".join(problems) + ".",
            )
        return CheckResult(
            CheckStatus.OK,
            body + "\n• End-to-end invariants hold — flooding-mode L2VNI is consistent "
            "across both edges.",
        )


def build_underlay_multicast_correlation_chain() -> list:
    """Return the ordered list of FHR↔LHR correlation checks."""
    return [
        UmcastCorrRp(),
        UmcastCorrGroup(),
        UmcastCorrSsm(),
        UmcastCorrMcastRange(),
        UmcastCorrSummary(),
    ]
