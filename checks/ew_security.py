"""East-West Phase E: CTS / TrustSec policy evaluation (SGT + RBACL).

Mirrors forwardinglogic.l2_inter_xtr_ew lines 412-479. Runs on both intra-XTR
and inter-XTR (per user direction: MAC tracking, CTS, ACL, authen session all
matter locally too). On intra-XTR the destination XTR == source XTR.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.ew_shared import (
    _legacy_fail,
    _need,
    _skip_if_l3,
    _build_src_xtr_shim,
    _fmt_kv,
)


def _run_cts_endpoint(ep, xtr_hostname, service, *, wireless_sgt=None):
    """Run the CTS endpoint queries.

    On Fabric-Enabled Wireless the endpoint lands on a virtual AccessTunnel
    (e.g. Ac0) and CTS classification comes from the WLC's per-client SGT,
    not from `show cts interface`. When the caller supplies a wireless_sgt
    (resolved during the wireless lookup), we use it directly and skip the
    interface-level CTS probe that would otherwise fail on Ac*.
    """
    from securitymodules.ciscotrustsec import cts_endpoint_info
    info = cts_endpoint_info(ep.sourceip, ep.sourcevrf, xtr_hostname)
    info.cts_sgt_mapping(service)

    port = (getattr(ep, "sourceport", "") or "")
    is_few = port.lower().startswith("ac") and wireless_sgt is not None

    if is_few:
        # Trust the WLC-reported SGT for FEW. Mark classification as DYNAMIC
        # (assigned by AAA at wireless authentication), no port-level CTS state.
        try:
            info.sgt = int(wireless_sgt)
        except (TypeError, ValueError):
            info.sgt = wireless_sgt
        info.cefsgt = info.sgt
        info.source = "WIRELESS"
        info.ctsintf_state = False
        info.sgt_classificaiton = "DYNAMIC"
        info.propagation = False
        info.trust = False
    else:
        binding = {"ip": info.endpoint_ip, "sgt": info.sgt, "source": info.source}
        info.cts_class_method(ep.sourceport, binding, service)

    info.cts_enforcement(ep.sourcevlan, ep.sourceport, service)
    return info


def _cts_body(info, label: str) -> str:
    return label + "\n" + _fmt_kv([
        ("Endpoint IP", getattr(info, "endpoint_ip", None)),
        ("SGT", getattr(info, "sgt", None)),
        ("CEF SGT", getattr(info, "cefsgt", None)),
        ("Source", getattr(info, "source", None)),
        ("Classification method", getattr(info, "method", None)),
        ("Enforcement (VLAN)", getattr(info, "vlanenforcement", None)),
        ("Enforcement (port)", getattr(info, "portenforcement", None)),
    ])


class EwSourceCts(Check):
    """Resolve source SGT, classification method, and enforcement state."""

    name = "Source CTS / SGT"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_sourceep")
        if miss:
            return miss
        srcxtr = _build_src_xtr_shim(ctx)
        ep = ctx.state["ew_sourceep"]
        try:
            info = _run_cts_endpoint(
                ep, srcxtr.hostname, ctx.service,
                wireless_sgt=ctx.state.get("wireless_sgt"),
            )
        except BaseException as e:
            return _legacy_fail(e, "Source CTS")
        ctx.state["ew_src_cts"] = info
        ctx.state["ew_src_sgt"] = getattr(info, "cefsgt", None)
        return CheckResult(CheckStatus.OK, _cts_body(info, "Source endpoint:"))


class EwDestCts(Check):
    """Resolve destination SGT, classification method, and enforcement state."""

    name = "Destination CTS / SGT"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_destep")
        if miss:
            return miss
        # On intra-XTR, dstxtr == srcxtr.
        if ctx.state.get("ew_is_intra_xtr"):
            xtr = _build_src_xtr_shim(ctx)
        else:
            dstxtr = ctx.state.get("ew_dstxtr")
            if dstxtr is None:
                return CheckResult(
                    CheckStatus.SKIP,
                    "Skipped — destination XTR not profiled.",
                )
            xtr = dstxtr
        ep = ctx.state["ew_destep"]
        try:
            info = _run_cts_endpoint(
                ep, xtr.hostname, ctx.service,
                wireless_sgt=ctx.state.get("wireless_dst_sgt"),
            )
        except BaseException as e:
            return _legacy_fail(e, "Destination CTS")
        ctx.state["ew_dst_cts"] = info
        ctx.state["ew_dst_sgt"] = getattr(info, "cefsgt", None)
        sgt_val = getattr(info, "cefsgt", None)
        ip = getattr(ep, "sourceip", None)
        mac = getattr(ep, "sourcemac", None)
        port = getattr(ep, "sourceport", None)
        vlan = getattr(ep, "sourcevlan", None)
        label_lines = [f"DST {ip}" if ip else "DST"]
        if mac:
            label_lines.append(str(mac))
        if vlan not in (None, ""):
            label_lines.append(f"VLAN {vlan}")
        if sgt_val not in (None, ""):
            label_lines.append(f"SGT {sgt_val}")
        if port:
            label_lines.append(str(port))
        data = {
            "relabel_nodes": [
                {"id": "dst-endpoint", "label": "\n".join(label_lines)}
            ]
        }
        return CheckResult(
            CheckStatus.OK,
            _cts_body(info, "Destination endpoint:"),
            data=data,
        )


class EwCtsRules(Check):
    """Evaluate the RBACL rule between src SGT and dst SGT on the destination XTR.

    Warns when hw/sw denied counters are non-zero (active drops).
    """

    name = "CTS / RBACL evaluation"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_src_sgt", "ew_dst_sgt")
        if miss:
            return miss
        sgt = ctx.state["ew_src_sgt"]
        dgt = ctx.state["ew_dst_sgt"]
        if ctx.state.get("ew_is_intra_xtr"):
            xtr_hostname = ctx.state.get("xtr_hostname")
        else:
            dstxtr = ctx.state.get("ew_dstxtr")
            xtr_hostname = getattr(dstxtr, "hostname", None) or ctx.state.get("xtr_hostname")
        try:
            from securitymodules.ciscotrustsec import cts_rules
            rules = cts_rules(xtr_hostname)
            rules.cts_rbac_permissions(sgt, dgt, ctx.service)
            rbacl = rules.rbacl
            if getattr(rules, "isdefaultrule", False):
                rules.cts_rbac_counters(0, 0, ctx.service)
                rules.cts_rbac_rbacls(rbacl, ctx.service)
                if getattr(rules, "defaultpermit", False) is True:
                    rules.aces = None
            else:
                rules.cts_rbac_rbacls(rbacl, ctx.service)
                rules.cts_rbac_counters(sgt, dgt, ctx.service)
        except BaseException as e:
            return _legacy_fail(e, "CTS / RBACL evaluation")
        ctx.state["ew_cts_rules"] = rules
        aces = getattr(rules, "aces", None)
        is_default = getattr(rules, "isdefaultrule", False)
        hw_denied = getattr(rules, "hw_denied_count", 0) or 0
        sw_denied = getattr(rules, "sw_denied_count", 0) or 0
        hw_permit = getattr(rules, "hw_permitted_count", 0) or 0
        sw_permit = getattr(rules, "sw_permitted_count", 0) or 0
        body_lines = [
            f"Evaluating SGT {sgt} → DGT {dgt} on {xtr_hostname}",
            "",
            f"• Rule type: {'default' if is_default else 'specific'}",
            f"• RBACL: {rbacl}",
        ]
        if aces:
            body_lines.append("• ACEs:")
            for ace in (aces if isinstance(aces, list) else [aces]):
                body_lines.append(f"    {ace}")
        body_lines += [
            f"• Permit counters — hw: {hw_permit}, sw: {sw_permit}",
            f"• Deny counters   — hw: {hw_denied}, sw: {sw_denied}",
        ]
        body = "\n".join(body_lines)
        if (hw_denied + sw_denied) > 0:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n\nActive drop counters — verify intended policy.",
            )
        return CheckResult(CheckStatus.OK, body)
