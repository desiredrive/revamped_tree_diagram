"""East-West Phase A: source endpoint profiling and flow election (L2 vs L3).

Mirrors main.py:59-83 and forwardinglogic.flowelection(). These checks run on
the source XTR and produce ctx.state["ew_sourceep"] + ctx.state["ew_flow_type"].
When the result is "L3", ctx.state["ew_l3_skip"] is set so every downstream
check trips the _skip_if_l3 gate cleanly.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.ew_shared import (
    _legacy_fail,
    _need,
    _build_src_xtr_shim,
    _endpoint_node_spec,
    _fmt_kv,
)


_IPDT_BAD = ("DOWN", "VERIFY", "STALE", "UNKNOWN", "INCOMPLETE")


def _render_endpoint_sisf(ep, hostname, service, side: str) -> CheckResult:
    """Build a CheckResult body for an endpoint-centric SISF view.

    `ep` is the EndpointInfo populated by host_onboarding_validation: it
    already carries the matched SISF row's state/method/privilege/MAC/VLAN/
    port. We additionally pull the device-tracking policies attached to the
    endpoint's VLAN so the output mirrors the DHCP check's "VLAN IPDT Policy"
    line — but keyed on the endpoint's VLAN rather than the SVI prefix.
    """
    state  = getattr(ep, "ipdtstate", None) or "(none)"
    method = getattr(ep, "ipdtmethod", None) or "(none)"
    priv   = getattr(ep, "ipdtprivilege", None)
    mac    = getattr(ep, "sourcemac", None)
    vlan   = getattr(ep, "sourcevlan", None)
    port   = getattr(ep, "sourceport", None)
    ip     = getattr(ep, "sourceip", None)

    pol_line = "(VLAN policy lookup skipped — service or VLAN missing)"
    if service and hostname and vlan:
        try:
            from switchingmodules.sisf import SISF
            sisf = SISF(hostname)
            sisf.device_tracking_policies(vlan, service)
            policies = getattr(sisf, "policies", None) or []
            if policies:
                names = sorted({p.get("policy", "?") for p in policies})
                pol_line = f"VLAN {vlan} → {', '.join(names)}"
            else:
                pol_line = f"no device-tracking policy attached to VLAN {vlan}"
        except Exception as e:
            pol_line = f"policy lookup failed: {type(e).__name__}: {e}"

    bad = any(x in (state or "") for x in _IPDT_BAD)
    status = CheckStatus.WARN if bad else CheckStatus.OK
    body = _fmt_kv([
        ("Endpoint IP", ip),
        ("MAC", mac),
        ("VLAN", vlan),
        ("Port", port),
        ("IPDT State", state),
        ("Learned via", method),
        ("Privilege", priv),
        ("VLAN IPDT Policy", pol_line),
    ])
    if bad:
        body += (
            f"\n\n⚠ IPDT state '{state}' is non-REACHABLE — endpoint will not "
            "register into LISP until the SISF row converges."
        )
    return CheckResult(status, body)


class EwSourceEndpointOnboarding(Check):
    """Profile the source endpoint on the source XTR via SISF/host-onboarding.

    Wraps EndpointInfo(endpoint_ip).host_onboarding_validation(srcxtr, service).
    For L2-only pools (where the SVI lives elsewhere), the form supplies mask
    and gateway directly — we honor those after onboarding so flowelection()
    has the data it needs.
    """

    name = "Source endpoint onboarding"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        service = ctx.service
        endpoint_ip = ctx.payload.get("endpoint_ip")
        if not (service and endpoint_ip):
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — requires service / endpoint_ip in payload.",
            )

        srcxtr = _build_src_xtr_shim(ctx)
        if not srcxtr.hostname:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — source XTR profiling has not populated xtr_hostname.",
            )

        try:
            from hostonboarding import EndpointInfo
            ep = EndpointInfo(endpoint_ip)
            ep.host_onboarding_validation(srcxtr, service, 0)
        except BaseException as e:
            return _legacy_fail(e, "Source endpoint onboarding")

        # L2-only override (form sends mask + gateway when ewL2.checked).
        if ctx.payload.get("l2only"):
            mask = ctx.payload.get("mask")
            gateway = ctx.payload.get("gateway")
            if mask:
                ep.mask = mask
            if gateway:
                ep.prefix = gateway
            ep.isl2only = True

        ctx.state["ew_sourceep"] = ep

        # Bridge MAC/VLAN into payload so the wireless (FEW) checks — which
        # were originally written for the DHCP form and read these from
        # payload directly — can run as-is in the east-west chain.
        if getattr(ep, "sourcemac", None) and not ctx.payload.get("mac"):
            ctx.payload["mac"] = ep.sourcemac
        if getattr(ep, "sourcevlan", None) and not ctx.payload.get("vlan"):
            ctx.payload["vlan"] = ep.sourcevlan

        node_spec = _endpoint_node_spec(
            "src-endpoint", ep, connect_to="xtr", label_prefix="SRC"
        )

        body = _fmt_kv([
            ("IP", getattr(ep, "sourceip", None)),
            ("MAC", getattr(ep, "sourcemac", None)),
            ("Port", getattr(ep, "sourceport", None)),
            ("VLAN", getattr(ep, "sourcevlan", None)),
            ("VRF", getattr(ep, "sourcevrf", None)),
            ("Gateway", getattr(ep, "prefix", None)),
            ("Mask", getattr(ep, "mask", None)),
            ("SISF state", getattr(ep, "ipdtstate", None)),
            ("L2-only pool", getattr(ep, "isl2only", None)),
            ("Wireless pool", getattr(ep, "iswirelesspool", None)),
        ])
        return CheckResult(
            CheckStatus.OK, body, data={"add_nodes": [node_spec]}
        )


class EwFlowElection(Check):
    """Decide L2 (same subnet) vs L3 (different subnet) east-west flow.

    Wraps forwardinglogic.flowelection(sourceep, destip). On "L3" the chain
    short-circuits — legacy doesn't implement the routed/transit/inter-VRF
    path, so downstream checks SKIP via the ew_l3_skip flag.
    """

    name = "Flow Election (L2 vs L3)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        miss = _need(ctx, "ew_sourceep")
        if miss:
            return miss
        destip = ctx.payload.get("destination_ip")
        if not destip:
            return CheckResult(
                CheckStatus.FAIL, "destination_ip missing from payload."
            )
        ep = ctx.state["ew_sourceep"]
        if not getattr(ep, "mask", None):
            return CheckResult(
                CheckStatus.FAIL,
                "Source endpoint has no mask — flow election needs source mask "
                "to determine same-subnet. For L2-only pools, supply mask in the form.",
            )

        try:
            from forwardinglogic import flowelection
            flow_type = flowelection(ep, destip, 0)
        except BaseException as e:
            return _legacy_fail(e, "Flow Election")

        ctx.state["ew_flow_type"] = flow_type
        if flow_type == "L3":
            ctx.state["ew_l3_skip"] = True
            return CheckResult(
                CheckStatus.WARN,
                "Different subnet → L3 east-west.\n"
                "L3 east-west is not yet implemented (legacy reference has no "
                "transit / inter-VRF support either). Downstream checks will SKIP.",
            )

        body = (
            f"Same subnet detected → L2 east-west.\n"
            f"• Source IP: {ep.sourceip}\n"
            f"• Destination IP: {destip}\n"
            f"• Source mask: {ep.mask}"
        )
        return CheckResult(CheckStatus.OK, body)


class EwSourceSisf(Check):
    """East-West — endpoint-centric SISF / device-tracking validation.

    Reads the EndpointInfo populated by EwSourceEndpointOnboarding (which
    already pulled the SISF row for the endpoint IP) and surfaces it as a
    dedicated check, plus the device-tracking policies attached to the
    endpoint's VLAN. Unlike the DHCP `SisfDeviceTracking` check, this is keyed
    on the endpoint — not the SVI — so it works for L2-only / wireless / FEW
    pools and for endpoints whose SVI is on a different node.
    """

    name = "SISF / Device-Tracking (endpoint)"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        ep = ctx.state.get("ew_sourceep")
        hostname = ctx.state.get("xtr_hostname")
        service = ctx.service
        if not ep:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped — source endpoint onboarding has not populated ew_sourceep.",
            )
        return _render_endpoint_sisf(ep, hostname, service, side="source")
