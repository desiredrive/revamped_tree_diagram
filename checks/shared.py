"""Shared helpers used by every checks_* module.

Kept tiny on purpose: just the two utilities that bridge the legacy
sys.exit-based helpers to structured CheckResults, and the SimpleNamespace
shim that lets legacy traffic_flows functions see ctx.state as if it were
the old edge_node_device object.
"""

import re
from types import SimpleNamespace

from checks import CheckResult, CheckStatus, RunContext


def normalize_mac(mac) -> str:
    """A MAC in the dotted-quad lower-case form IOS parsers key on.

    Genie keys its results the way IOS prints them -- `b811.4b0e.2630` -- while
    a user types whatever their notes hold: colons, hyphens, upper case. A
    lookup that only lower-cases the input misses every one of those, and the
    checks report the endpoint as unknown to the switch when the switch knew it
    perfectly well. Anything that is not twelve hex digits is returned trimmed
    and lower-cased rather than mangled, so a malformed value still reaches the
    device and fails there with a message about the MAC.
    """
    raw = (mac or "").strip().lower()
    hexonly = re.sub(r"[^0-9a-f]", "", raw)
    if len(hexonly) != 12:
        return raw
    return f"{hexonly[0:4]}.{hexonly[4:8]}.{hexonly[8:12]}"


def _legacy_fail(e: BaseException, prefix: str) -> CheckResult:
    """Format a legacy-helper failure for the UI.

    The CLI helpers call exit_program() which raises SystemExit with a
    user-friendly "Error: X | Y" string. For those, we show only that string.
    For genuinely unexpected exceptions we include the traceback.
    """
    if isinstance(e, SystemExit):
        return CheckResult(CheckStatus.FAIL, str(e) or f"{prefix} (SystemExit)")
    import traceback
    return CheckResult(
        CheckStatus.FAIL,
        f"{prefix} raised {type(e).__name__}: {e}\n\n"
        f"Traceback:\n{traceback.format_exc()}",
    )


def _build_edge_shim(ctx: RunContext):
    """Compose a SimpleNamespace mirroring the legacy edge_node_device.

    Legacy functions reach into edge_node_device.profiled_device.{hostname,
    mgmtip, dnac, fabric_id, fabric_site_hierarchy, ispubsub, loopback,
    isfabric, edge, l2handoff, iborder} and edge_node_device.{hostname,
    mac, vlan, mac_learning_info, loopback, localsgt, is_infravn, is_ap,
    dhcpparameters_info, lispparameters_info, sisfparameters_info}.
    """
    profiled = SimpleNamespace(
        hostname=ctx.state.get("xtr_hostname"),
        mgmtip=ctx.payload.get("mgmt_ip"),
        dnac=ctx.state.get("catc_name"),
        fabric_id=ctx.state.get("fabric_id"),
        fabric_site_hierarchy=ctx.state.get("fabric_site_hierarchy"),
        ispubsub=ctx.state.get("is_pubsub"),
        loopback=ctx.state.get("xtr_loopback"),
        isfabric=ctx.state.get("xtr_is_fabric"),
        edge=ctx.state.get("edge"),
        l2handoff=ctx.state.get("l2handoff"),
        iborder=ctx.state.get("iborder"),
    )
    return SimpleNamespace(
        profiled_device=profiled,
        hostname=ctx.state.get("xtr_hostname"),
        mac=ctx.payload.get("mac"),
        vlan=ctx.payload.get("vlan"),
        port=ctx.state.get("xtr_port"),
        mac_learning_info=ctx.state.get("mac_learning_info"),
        loopback=ctx.state.get("xtr_loopback"),
        localsgt=ctx.state.get("localsgt"),
        is_infravn=ctx.state.get("is_infravn"),
        is_ap=ctx.state.get("is_ap"),
        dhcpparameters_info=ctx.state.get("dhcpparameters_info"),
        lispparameters_info=ctx.state.get("lispparameters_info"),
        sisfparameters_info=ctx.state.get("sisfparameters_info"),
    )
def _cef_interfaces(ctx, hostname, dst_ip):
    """Outgoing interfaces the CEF entry for `dst_ip` resolves onto.

    ACLs are evaluated on the interfaces the traffic actually leaves by, so
    the path is taken from CEF rather than from the IGP: CEF is what the box
    forwards on, and the two can disagree.

    Derived per destination and never shared between them. The interfaces
    toward a map-server and toward the WLC are separate lookups -- on a switch
    with more than one uplink they can resolve onto different ports entirely,
    so reusing one set for the other would evaluate the wrong ACLs.
    """
    from routingmodules.cef import IPCef
    cef = IPCef(dst_ip, "default", hostname)
    cef.get_cef_internal(ctx.service)
    intfs = []
    for hop in (getattr(cef, "nexthops", None) or []):
        oif = hop.get("oif")
        # A LISP interface is virtual and carries no ACL.
        if oif and "LISP" not in oif and oif not in intfs:
            intfs.append(oif)
    return intfs


def _join(items):
    """Join labels for prose: "a", "a and b", "a, b and c"."""
    items = list(items)
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _evaluate_acls(ctx, hostname, interfaces, flows):
    """Evaluate every ACL on `interfaces` against each flow in `flows`.

    Returns (acl_names, denies, permits, unevaluated). A flow is a dict of
    the shape acl_evaluation expects plus a "label" used in the reported text.

    An ACL that cannot be read is reported in `unevaluated` rather than
    skipped. It is applied to the path whether or not we can parse it, so
    treating a parse failure as "nothing found" would report the path clear
    on the strength of an ACL nobody has looked at.
    """
    from securitymodules.accesslists import AccessList, acl_evaluation
    names = []
    for intf in interfaces:
        acls = AccessList(hostname)
        acls.aclbyinterface(intf, ctx.service)
        names.extend(getattr(acls, "aclnames", None) or [])
    names = sorted(set(names))

    denies, permits = [], []
    # Keyed by (acl, reason) so one unreadable ACL is reported once with the
    # flows it affected, not once per flow. Four near-identical sentences
    # repeating the same TypeError is noise that buries the actual finding.
    reasons: dict = {}
    for acl in names:
        for flow in flows:
            ev = {k: v for k, v in flow.items() if k != "label"}
            try:
                hit = acl_evaluation(ctx.service, hostname, acl, False, ev)
            except BaseException as e:
                reasons.setdefault(
                    (acl, f"{type(e).__name__}: {e}"), []).append(flow["label"])
                continue
            if not hit or len(hit) < 3:
                reasons.setdefault(
                    (acl, "no verdict returned"), []).append(flow["label"])
                continue
            # (flow, detail) pairs: the renderer puts the flow first and
            # the ACL that decided it second, so a reader scans what broke
            # before why.
            if hit[1] == "deny":
                denies.append((flow["label"], f"{acl}, sequence {hit[2]}"))
            elif hit[1] == "permit":
                permits.append((flow["label"], f"{acl}, sequence {hit[2]}"))
    # (acl, flows, reason) triples. Flows that failed identically collapse
    # to "all N flows" rather than being spelled out.
    unevaluated = []
    for (acl, reason), labels in reasons.items():
        covered = (f"all {len(flows)} flows" if len(labels) == len(flows)
                   else _join(labels))
        unevaluated.append((acl, covered, reason))
    return names, denies, permits, unevaluated


def render_acl_section(header, path, blocked=(), permitted=(), unread=()):
    """Render one destination's ACL findings as an indented section.

    A flat bullet list forced every line to repeat the addresses and the
    interface, which buried the one line the reader acts on. Stating the
    path once in a header and splitting blocked from not-evaluated keeps a
    deny visible next to the gaps around it.

    `blocked` and `permitted` are (flow, detail) pairs; `unread` is
    (acl, flows, reason) triples.
    """
    out = [header + (f", via {path}:" if path else ":")]
    if blocked:
        out.append("")
        out.append("  Blocked")
        out += [f"    • {flow} — {detail}" for flow, detail in blocked]
    if permitted and not blocked:
        out.append("")
        out.append("  Permitted")
        out += [f"    • {flow} — {detail}" for flow, detail in permitted]
    if unread:
        out.append("")
        out.append("  Not evaluated")
        for acl, flows, reason in unread:
            out.append(f"    • {acl} — {flows}")
            if reason:
                out.append(f"      {reason}")
    return "\n".join(out)
