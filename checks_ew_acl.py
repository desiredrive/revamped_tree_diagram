"""East-West: PACL / VACL evaluation on source and destination XTRs.

Mirrors the DHCP path's local-policy validation but excludes RACL (route-map
inbound/outbound on the SVI) — east-west host-to-host traffic that stays in the
same VRF is evaluated against the access-port PACL and the VLAN VACL only.

For each side (source XTR + destination XTR) we evaluate two flow directions:
  • src endpoint IP  ->  dst endpoint IP
  • dst endpoint IP  ->  src endpoint IP

A direction is FAIL if any matched ACE returns 'deny'. SKIP cleanly when the
endpoint port is virtual (AccessTunnel/LISP) — PACLs cannot be applied — or
when no VACL is configured. Wireless (FEW) source ports always SKIP PACL.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks_ew_shared import _legacy_fail, _need, _skip_if_l3


_VIRTUAL_PORT_PREFIXES = ("AccessTunnel", "Ac", "LISP", "Tunnel")


def _is_physical_port(port: str | None) -> bool:
    if not port:
        return False
    return not str(port).startswith(_VIRTUAL_PORT_PREFIXES)


def _eval_bidir(service, hostname: str, acl_name: str, src_ip: str, dst_ip: str):
    """Return list of dicts: {'direction', 'src', 'dst', 'action', 'sequence'}.
    'action' is 'permit' / 'deny' / 'no-match' (no ACE matched and the ACL has
    no implicit deny — shouldn't happen since acl_evaluation appends one)."""
    from securitymodules.accesslists import acl_evaluation
    results = []
    for label, s, d in (("forward", src_ip, dst_ip), ("return", dst_ip, src_ip)):
        params = {
            "sourceip": s, "destinationip": d,
            "protocol": "ip", "srcport": None, "dstport": None,
        }
        hit = acl_evaluation(service, hostname, acl_name, False, params)
        if isinstance(hit, tuple) and len(hit) >= 3:
            results.append({
                "direction": label, "src": s, "dst": d,
                "action": str(hit[1]).lower(), "sequence": hit[2],
            })
        else:
            results.append({
                "direction": label, "src": s, "dst": d,
                "action": "no-match", "sequence": None,
            })
    return results


def _format_eval_block(acl_name: str, evals: list) -> str:
    lines = [f"  • ACL: {acl_name}"]
    for e in evals:
        action = e["action"].upper()
        arrow = "→"
        seq = e["sequence"]
        seq_str = f"  [seq {seq}]" if seq not in (None, "") else ""
        lines.append(
            f"      {e['direction']:<7}  {e['src']}  {arrow}  {e['dst']}   →   {action}{seq_str}"
        )
    return "\n".join(lines)


def _verdict(per_acl_results: list[dict]) -> CheckStatus:
    if not per_acl_results:
        return CheckStatus.SKIP
    any_deny = any(
        e["action"] == "deny"
        for r in per_acl_results
        for e in r["evals"]
    )
    return CheckStatus.FAIL if any_deny else CheckStatus.OK


def _resolve_ips(ctx: RunContext) -> tuple[str | None, str | None]:
    src = None
    sep = ctx.state.get("ew_sourceep")
    if sep is not None:
        src = getattr(sep, "sourceip", None)
    dst = ctx.payload.get("destination_ip")
    return src, dst


def _resolve_dst_xtr_hostname(ctx: RunContext) -> str | None:
    if ctx.state.get("ew_is_intra_xtr"):
        return ctx.state.get("xtr_hostname")
    dxtr = ctx.state.get("ew_dstxtr")
    if dxtr is None:
        return None
    return getattr(dxtr, "hostname", None)


def _run_pacl(ctx: RunContext, hostname: str, port: str | None,
              src_ip: str, dst_ip: str, role: str) -> CheckResult:
    if not _is_physical_port(port):
        return CheckResult(
            CheckStatus.SKIP,
            f"Skipped — {role} port '{port}' is virtual; PACL not applicable.",
        )
    try:
        from securitymodules.accesslists import AccessList
        port_acls = AccessList(hostname)
        port_acls.aclbyinterface(str(port), ctx.service)
    except BaseException as e:
        return _legacy_fail(e, f"{role} PACL discovery")
    acl_names = list(getattr(port_acls, "aclnames", []) or [])
    if not acl_names:
        return CheckResult(
            CheckStatus.OK,
            f"Device:        {hostname}\n"
            f"Port:          {port}\n"
            f"\n"
            f"No PACL applied — traffic implicitly permitted at port.",
        )
    per_acl = []
    try:
        for acl in acl_names:
            evals = _eval_bidir(ctx.service, hostname, acl, src_ip, dst_ip)
            per_acl.append({"acl": acl, "evals": evals})
    except BaseException as e:
        return _legacy_fail(e, f"{role} PACL evaluation")

    body = (
        f"Device:        {hostname}\n"
        f"Port:          {port}\n"
        f"Source:        {src_ip}\n"
        f"Destination:   {dst_ip}\n"
        f"\n"
        f"Port ACLs:\n"
        + "\n".join(_format_eval_block(r["acl"], r["evals"]) for r in per_acl)
    )
    return CheckResult(_verdict(per_acl), body, data={"per_acl": per_acl})


def _run_vacl(ctx: RunContext, hostname: str, vlan,
              src_ip: str, dst_ip: str, role: str) -> CheckResult:
    if vlan in (None, ""):
        return CheckResult(
            CheckStatus.SKIP,
            f"Skipped — {role} VLAN unknown.",
        )
    try:
        from switchingmodules.vacl import get_vacl_drop_acls
        vacl_raw = get_vacl_drop_acls(hostname, int(vlan), ctx.service) or []
    except BaseException as e:
        return _legacy_fail(e, f"{role} VACL discovery")

    implicit_deny = "VACL_IMPLICIT_DENY_ACTIVE" in vacl_raw
    acl_names = [a for a in vacl_raw if a != "VACL_IMPLICIT_DENY_ACTIVE"]

    if implicit_deny and not acl_names:
        return CheckResult(
            CheckStatus.FAIL,
            f"Device:        {hostname}\n"
            f"VLAN:          {vlan}\n"
            f"\n"
            f"VLAN access-map ends without 'action forward' — implicit deny\n"
            f"will block unmatched traffic.",
        )
    if not acl_names:
        return CheckResult(
            CheckStatus.OK,
            f"Device:        {hostname}\n"
            f"VLAN:          {vlan}\n"
            f"\n"
            f"No VACL drop entries on this VLAN.",
        )

    per_acl = []
    try:
        for acl in acl_names:
            evals = _eval_bidir(ctx.service, hostname, acl, src_ip, dst_ip)
            per_acl.append({"acl": acl, "evals": evals})
    except BaseException as e:
        return _legacy_fail(e, f"{role} VACL evaluation")

    body_lines = [
        f"Device:        {hostname}",
        f"VLAN:          {vlan}",
        f"Source:        {src_ip}",
        f"Destination:   {dst_ip}",
        "",
        "VLAN drop ACLs:",
        *[_format_eval_block(r["acl"], r["evals"]) for r in per_acl],
    ]
    if implicit_deny:
        body_lines += [
            "",
            "Note: access-map has no final 'action forward' — unmatched",
            "traffic falls to implicit deny.",
        ]
    status = _verdict(per_acl)
    if status == CheckStatus.OK and implicit_deny:
        status = CheckStatus.WARN
    return CheckResult(status, "\n".join(body_lines), data={"per_acl": per_acl})


class EwSourcePacl(Check):
    name = "Source PACL evaluation"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_sourceep", "xtr_hostname")
        if miss: return miss
        src_ip, dst_ip = _resolve_ips(ctx)
        if not (src_ip and dst_ip):
            return CheckResult(CheckStatus.SKIP, "Skipped — src/dst IP unresolved.")
        ep = ctx.state["ew_sourceep"]
        return _run_pacl(
            ctx,
            ctx.state["xtr_hostname"],
            getattr(ep, "sourceport", None),
            src_ip, dst_ip, "source",
        )


class EwSourceVacl(Check):
    name = "Source VACL evaluation"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_sourceep", "xtr_hostname")
        if miss: return miss
        src_ip, dst_ip = _resolve_ips(ctx)
        if not (src_ip and dst_ip):
            return CheckResult(CheckStatus.SKIP, "Skipped — src/dst IP unresolved.")
        ep = ctx.state["ew_sourceep"]
        return _run_vacl(
            ctx,
            ctx.state["xtr_hostname"],
            getattr(ep, "sourcevlan", None),
            src_ip, dst_ip, "source",
        )


class EwDestPacl(Check):
    name = "Destination PACL evaluation"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_destep")
        if miss: return miss
        host = _resolve_dst_xtr_hostname(ctx)
        if not host:
            return CheckResult(CheckStatus.SKIP, "Skipped — destination XTR not profiled.")
        src_ip, dst_ip = _resolve_ips(ctx)
        if not (src_ip and dst_ip):
            return CheckResult(CheckStatus.SKIP, "Skipped — src/dst IP unresolved.")
        ep = ctx.state["ew_destep"]
        return _run_pacl(
            ctx, host, getattr(ep, "sourceport", None),
            src_ip, dst_ip, "destination",
        )


class EwDestVacl(Check):
    name = "Destination VACL evaluation"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        if (skip := _skip_if_l3(ctx)): return skip
        miss = _need(ctx, "ew_destep")
        if miss: return miss
        host = _resolve_dst_xtr_hostname(ctx)
        if not host:
            return CheckResult(CheckStatus.SKIP, "Skipped — destination XTR not profiled.")
        src_ip, dst_ip = _resolve_ips(ctx)
        if not (src_ip and dst_ip):
            return CheckResult(CheckStatus.SKIP, "Skipped — src/dst IP unresolved.")
        ep = ctx.state["ew_destep"]
        return _run_vacl(
            ctx, host, getattr(ep, "sourcevlan", None),
            src_ip, dst_ip, "destination",
        )
