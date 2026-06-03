"""Stage 4b: RP-side underlay-multicast validation (anycast-RP capable).

Discovers ALL devices that own the RP IP via CatC's ``/interface/ip-address``
endpoint (so anycast-RP setups validate every replica), then fans out a
per-RP validation chain. A trailing consistency check correlates state
across the discovered RPs.

Per-RP state keys (idx 1, 2, ...):
    umcast_rp{idx}_device       — UnderlayMulticastDevice wrapping profiled RP.
    umcast_rp{idx}_hostname     — RP hostname.
    umcast_rp{idx}_mgmtip       — RP mgmt IP.
    umcast_rp{idx}_star_g       — *,G mroute dict or None.
    umcast_rp{idx}_fhr_sg       — (FHR_Lo0, G) S,G dict or None.

Discovery-level state:
    umcast_rp_devices           — list of profiled Device objects (anycast set).
    umcast_rp_count             — len(umcast_rp_devices).
    umcast_rp{idx}_skip         — disable flag for that RP's downstream checks.
"""

from checks import Check, CheckResult, CheckStatus, RunContext


def _wrap_fail(name: str, exc: BaseException) -> CheckResult:
    msg = str(exc) if str(exc) else exc.__class__.__name__
    return CheckResult(CheckStatus.FAIL, f"{name} raised {exc.__class__.__name__}: {msg}")


def _safe_mroute_entries(host, vrf, group, source, service):
    """Return a list of mroute entry dicts for ``group`` on ``host``.

    Wraps the legacy ``MulticastRoutes.mroute_get`` (which crashes with KeyError
    when Genie omits a field like ``incoming_interface_list`` — common for
    transient entries during PIM register processing). Falls back to parsing
    the raw Genie output ourselves with ``.get()`` so a partially-populated
    entry still yields useful diagnostic data instead of a hard failure.

    Returns ``(entries_list, used_fallback_bool)``. Entries match the legacy
    schema: ``source/flags/incominginterface/rpfneighbor/outgoinginterfacelist``.
    """
    from routingmodules.multicastrouting import MulticastRoutes
    mr = MulticastRoutes(None, host)
    if vrf:
        mr.vrf = vrf
    try:
        mr.mroute_get(group, source, service)
        return list(getattr(mr, "mrouteinfo", None) or []), False
    except KeyError:
        pass
    # Fallback — re-issue the same command and parse defensively.
    import radkit_cli
    vrf_mode = ""
    vrf_key = ""
    if vrf and vrf != "default":
        vrf_mode = f"vrf {vrf} "
        vrf_key = vrf
    cmd = f"show ip mroute {vrf_mode}{group} {source}"
    op = radkit_cli.get_single_output_genie(host, cmd, service)
    if not op:
        return [], True
    try:
        srcs = op["vrf"][vrf_key]["address_family"]["ipv4"]["multicast_group"][group]["source_address"]
    except KeyError:
        return [], True
    entries = []
    for s, body in srcs.items():
        iif_dict = body.get("incoming_interface_list") or {}
        iif = next(iter(iif_dict), None) if iif_dict else None
        oil = body.get("outgoing_interface_list") or {}
        oils = [
            {
                "interface": k,
                "uptime": v.get("uptime"),
                "expire": v.get("expire"),
                "state": v.get("state_mode"),
            }
            for k, v in oil.items()
        ]
        entries.append({
            "source": s,
            "uptime": body.get("uptime"),
            "expire": body.get("expire"),
            "flags": body.get("flags") or "",
            "msdplearned": body.get("msdp_learned"),
            "rp_bit": body.get("rp_bit"),
            "rp": body.get("rp") if s == "*" else "N/A",
            "rpfneighbor": body.get("rpf_nbr"),
            "incominginterface": iif,
            "outgoinginterfacelist": oils,
        })
    return entries, True


def _node_id(idx: int) -> str:
    return f"urp{idx}"


def _key(idx: int, suffix: str) -> str:
    return f"umcast_rp{idx}_{suffix}"


def _disabled_flag(idx: int) -> str:
    return _key(idx, "skip")


def _mark_disabled(ctx: RunContext, idx: int, reason: str) -> None:
    ctx.state[_disabled_flag(idx)] = reason


def _skip_if_disabled(ctx: RunContext, idx: int):
    reason = ctx.state.get(_disabled_flag(idx))
    if reason:
        return CheckResult(
            CheckStatus.SKIP,
            f"Skipped — RP-side validation disabled: {reason}",
        )
    return None


def _fhr_loopback(ctx: RunContext):
    fhr = ctx.state.get("umcast_device")
    if fhr is None:
        return None
    return getattr(getattr(fhr, "profiled_device", None), "loopback", None)


def _lhr_loopback(ctx: RunContext):
    lhr = ctx.state.get("umcast_dst_device")
    if lhr is None:
        return None
    return getattr(getattr(lhr, "profiled_device", None), "loopback", None)


# ---------------------------------------------------------------------------
# Discovery: resolve the RP IP via CatC, profile every device that owns it,
# and queue a per-RP validation chain (+ consistency verdict).
# ---------------------------------------------------------------------------


class UmcastRpDiscovery(Check):
    """Find every device that owns the RP IP and queue per-RP chains."""

    name = "Underlay Mcast (RP): discover RP devices"
    target_node_id = "xtr"  # anchor on FHR; per-RP nodes are added later

    def run(self, ctx: RunContext) -> CheckResult:
        rp_ip = ctx.state.get("umcast_rp")
        if not rp_ip:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: RP IP not resolved (see FHR RP identification check).",
            )
        catc = ctx.state.get("umcast_catc_name") or ctx.state.get("catc_name")
        try:
            from catalystcenterapi.catcapi import profile_devices_with_ip
            profiled = profile_devices_with_ip(0, rp_ip, catc, ctx.service) or []
        except BaseException as e:
            return _wrap_fail(self.name, e)
        if not profiled:
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped: RP {rp_ip} is not associated with any device in CatC "
                f"inventory — likely outside the fabric / not managed by CatC. "
                f"RP-side checks cannot proceed.",
            )
        ctx.state["umcast_rp_devices"] = profiled
        ctx.state["umcast_rp_count"] = len(profiled)

        # Build the queued per-RP chains and a final consistency verdict.
        queued = []
        for idx, _pd in enumerate(profiled, start=1):
            queued.extend(_per_rp_chain(idx))
        if len(profiled) >= 2:
            # Anycast-RP set — validate MSDP synchronization between replicas.
            from checks.underlay_multicast_msdp import build_msdp_chain_for_rp
            for idx, _pd in enumerate(profiled, start=1):
                queued.extend(build_msdp_chain_for_rp(idx))
            queued.append(UmcastRpAnycastConsistency())

        # Body lists each RP that will be validated.
        lines = [
            f"• RP IP: {rp_ip}",
            f"• Devices owning the RP IP: {len(profiled)}"
            + (" (anycast-RP)" if len(profiled) >= 2 else ""),
        ]
        for idx, pd in enumerate(profiled, start=1):
            lines.append(
                f"  - RP{idx}: {getattr(pd, 'hostname', '?')} "
                f"(mgmt {getattr(pd, 'mgmtip', '?')})"
            )
        return CheckResult(
            CheckStatus.OK, "\n".join(lines), data={"queue_checks": queued}
        )


def _per_rp_chain(idx: int) -> list:
    from checks.underlay_multicast_gates import build_pim_gates_for_rp
    return [
        UmcastRpProfile(idx),
        *build_pim_gates_for_rp(idx),
        UmcastRpGlobalMcast(idx),
        UmcastRpStarG(idx),
        UmcastRpFhrSg(idx),
        UmcastRpLhrSg(idx),
        UmcastRpVerdict(idx),
    ]


class _PerRp(Check):
    """Base for per-RP checks: stamps name/node id from the index."""

    base_name = "per-RP"

    def __init__(self, idx: int):
        self.idx = idx
        self.name = f"Underlay Mcast (RP{idx}): {self.base_name}"
        self.target_node_id = _node_id(idx)


class UmcastRpProfile(_PerRp):
    """Wrap the discovered RP device into UnderlayMulticastDevice + emit node."""

    base_name = "profile device"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        devices = ctx.state.get("umcast_rp_devices") or []
        if idx - 1 >= len(devices):
            _mark_disabled(ctx, idx, "RP device not in discovery list")
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: discovery did not produce this RP slot.",
            )
        pd = devices[idx - 1]
        rp_ip = ctx.state.get("umcast_rp")
        try:
            from traffic_flows.underlay_multicast import UnderlayMulticastDevice
            umd = UnderlayMulticastDevice(None, getattr(pd, "mgmtip", rp_ip), 0)
            umd.existing_profiled(pd)
        except BaseException as e:
            _mark_disabled(ctx, idx, f"profile wrap raised {e.__class__.__name__}")
            return _wrap_fail(self.name, e)
        ctx.state[_key(idx, "device")] = umd
        ctx.state[_key(idx, "hostname")] = getattr(pd, "hostname", None)
        ctx.state[_key(idx, "mgmtip")] = getattr(pd, "mgmtip", None)

        loopback = getattr(pd, "loopback", None)
        platform = getattr(pd, "platform", None)
        label_lines = [getattr(pd, "hostname", f"RP{idx}"), rp_ip]
        if loopback:
            label_lines.append(f"Lo0 {loopback}")
        if platform:
            label_lines.append(platform)
        node = {
            "id": _node_id(idx),
            "role": "rp",
            "label": "\n".join(label_lines),
            # Use the device's MGMT IP (unique) as the node identity key — the
            # RP IP itself is shared across anycast replicas and would cause
            # the frontend to merge urp1/urp2 into a single node.
            "ip": getattr(pd, "mgmtip", None) or rp_ip,
            "hostname": getattr(pd, "hostname", None),
        }
        body = (
            f"• RP{idx} IP: {rp_ip}\n"
            f"• Hostname: {getattr(pd, 'hostname', None)}\n"
            f"• Mgmt IP: {getattr(pd, 'mgmtip', None)}\n"
            f"• Loopback0: {loopback}\n"
            f"• Platform: {platform}\n"
            f"• Software: {getattr(pd, 'version', None)}\n"
            f"• Site: {getattr(pd, 'fabric_site_hierarchy', None)}"
        )
        return CheckResult(CheckStatus.OK, body, data={"add_nodes": [node]})


class UmcastRpGlobalMcast(_PerRp):
    """Global multicast routing must be enabled on this RP."""

    base_name = "global multicast enabled"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        if (skip := _skip_if_disabled(ctx, idx)): return skip
        umd = ctx.state.get(_key(idx, "device"))
        if umd is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: RP not profiled.")
        try:
            umd.multicast_enablement(ctx.service)
        except BaseException as e:
            _mark_disabled(ctx, idx, "multicast_enablement raised")
            return _wrap_fail(self.name, e)
        cfg = getattr(umd, "mcastconfig", None)
        enabled = bool(getattr(cfg, "multicastenabled", False)) if cfg else False
        host = ctx.state.get(_key(idx, "hostname"))
        body = f"• Device: {host}\n• Global multicast routing enabled: {enabled}"
        ctx.state[_key(idx, "mcast_enabled")] = enabled
        if not enabled:
            _mark_disabled(ctx, idx, "global multicast routing disabled on RP")
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• Without `ip multicast-routing` on the RP, the RP cannot "
                "decap PIM Registers or build any *,G — the broadcast-underlay tree "
                "will not form.",
            )
        return CheckResult(CheckStatus.OK, body)


class UmcastRpStarG(_PerRp):
    """RP must have a ``*,G`` mroute for the broadcast-underlay group."""

    base_name = "*,G for broadcast group"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        if (skip := _skip_if_disabled(ctx, idx)): return skip
        host = ctx.state.get(_key(idx, "hostname"))
        group = ctx.state.get("umcast_broadcast_group")
        if not host or not group:
            return CheckResult(CheckStatus.SKIP, "Skipped: RP host / group not available.")
        try:
            # 255.255.255.255 is a sentinel: matches no real source, so the
            # device returns the full mroute table for the group (incl. *,G).
            info, _fb = _safe_mroute_entries(host, None, group, "255.255.255.255", ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        star_g = next((e for e in info if e.get("source") == "*"), None)
        ctx.state[_key(idx, "star_g")] = star_g
        if not star_g:
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n• Group: {group}\n"
                f"• No *,G mroute on the RP — either this device isn't actually the "
                f"RP for {group}, or PIM hasn't initialized for this group yet.",
            )
        iif = star_g.get("incominginterface") or "Null"
        flags = star_g.get("flags") or ""
        oils = star_g.get("outgoinginterfacelist") or []
        body = (
            f"• Device: {host}\n"
            f"• *,G entry: (*, {group})\n"
            f"• IIF: {iif}\n"
            f"• Flags: {flags}\n"
            f"• OIL count: {len(oils)}"
        )
        if not flags:
            return CheckResult(CheckStatus.WARN, body + "\n• flags empty — RP entry may be transient")
        return CheckResult(CheckStatus.OK, body)


class UmcastRpFhrSg(_PerRp):
    """``(FHR_Lo0, group)`` S,G must exist on the RP after PIM register."""

    base_name = "FHR registration S,G"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        if (skip := _skip_if_disabled(ctx, idx)): return skip
        host = ctx.state.get(_key(idx, "hostname"))
        group = ctx.state.get("umcast_broadcast_group")
        src = _fhr_loopback(ctx)
        if not host or not group or not src:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: RP / group / FHR Lo0 not available.",
            )
        try:
            info, _fb = _safe_mroute_entries(host, None, group, src, ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        sg = next((e for e in info if e.get("source") not in (None, "*")), None)
        ctx.state[_key(idx, "fhr_sg")] = sg
        if not sg:
            return CheckResult(
                CheckStatus.WARN,
                f"• Device: {host}\n• Expected S,G: ({src}, {group})\n"
                f"• No S,G on the RP for this FHR — either FHR has not yet sent a "
                f"PIM Register, registration is being filtered, or the entry has "
                f"timed out (no recent traffic).",
            )
        iif = sg.get("incominginterface") or "Null"
        flags = sg.get("flags") or ""
        oils = sg.get("outgoinginterfacelist") or []
        body_lines = [
            f"• Device: {host}",
            f"• S,G: ({src}, {group})",
            f"• IIF: {iif}",
            f"• Flags: {flags}",
            f"• OIL count: {len(oils)}",
        ]
        problems = []
        if "P" in flags and not oils:
            problems.append("entry is pruned with empty OIL — no active receivers (OK if no joins yet)")
        body = "\n".join(body_lines)
        if problems:
            return CheckResult(CheckStatus.WARN, body + "\n• " + "; ".join(problems))
        return CheckResult(CheckStatus.OK, body)


class UmcastRpLhrSg(_PerRp):
    """Optional: ``(LHR_Lo0, group)`` S,G when LHR is also a registered source."""

    base_name = "LHR registration S,G"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        if (skip := _skip_if_disabled(ctx, idx)): return skip
        host = ctx.state.get(_key(idx, "hostname"))
        group = ctx.state.get("umcast_broadcast_group")
        src = _lhr_loopback(ctx)
        if not host or not group:
            return CheckResult(CheckStatus.SKIP, "Skipped: RP / group not available.")
        if not src:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: LHR not in scope (FHR-only run) or LHR Lo0 not resolved.",
            )
        try:
            info, _fb = _safe_mroute_entries(host, None, group, src, ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        sg = next((e for e in info if e.get("source") not in (None, "*")), None)
        ctx.state[_key(idx, "lhr_sg")] = sg
        if not sg:
            return CheckResult(
                CheckStatus.WARN,
                f"• Device: {host}\n• Expected S,G: ({src}, {group})\n"
                f"• No S,G on the RP for the LHR — LHR has not yet flooded for "
                f"this group, or no traffic has triggered registration.",
            )
        body = (
            f"• Device: {host}\n"
            f"• S,G: ({src}, {group})\n"
            f"• IIF: {sg.get('incominginterface') or 'Null'}\n"
            f"• Flags: {sg.get('flags') or ''}\n"
            f"• OIL count: {len(sg.get('outgoinginterfacelist') or [])}"
        )
        return CheckResult(CheckStatus.OK, body)


class UmcastRpVerdict(_PerRp):
    """Per-RP end-to-end verdict."""

    base_name = "RP-side verdict"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        if (skip := _skip_if_disabled(ctx, idx)): return skip
        host = ctx.state.get(_key(idx, "hostname"))
        group = ctx.state.get("umcast_broadcast_group")
        star_g = ctx.state.get(_key(idx, "star_g"))
        fhr_sg = ctx.state.get(_key(idx, "fhr_sg"))
        if host is None or group is None:
            return CheckResult(CheckStatus.SKIP, "Skipped: RP / group not available.")
        body = (
            f"• RP: {host}\n"
            f"• Group: {group}\n"
            f"• *,G present on RP: {star_g is not None}\n"
            f"• FHR registered (S,G on RP): {fhr_sg is not None}"
        )
        if star_g is None:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• RP is missing the *,G — RP-side mroute state is not "
                "established; flooding cannot propagate via this RP.",
            )
        if fhr_sg is None:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n• FHR has not registered to this RP yet — generate flooded "
                "traffic on the FHR and re-run, or investigate register filtering.",
            )
        return CheckResult(
            CheckStatus.OK,
            body + "\n• RP has both *,G and FHR S,G — registration path is healthy.",
        )


class UmcastRpAnycastConsistency(Check):
    """Cross-RP consistency for anycast-RP setups."""

    name = "Underlay Mcast (RP): anycast consistency"
    target_node_id = "xtr"

    def run(self, ctx: RunContext) -> CheckResult:
        count = ctx.state.get("umcast_rp_count") or 0
        if count < 2:
            return CheckResult(CheckStatus.SKIP, "Skipped: not an anycast-RP set (≤1 RP).")
        rows = []
        problems = []
        active_count = 0
        for idx in range(1, count + 1):
            host = ctx.state.get(_key(idx, "hostname")) or f"RP{idx}"
            mcast = ctx.state.get(_key(idx, "mcast_enabled"))
            star_g = ctx.state.get(_key(idx, "star_g"))
            fhr_sg = ctx.state.get(_key(idx, "fhr_sg"))
            disabled = ctx.state.get(_disabled_flag(idx))
            rows.append(
                f"  - {host}: mcast={mcast}, *,G={star_g is not None}, "
                f"FHR-S,G={fhr_sg is not None}"
                + (f"  [skipped: {disabled}]" if disabled else "")
            )
            if mcast and star_g is not None:
                active_count += 1
            if disabled:
                problems.append(f"{host} did not complete validation ({disabled})")
        # Need at least one fully-good RP for the anycast set to be functional;
        # warn if the set is degraded (some good, some not), fail if all bad.
        body = "Anycast-RP set:\n" + "\n".join(rows)
        if active_count == 0:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• No RP in the anycast set has both mcast enabled AND a *,G — "
                "the broadcast-underlay tree cannot form on any replica.",
            )
        if active_count < count:
            return CheckResult(
                CheckStatus.WARN,
                body + f"\n• Only {active_count}/{count} replicas are healthy — anycast-RP "
                "is degraded. The set still functions via the healthy replica(s), but a "
                "failover would land traffic on a broken RP.",
            )
        # All replicas healthy — also verify FHR is registered to at least one.
        registered = sum(
            1 for idx in range(1, count + 1)
            if ctx.state.get(_key(idx, "fhr_sg")) is not None
        )
        if registered == 0:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n• All replicas are healthy but FHR is not registered to any of "
                "them — generate flooded traffic on the FHR and re-run.",
            )
        return CheckResult(
            CheckStatus.OK,
            body + f"\n• All {count} replicas healthy; FHR registered to {registered}/{count}.",
        )


def build_underlay_multicast_rp_chain() -> list:
    """Return the chain entry-points; per-RP chains are queued by Discovery."""
    return [UmcastRpDiscovery()]
