"""Stage 5b: RPF-walk path traversal between LHR and FHR (S,G) or RP (*,G).

Branches at start: if LHR has the (FHR_Lo0, group) S,G with the T flag, walk
the SPT back toward the FHR. Otherwise, if a (*, group) entry exists on the
LHR, walk the shared tree back toward the RP.

Per-hop resolution rules (no recursion duplicated; reuse CEF/physical_recursion):
    1. CEF + physical_recursion on the current hop give the physical egress
       port(s) toward the RPF-neighbor IP.
    2. CDP on those ports → set of neighbor hostnames.
    3. CatC IP-search on the RPF-neighbor IP → set of devices owning that IP.
    4. Match per these rules:
         CatC=0                       → STOP (unmanaged hop).
         CatC=1, CDP confirms it      → take it.
         CatC=N, CDP picks one        → take it.
         CDP empty                    → fall back to "already-discovered nodes".
         No match anywhere            → STOP.

State namespace:
    umcast_path_mode      — "sg" | "starg"
    umcast_path_target    — terminal IP (FHR Lo0 for sg, RP IP for starg).
    umcast_path_visited   — set of mgmt IPs we've already walked through.
    umcast_path_hops      — list of dicts (device, iif, rpf_nbr, sg_present, oil_count).
    umcast_path_done      — terminal reason string when the walk has ended.
"""

from checks import Check, CheckResult, CheckStatus, RunContext


def _wrap_fail(name: str, exc: BaseException) -> CheckResult:
    msg = str(exc) if str(exc) else exc.__class__.__name__
    return CheckResult(CheckStatus.FAIL, f"{name} raised {exc.__class__.__name__}: {msg}")


def _safe_mroute(host, vrf, group, source, service):
    """Reuse the safe-mroute helper from the RP module (handles Genie KeyError)."""
    from checks_underlay_multicast_rp import _safe_mroute_entries
    return _safe_mroute_entries(host, vrf, group, source, service)


def _physical_egress_for_ip(host: str, vrf, ip: str, service, step):
    """Return list of physical egress interfaces on ``host`` toward ``ip``.

    Reuses ``IPCef.get_cef_internal`` + ``physical_recursion`` so SVI / port-channel
    / nested-recursion is handled by existing code rather than duplicated here.
    """
    from routingmodules.cef import IPCef, physical_recursion
    cef = IPCef(ip, vrf or "default", host)
    cef.get_cef_internal(service)
    hops = getattr(cef, "cef_hops", None) or getattr(cef, "cefhops", None) or []
    if not hops:
        return []
    pr = physical_recursion(hops, host)
    pr.get_physical_interfaces(service, step)
    total = getattr(pr, "total_phys", None) or getattr(pr, "physical_interfaces", None) or []
    flat: list = []
    for entry in total:
        if isinstance(entry, (list, tuple)):
            flat.extend(entry)
        elif entry:
            flat.append(entry)
    seen, ordered = set(), []
    for p in flat:
        s = str(p)
        if s and s not in seen:
            seen.add(s)
            ordered.append(s)
    return ordered


def _cdp_neighbors_on(host: str, interface: str, service):
    """Return [{'device_id', 'remoteinterface', ...}] from CDP on ``interface``."""
    from switchingmodules.cdp import CDPinfo
    c = CDPinfo(host)
    c.cdpneighborinterface(interface, service)
    return list(getattr(c, "cdpneighbors", None) or [])


def _hostname_match(a: str, b: str) -> bool:
    """Compare CDP device_id and CatC hostname, tolerating FQDN vs short forms."""
    if not a or not b:
        return False
    a = a.split(".")[0].strip().lower()
    b = b.split(".")[0].strip().lower()
    return a == b


def _resolve_next_hop(ctx: RunContext, current_host: str, current_vrf,
                     rpf_nbr_ip: str, step):
    """Apply the layered match rules. Returns ``(profiled_device, reason, ports)``.

    ``profiled_device`` is the matched ``Device`` or ``None`` when the walk
    must stop. ``reason`` is human-readable diagnostic text either way.
    ``ports`` is the CEF-resolved physical egress port list on ``current_host``
    toward ``rpf_nbr_ip`` (used by the topology renderer as the edge label).
    """
    catc = ctx.state.get("umcast_catc_name") or ctx.state.get("catc_name")
    # Step 1: CatC IP search (authoritative for what the IP belongs to).
    try:
        from catalystcenterapi.catcapi import profile_devices_with_ip
        catc_devices = profile_devices_with_ip(step, rpf_nbr_ip, catc, ctx.service) or []
    except BaseException as e:
        return None, f"CatC IP-search raised {e.__class__.__name__}: {e}", []
    if not catc_devices:
        return None, f"CatC has no device owning {rpf_nbr_ip} — unmanaged hop, walk halted.", []

    # Step 2: CEF + physical recursion on the current hop → egress ports.
    try:
        ports = _physical_egress_for_ip(current_host, current_vrf, rpf_nbr_ip, ctx.service, step)
    except BaseException:
        ports = []

    # Step 3: CDP per egress port → neighbor hostnames.
    cdp_hostnames = set()
    for p in ports:
        try:
            for nbr in _cdp_neighbors_on(current_host, p, ctx.service):
                did = (nbr.get("device_id") or "").split(".")[0].lower()
                if did:
                    cdp_hostnames.add(did)
        except BaseException:
            continue

    # Step 4: Match.
    if len(catc_devices) == 1:
        only = catc_devices[0]
        host = (getattr(only, "hostname", "") or "").split(".")[0].lower()
        if cdp_hostnames and host in cdp_hostnames:
            return only, f"CatC=1 ({host}); CDP confirmed.", ports
        if cdp_hostnames:
            visited = ctx.state.get("umcast_known_nodes") or set()
            if host in visited:
                return only, f"CatC=1; CDP returned {sorted(cdp_hostnames)}, not matching, but {host} is in already-discovered set — accepting.", ports
            return None, (
                f"CatC=1 ({host}) but CDP on egress returned {sorted(cdp_hostnames)}; "
                "neither CDP nor already-discovered nodes corroborate. Walk halted."
            ), ports
        visited = ctx.state.get("umcast_known_nodes") or set()
        if host in visited:
            return only, f"CatC=1 ({host}); no CDP available; already discovered earlier.", ports
        return None, (
            f"CatC=1 ({host}) but no CDP corroboration and not previously discovered. "
            "Walk halted (cannot trust a single CatC hit without confirmation)."
        ), ports

    # Multiple CatC devices — MUST disambiguate via CDP, otherwise via discovered set.
    catc_hosts = {(getattr(d, "hostname", "") or "").split(".")[0].lower(): d for d in catc_devices}
    cdp_hits = cdp_hostnames & set(catc_hosts.keys())
    if len(cdp_hits) == 1:
        chosen = catc_hosts[next(iter(cdp_hits))]
        return chosen, f"CatC={len(catc_devices)} ambiguous; CDP disambiguated to {chosen.hostname}.", ports
    if len(cdp_hits) > 1:
        return None, (
            f"CatC={len(catc_devices)} candidates {sorted(catc_hosts)} and CDP "
            f"matches multiple of them ({sorted(cdp_hits)}) — ambiguous, walk halted."
        ), ports
    visited = ctx.state.get("umcast_known_nodes") or set()
    discovered_hits = visited & set(catc_hosts.keys())
    if len(discovered_hits) == 1:
        chosen = catc_hosts[next(iter(discovered_hits))]
        return chosen, f"CatC={len(catc_devices)}; CDP didn't help; already-discovered set picked {chosen.hostname}.", ports
    return None, (
        f"CatC returned {len(catc_devices)} candidates {sorted(catc_hosts)}; "
        "CDP didn't disambiguate and already-discovered set didn't either. "
        "Walk halted (unsafe to pick blindly)."
    ), ports


def _seed_known_nodes(ctx: RunContext) -> set:
    """Seed the already-discovered short-hostname set from earlier checks."""
    known = set()
    for key in ("umcast_source_hostname", "umcast_dst_hostname"):
        v = ctx.state.get(key)
        if isinstance(v, str) and v:
            known.add(v.split(".")[0].lower())
    for d in (ctx.state.get("umcast_rp_devices") or []):
        h = (getattr(d, "hostname", "") or "").split(".")[0].lower()
        if h:
            known.add(h)
    fhr = ctx.state.get("umcast_device")
    if fhr is not None:
        h = (getattr(getattr(fhr, "profiled_device", None), "hostname", "") or "").split(".")[0].lower()
        if h:
            known.add(h)
    lhr = ctx.state.get("umcast_dst_device")
    if lhr is not None:
        h = (getattr(getattr(lhr, "profiled_device", None), "hostname", "") or "").split(".")[0].lower()
        if h:
            known.add(h)
    ctx.state["umcast_known_nodes"] = known
    return known


def _topology_node(idx: int, pd, hop_iif: str, mode: str,
                   connect_to: str | None, edge_label: str | None) -> dict:
    """Build a topology-add node dict for the new hop, anchored to the
    previous hop's node via ``connect_to`` and labeled with the CEF-resolved
    egress port from the previous hop."""
    label_lines = [
        getattr(pd, "hostname", f"hop{idx}") or f"hop{idx}",
        getattr(pd, "mgmtip", "") or "",
        f"IIF: {hop_iif or '?'}",
        f"({mode.upper()} hop {idx})",
    ]
    spec = {
        "id": f"upath{idx}",
        "role": "hop",
        "label": "\n".join(x for x in label_lines if x),
        "ip": getattr(pd, "mgmtip", None),
        "hostname": getattr(pd, "hostname", None),
    }
    if connect_to:
        spec["connect_to"] = connect_to
    if edge_label:
        spec["edge_label"] = edge_label
    return spec


def _rp_node_id_for_mgmt(ctx: RunContext, mgmt: str) -> str | None:
    """Match a hop mgmt-IP to an RP-node id created by the RP discovery stage."""
    rp_devs = ctx.state.get("umcast_rp_devices") or []
    for idx, d in enumerate(rp_devs, start=1):
        if getattr(d, "mgmtip", None) == mgmt:
            return f"umcast_rp{idx}"
    return None


class UmcastPathStart(Check):
    """Decide SPT vs shared-tree walk, queue the first hop."""

    name = "Underlay Mcast (path): start"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        lhr_sg = ctx.state.get("umcast_lhr_sg")
        # LHR *,G isn't stored in ctx.state — UmcastLocalStarG writes it onto the
        # device object as ``stargmroute``. Pull it from there if present.
        lhr = ctx.state.get("umcast_dst_device")
        lhr_starg = getattr(lhr, "stargmroute", None) if lhr is not None else None
        group = ctx.state.get("umcast_broadcast_group")
        fhr_lo0 = None
        fhr = ctx.state.get("umcast_device")
        if fhr is not None:
            fhr_lo0 = getattr(getattr(fhr, "profiled_device", None), "loopback", None)

        if lhr_sg and "T" in (lhr_sg.get("flags") or "") and fhr_lo0:
            mode = "sg"
            target = fhr_lo0
            entry = lhr_sg
            mode_label = "S,G (SPT toward FHR)"
        elif lhr_starg:
            mode = "starg"
            target = ctx.state.get("umcast_rp")
            entry = lhr_starg
            mode_label = "*,G (shared tree toward RP)"
        else:
            return CheckResult(
                CheckStatus.SKIP,
                "Skipped: LHR has neither an SPT-flagged S,G nor a *,G — no tree to walk.",
            )

        if not target:
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped: walk target IP not resolved for mode {mode}.",
            )

        rpf_nbr = entry.get("rpfneighbor")
        iif = entry.get("incominginterface")
        if not rpf_nbr or rpf_nbr in ("0.0.0.0",):
            return CheckResult(
                CheckStatus.WARN,
                f"• Mode: {mode_label}\n• LHR has the entry but RPF neighbor is "
                f"{rpf_nbr} — already at the root. Nothing to walk.",
            )

        ctx.state["umcast_path_mode"] = mode
        ctx.state["umcast_path_target"] = target
        ctx.state["umcast_path_group"] = group
        ctx.state["umcast_path_visited"] = set()
        ctx.state["umcast_path_hops"] = []
        ctx.state["umcast_path_done"] = None
        _seed_known_nodes(ctx)

        # Anchor the LHR as hop-0 in the visited set.
        lhr = ctx.state.get("umcast_dst_device")
        lhr_host = getattr(getattr(lhr, "profiled_device", None), "hostname", None)
        lhr_mgmt = getattr(getattr(lhr, "profiled_device", None), "mgmtip", None)
        if lhr_mgmt:
            ctx.state["umcast_path_visited"].add(lhr_mgmt)
        ctx.state["umcast_path_hops"].append({
            "device": lhr_host,
            "mgmtip": lhr_mgmt,
            "iif": iif,
            "rpf_nbr": rpf_nbr,
            "sg_present": True,
            "oil_count": len(entry.get("outgoinginterfacelist") or []),
            "role": "lhr",
        })

        # Queue the first hop.
        body = (
            f"• Mode: {mode_label}\n"
            f"• Target: {target}\n"
            f"• Group: {group}\n"
            f"• Walk seed: LHR {lhr_host} → next hop {rpf_nbr} via {iif}"
        )
        return CheckResult(
            CheckStatus.OK, body,
            data={"queue_checks": [UmcastPathHop(idx=1, prev_host=lhr_host, prev_vrf=None,
                                                rpf_nbr_ip=rpf_nbr,
                                                prev_node_id="dxtr")]},
        )


MAX_HOPS = 16  # safety bound; real fabrics rarely exceed 6 underlay hops.


class UmcastPathHop(Check):
    """One hop of the RPF walk — resolve, profile, fetch mroute, queue next."""

    base_name = "hop"

    def __init__(self, idx: int, prev_host: str, prev_vrf, rpf_nbr_ip: str,
                 prev_node_id: str = "dxtr"):
        self.idx = idx
        self.prev_host = prev_host
        self.prev_vrf = prev_vrf
        self.rpf_nbr_ip = rpf_nbr_ip
        self.prev_node_id = prev_node_id
        self.name = f"Underlay Mcast (path): hop {idx} ({rpf_nbr_ip})"
        self.target_node_id = f"upath{idx}"

    def run(self, ctx: RunContext) -> CheckResult:
        if ctx.state.get("umcast_path_done"):
            return CheckResult(
                CheckStatus.SKIP,
                f"Skipped: walk already terminated ({ctx.state['umcast_path_done']}).",
            )
        if self.idx > MAX_HOPS:
            ctx.state["umcast_path_done"] = "max-hops exceeded"
            return CheckResult(
                CheckStatus.FAIL,
                f"• Walk exceeded {MAX_HOPS} hops without reaching the target — "
                "loop suspected or fabric larger than expected.",
            )

        # Resolve the next-hop device per the layered rules.
        try:
            pd, reason, ports = _resolve_next_hop(
                ctx, self.prev_host, self.prev_vrf, self.rpf_nbr_ip, step=self.idx
            )
        except BaseException as e:
            ctx.state["umcast_path_done"] = f"resolution raised {e.__class__.__name__}"
            return _wrap_fail(self.name, e)
        if pd is None:
            ctx.state["umcast_path_done"] = "next-hop unresolved"
            return CheckResult(
                CheckStatus.FAIL,
                f"• Walking from {self.prev_host} toward {self.rpf_nbr_ip}\n"
                f"• {reason}",
            )
        # Edge label = the CEF-resolved physical egress on the previous hop
        # toward this hop's RPF-neighbor IP. Multiple ports => comma-join.
        edge_label = ", ".join(ports) if ports else None

        mgmt = getattr(pd, "mgmtip", None)
        host = getattr(pd, "hostname", None) or mgmt
        visited = ctx.state.setdefault("umcast_path_visited", set())
        if mgmt and mgmt in visited:
            ctx.state["umcast_path_done"] = "loop detected"
            return CheckResult(
                CheckStatus.FAIL,
                f"• Walking toward {self.rpf_nbr_ip} resolved to {host} which has "
                "already been visited — loop detected, walk halted.",
            )
        if mgmt:
            visited.add(mgmt)

        # Fetch mroute on this hop matching the current mode.
        # IMPORTANT: IOS does longest-match for ``show ip mroute <group> <source>``.
        # The 255.255.255.255 sentinel falls back to the *,G when no S,G matches —
        # which silently HIDES any S,G on the device for a different source. So:
        #   SG mode  → query the exact source (FHR Lo0).
        #   *,G mode → use the sentinel (resolves to the *,G correctly).
        mode = ctx.state.get("umcast_path_mode")
        group = ctx.state.get("umcast_path_group")
        target = ctx.state.get("umcast_path_target")
        query_source = target if mode == "sg" else "255.255.255.255"
        try:
            entries, _fb = _safe_mroute(host, None, group, query_source, ctx.service)
        except BaseException as e:
            ctx.state["umcast_path_done"] = "hop mroute lookup failed"
            return _wrap_fail(self.name, e)
        if mode == "sg":
            entry = next((e for e in entries if e.get("source") == target), None)
        else:
            entry = next((e for e in entries if e.get("source") == "*"), None)

        node = _topology_node(
            self.idx, pd,
            entry.get("incominginterface") if entry else None,
            mode,
            connect_to=self.prev_node_id,
            edge_label=edge_label,
        )
        ctx.state.setdefault("umcast_path_hops", []).append({
            "device": host,
            "mgmtip": mgmt,
            "iif": (entry.get("incominginterface") if entry else None),
            "rpf_nbr": (entry.get("rpfneighbor") if entry else None),
            "sg_present": entry is not None,
            "oil_count": (len(entry.get("outgoinginterfacelist") or []) if entry else 0),
            "role": "transit",
        })

        body_lines = [
            f"• Hop {self.idx}: {host} ({mgmt})",
            f"• Resolution: {reason}",
        ]
        if entry is None:
            body_lines.append(
                f"• Mode {mode.upper()}: NO matching entry on this hop for "
                f"({'*' if mode=='starg' else target}, {group}) — tree is broken here."
            )
            ctx.state["umcast_path_done"] = "missing entry mid-walk"
            return CheckResult(
                CheckStatus.FAIL,
                "\n".join(body_lines),
                data={"add_nodes": [node]},
            )
        iif = entry.get("incominginterface") or "Null"
        rpf_next = entry.get("rpfneighbor")
        flags = entry.get("flags") or ""
        oils = entry.get("outgoinginterfacelist") or []
        body_lines.extend([
            f"• Entry: ({entry.get('source')}, {group})",
            f"• IIF: {iif}",
            f"• RPF neighbor: {rpf_next}",
            f"• Flags: {flags}",
            f"• OIL count: {len(oils)}",
        ])

        # Termination?
        terminal = False
        # FHR identity is stored in ``umcast_source_hostname`` which (see
        # checks_ew_destination.py:243) is the FHR's mgmt IP if available else
        # its short hostname. Match either the mgmt IP or the short hostname.
        fhr_id = ctx.state.get("umcast_source_hostname")
        fhr_short = (fhr_id or "").split(".")[0].lower()
        host_short = (host or "").split(".")[0].lower()
        merged_into_root = False
        merge_target_id = None
        if mode == "sg" and ((mgmt and mgmt == fhr_id) or (host_short and host_short == fhr_short)):
            terminal = True
            merged_into_root = True
            merge_target_id = "xtr"
            body_lines.append("• Reached FHR — SPT walk complete.")
        elif mode == "starg":
            rp_devices = ctx.state.get("umcast_rp_devices") or []
            rp_ips = {getattr(d, "mgmtip", None) for d in rp_devices}
            if mgmt in rp_ips:
                terminal = True
                merged_into_root = True
                merge_target_id = _rp_node_id_for_mgmt(ctx, mgmt) or "xtr"
                body_lines.append("• Reached RP — shared-tree walk complete.")
        if rpf_next in (None, "0.0.0.0", "") or iif == "Null0":
            terminal = True
            body_lines.append("• RPF terminator (Null0 / 0.0.0.0) — at the tree root.")

        if terminal:
            ctx.state["umcast_path_done"] = "reached root"
            # When the terminal hop IS the FHR/RP, suppress the duplicate
            # floating node and instead draw an edge from the previous hop's
            # node into the existing root (xtr or umcast_rp{idx}), labeled
            # with the CEF-resolved egress port so the topology mirrors the
            # actual RPF path.
            if merged_into_root and merge_target_id:
                payload = {
                    "add_edges": [{
                        "source": self.prev_node_id,
                        "target": merge_target_id,
                        "label": edge_label or "",
                        "id_prefix": "umcast-path",
                    }],
                }
            else:
                payload = {"add_nodes": [node]}
            return CheckResult(
                CheckStatus.OK,
                "\n".join(body_lines),
                data=payload,
            )

        # Queue the next hop.
        return CheckResult(
            CheckStatus.OK,
            "\n".join(body_lines),
            data={
                "add_nodes": [node],
                "queue_checks": [UmcastPathHop(
                    idx=self.idx + 1,
                    prev_host=host,
                    prev_vrf=None,
                    rpf_nbr_ip=rpf_next,
                    prev_node_id=f"upath{self.idx}",
                )],
            },
        )


class UmcastPathVerdict(Check):
    """Final verdict for the RPF walk."""

    name = "Underlay Mcast (path): verdict"
    target_node_id = "dxtr"

    def run(self, ctx: RunContext) -> CheckResult:
        hops = ctx.state.get("umcast_path_hops") or []
        mode = ctx.state.get("umcast_path_mode")
        done = ctx.state.get("umcast_path_done")
        if not hops or not mode:
            return CheckResult(CheckStatus.SKIP, "Skipped: path walk did not start.")
        rows = []
        for i, h in enumerate(hops):
            rows.append(
                f"  {i}. {h.get('device')} ({h.get('mgmtip')})  "
                f"IIF={h.get('iif')}, RPF→{h.get('rpf_nbr')}, "
                f"entry={'yes' if h.get('sg_present') else 'NO'}, "
                f"OILs={h.get('oil_count')}"
            )
        body = (
            f"• Mode: {mode.upper()}\n"
            f"• Hops walked: {len(hops)}\n"
            f"• Termination: {done}\n"
            "• Path:\n" + "\n".join(rows)
        )
        if done == "reached root":
            return CheckResult(
                CheckStatus.OK,
                body + "\n• End-to-end RPF walk succeeded; tree is consistent.",
            )
        return CheckResult(
            CheckStatus.FAIL,
            body + f"\n• Walk did not reach the root — {done}.",
        )


def build_underlay_multicast_path_chain() -> list:
    """Entry-point chain for the path traversal.

    The verdict is statically appended at the end; intermediate per-hop checks
    are queued dynamically by ``UmcastPathHop`` via ``queue_checks``, which the
    server inserts immediately after the current check — so hops always land
    between Start and Verdict regardless of how many hops the walk produces.
    """
    return [UmcastPathStart(), UmcastPathVerdict()]
