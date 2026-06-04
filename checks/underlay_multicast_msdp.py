"""Stage 5a: MSDP validation across an anycast-RP set.

Only relevant when ``UmcastRpDiscovery`` finds 2+ devices owning the RP IP
(classic Cisco anycast-RP with MSDP). Each replica is checked for:

  * MSDP peer config + state (peer must be Up).
  * MSDP SA-cache contains the broadcast group's S,G — proving SA messages
    are being exchanged for our flooded traffic.
  * Mesh-group / connection-source sanity (warn-level).

Per-RP state keys (idx 1, 2, ...):
    umcast_rp{idx}_msdp_peers       — list of peer summaries.
    umcast_rp{idx}_msdp_sa_cache    — list of SA-cache entries.
"""

from checks import Check, CheckResult, CheckStatus, RunContext
from checks.underlay_multicast_rp import (
    _node_id,
    _key,
    _disabled_flag,
    _skip_if_disabled,
    _wrap_fail,
)


class _PerRpMsdp(Check):
    base_name = "per-RP MSDP"

    def __init__(self, idx: int):
        self.idx = idx
        self.name = f"Underlay Mcast (RP{idx}): MSDP {self.base_name}"
        self.target_node_id = _node_id(idx)


class UmcastMsdpSummary(_PerRpMsdp):
    """Discover MSDP peers configured on this RP."""

    base_name = "peer summary"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        if (skip := _skip_if_disabled(ctx, idx)): return skip
        host = ctx.state.get(_key(idx, "hostname"))
        if not host:
            return CheckResult(CheckStatus.SKIP, "Skipped: RP not profiled.")
        try:
            from routingmodules.msdp import MSDP
            msdp = MSDP(host, None)
            msdp.msdpsummary(ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        peers = list(getattr(msdp, "peers", None) or [])
        ctx.state[_key(idx, "msdp_peers")] = peers
        ctx.state[_key(idx, "msdp_originator_id")] = getattr(msdp, "originatorid", None)
        ctx.state[_key(idx, "msdp_rfc3618")] = getattr(msdp, "rfc3618", False)
        if not peers:
            rp_count = ctx.state.get("umcast_rp_count") or 0
            rp_ip = ctx.state.get("umcast_rp")
            return CheckResult(
                CheckStatus.FAIL,
                f"• Device: {host}\n"
                f"• RP IP {rp_ip} is owned by {rp_count} devices "
                f"→ this is an anycast-RP set.\n"
                f"• MSDP peers configured on this replica: 0\n"
                f"• Anycast-RP cannot work without MSDP. Each replica only "
                f"sees the sources that register to itself; sources behind "
                f"one replica are invisible to receivers anchored on another, "
                f"so (S,G) state never converges across the set.\n"
                f"• Fix: configure MSDP peering between every replica "
                f"(typically a full mesh, or a mesh-group), e.g.\n"
                f"    ip msdp peer <other-replica-loopback> connect-source LoopbackN\n"
                f"    ip msdp originator-id LoopbackN\n"
                f"  on each anycast RP, then re-run this check.",
            )
        rows = [
            f"  - Peer {p.get('peer_address')}\n"
            f"      AS: {p.get('as')}\n"
            f"      Uptime: {p.get('uptime')}\n"
            f"      SA count: {p.get('sa_count')}\n"
            f"      Reset count: {p.get('reset_count')}"
            for p in peers
        ]
        body_lines = [
            f"• Device: {host}",
            f"• MSDP peers: {len(peers)}",
            f"• Originator-id: {getattr(msdp, 'originatorid', None)}",
            f"• RPF rfc3618: {getattr(msdp, 'rfc3618', False)}",
            "• Peer list:",
        ] + rows
        return CheckResult(CheckStatus.OK, "\n".join(body_lines))


class UmcastMsdpPeerState(_PerRpMsdp):
    """Every MSDP peer on this RP must be in the Up state."""

    base_name = "peer connection state"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        if (skip := _skip_if_disabled(ctx, idx)): return skip
        host = ctx.state.get(_key(idx, "hostname"))
        peers = ctx.state.get(_key(idx, "msdp_peers")) or []
        if not host:
            return CheckResult(CheckStatus.SKIP, "Skipped: RP not profiled.")
        if not peers:
            return CheckResult(CheckStatus.SKIP, "Skipped: no MSDP peers (covered by summary check).")
        try:
            from routingmodules.msdp import MSDP
            msdp = MSDP(host, None)
            msdp.msdppeer(ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        details = list(getattr(msdp, "peer_details", None) or [])
        ctx.state[_key(idx, "msdp_peer_details")] = details
        if not details:
            return CheckResult(
                CheckStatus.WARN,
                f"• Device: {host}\n• `show ip msdp peer` returned no parseable "
                f"detail blocks — peers exist per summary but state cannot be "
                f"confirmed.",
            )
        down = [d for d in details if (d.get("connection_state") or "").lower() != "up"]
        rows = []
        for d in details:
            rows.append(
                f"  - Peer {d.get('peer_ip')}\n"
                f"      State: {d.get('connection_state')}\n"
                f"      Connection source: {d.get('connection_source')}\n"
                f"      Mesh group: {d.get('mesh_group')}\n"
                f"      SAs in/out: {d.get('sa_in')} / {d.get('sa_out')}\n"
                f"      RPF failures: {d.get('rpf_failure_count')}"
            )
        body = (
            f"• Device: {host}\n"
            f"• Peers Up: {len(details) - len(down)}/{len(details)}\n"
            "• Peer detail:\n" + "\n".join(rows)
        )
        if down:
            return CheckResult(
                CheckStatus.FAIL,
                body + f"\n• {len(down)} peer(s) not Up — anycast-RP SA "
                "synchronization is broken; sources registered to a remote "
                "replica will be invisible here.",
            )
        # Mesh-group is only relevant for 3+ peer sets — with a single peer
        # there is nothing to re-flood to, so the absence is expected.
        if len(details) >= 2:
            no_mesh = [d for d in details if not d.get("mesh_group")]
            if no_mesh:
                return CheckResult(
                    CheckStatus.WARN,
                    body + f"\n• {len(no_mesh)} peer(s) not in a mesh-group — "
                    "without mesh-group, SAs received from one peer are re-flooded "
                    "to all other peers, which can cause loops in larger sets.",
                )
        return CheckResult(CheckStatus.OK, body)


class UmcastMsdpSaCache(_PerRpMsdp):
    """SA-cache on this RP should hold the broadcast group's S,G entries."""

    base_name = "SA-cache for broadcast group"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        if (skip := _skip_if_disabled(ctx, idx)): return skip
        host = ctx.state.get(_key(idx, "hostname"))
        group = ctx.state.get("umcast_broadcast_group")
        peers = ctx.state.get(_key(idx, "msdp_peers")) or []
        if not host or not group:
            return CheckResult(CheckStatus.SKIP, "Skipped: RP / group not available.")
        if not peers:
            return CheckResult(CheckStatus.SKIP, "Skipped: no MSDP peers.")
        try:
            from routingmodules.msdp import MSDP
            msdp = MSDP(host, None)
            msdp.msdpgroupstate(group, ctx.service)
        except BaseException as e:
            return _wrap_fail(self.name, e)
        sa_cache = list(getattr(msdp, "sa_cache", None) or [])
        ctx.state[_key(idx, "msdp_sa_cache")] = sa_cache
        for_group = [e for e in sa_cache if e.get("group") == group]
        if not sa_cache:
            return CheckResult(
                CheckStatus.WARN,
                f"• Device: {host}\n• Group: {group}\n"
                f"• MSDP SA-cache is empty — no anycast peer has advertised any "
                f"active source. Expected if no FHR is currently registered "
                f"anywhere in the set.",
            )
        if not for_group:
            return CheckResult(
                CheckStatus.WARN,
                f"• Device: {host}\n• Group: {group}\n"
                f"• SA-cache has {len(sa_cache)} entries but none for {group} — "
                f"FHR has not registered with any replica for the broadcast "
                f"group, or the SA was filtered before reaching this RP.",
            )
        rows = [
            f"  - ({e.get('source')}, {e.get('group')}) RP={e.get('rp')} "
            f"learned from peer {e.get('peer_ip')}"
            for e in for_group
        ]
        body = (
            f"• Device: {host}\n"
            f"• Group: {group}\n"
            f"• SA entries for this group: {len(for_group)}\n"
            "• Entries:\n" + "\n".join(rows)
        )
        return CheckResult(CheckStatus.OK, body)


class UmcastMsdpVerdict(_PerRpMsdp):
    """Per-RP MSDP verdict."""

    base_name = "verdict"

    def run(self, ctx: RunContext) -> CheckResult:
        idx = self.idx
        if (skip := _skip_if_disabled(ctx, idx)): return skip
        host = ctx.state.get(_key(idx, "hostname"))
        peers = ctx.state.get(_key(idx, "msdp_peers")) or []
        details = ctx.state.get(_key(idx, "msdp_peer_details")) or []
        sa_cache = ctx.state.get(_key(idx, "msdp_sa_cache")) or []
        group = ctx.state.get("umcast_broadcast_group")
        if not host:
            return CheckResult(CheckStatus.SKIP, "Skipped: RP not profiled.")
        up = sum(1 for d in details if (d.get("connection_state") or "").lower() == "up")
        for_group = sum(1 for e in sa_cache if e.get("group") == group)
        body = (
            f"• RP: {host}\n"
            f"• MSDP peers configured: {len(peers)}\n"
            f"• Peers Up: {up}/{len(details) if details else 0}\n"
            f"• SA-cache entries for {group}: {for_group}"
        )
        if not peers:
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• Anycast-RP without MSDP — replicas cannot share "
                "registered-source state.",
            )
        if details and up < len(details):
            return CheckResult(
                CheckStatus.FAIL,
                body + "\n• At least one MSDP peer is not Up — partial sync.",
            )
        if for_group == 0:
            return CheckResult(
                CheckStatus.WARN,
                body + "\n• Peers healthy but no SA in cache for the broadcast "
                "group — FHR not registered anywhere in the set, or SAs filtered.",
            )
        return CheckResult(
            CheckStatus.OK,
            body + "\n• MSDP set is healthy and carrying SA state for the "
            "broadcast group.",
        )


def build_msdp_chain_for_rp(idx: int) -> list:
    return [
        UmcastMsdpSummary(idx),
        UmcastMsdpPeerState(idx),
        UmcastMsdpSaCache(idx),
        UmcastMsdpVerdict(idx),
    ]
